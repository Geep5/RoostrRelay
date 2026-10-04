package relay

// Negentropy protocol V1 (https://github.com/hoytech/negentropy), responder
// side, byte-for-byte with the reference implementations. NIP-77 carries
// these binary messages hex-encoded; the wire envelope and per-connection
// sessions live in nip77.odin. This file depends on core packages only.
//
// Items are (timestamp, 32-byte id), sorted ascending by timestamp, then id.
// A message is a version byte followed by adjacent ranges, each an exclusive
// upper Bound, a mode and a payload (Skip, 16-byte Fingerprint or IdList).

import "core:crypto/sha2"
import "core:math/bits"

NEG_PROTOCOL_VERSION :: 0x61
NEG_ID_SIZE :: 32
NEG_FINGERPRINT_SIZE :: 16
NEG_INFINITY :: max(u64) // reserved timestamp, encoded as 0
NEG_BUCKETS :: 16
// Responder output budget in bytes. The hex NEG-MSG is twice this, well under
// MAX_SERVER_MESSAGE and the 1 MiB inbound cap common to clients.
NEG_FRAME_SIZE_LIMIT :: 250_000

Neg_Mode :: enum u64 {
	Skip        = 0,
	Fingerprint = 1,
	Id_List     = 2,
}

Neg_Item :: struct {
	timestamp: u64,
	id:        [NEG_ID_SIZE]byte,
}

// Exclusive range bound. Bytes of item.id past id_len are zero, which orders
// exactly like the shorter prefix the wire carries.
Neg_Bound :: struct {
	item:   Neg_Item,
	id_len: int,
}

neg_item_less :: proc(a, b: Neg_Item) -> bool {
	if a.timestamp != b.timestamp do return a.timestamp < b.timestamp
	for i in 0 ..< NEG_ID_SIZE {
		if a.id[i] != b.id[i] do return a.id[i] < b.id[i]
	}
	return false
}

// First index in [begin, end) whose item is not below bound.
neg_lower_bound :: proc(items: []Neg_Item, begin, end: int, bound: Neg_Item) -> int {
	lo, hi := begin, end
	for lo < hi {
		mid := lo + (hi - lo) / 2
		if neg_item_less(items[mid], bound) do lo = mid + 1
		else do hi = mid
	}
	return lo
}

// -- Varint: base-128, most significant digit first --------------------

neg_varint_bytes :: proc(n: u64, buf: ^[10]byte) -> []byte {
	n := n
	i := len(buf)
	for {
		i -= 1
		buf[i] = byte(n & 0x7f)
		n >>= 7
		if n == 0 do break
	}
	for j in i ..< len(buf) - 1 do buf[j] |= 0x80
	return buf[i:]
}

neg_put_varint :: proc(out: ^[dynamic]byte, n: u64) {
	buf: [10]byte
	append(out, ..neg_varint_bytes(n, &buf))
}

Neg_Reader :: struct {
	data: []byte,
	pos:  int,
}

neg_get_varint :: proc(r: ^Neg_Reader) -> (n: u64, ok: bool) {
	for {
		if r.pos >= len(r.data) || n > NEG_INFINITY >> 7 do return 0, false
		b := r.data[r.pos]
		r.pos += 1
		n = n << 7 | u64(b & 0x7f)
		if b & 0x80 == 0 do return n, true
	}
}

neg_get_bytes :: proc(r: ^Neg_Reader, n: int) -> (out: []byte, ok: bool) {
	if n < 0 || n > len(r.data) - r.pos do return nil, false
	out = r.data[r.pos:][:n]
	r.pos += n
	return out, true
}

// -- Fingerprint --------------------------------------------------------

// sha256(sum of ids as little-endian u256 mod 2^256 || varint(count))[:16]
neg_fingerprint :: proc(items: []Neg_Item) -> (fp: [NEG_FINGERPRINT_SIZE]byte) {
	sum: [4]u64
	for &item in items {
		limbs := transmute([4]u64le)item.id
		carry: u64
		for i in 0 ..< 4 do sum[i], carry = bits.add_u64(sum[i], u64(limbs[i]), carry)
	}
	sum_le: [4]u64le
	for i in 0 ..< 4 do sum_le[i] = u64le(sum[i])
	sum_bytes := transmute([NEG_ID_SIZE]byte)sum_le
	count_buf: [10]byte

	digest: [32]byte
	ctx: sha2.Context_256
	sha2.init_256(&ctx)
	sha2.update(&ctx, sum_bytes[:])
	sha2.update(&ctx, neg_varint_bytes(u64(len(items)), &count_buf))
	sha2.final(&ctx, digest[:])
	copy(fp[:], digest[:NEG_FINGERPRINT_SIZE])
	return fp
}

// -- Bounds: timestamps are delta-encoded within one message -------------

Neg_Codec :: struct {
	last_in:  u64,
	last_out: u64,
}

neg_put_timestamp :: proc(codec: ^Neg_Codec, out: ^[dynamic]byte, timestamp: u64) {
	if timestamp == NEG_INFINITY {
		codec.last_out = NEG_INFINITY
		neg_put_varint(out, 0)
		return
	}
	delta := timestamp - codec.last_out
	codec.last_out = timestamp
	neg_put_varint(out, delta + 1)
}

neg_put_bound :: proc(codec: ^Neg_Codec, out: ^[dynamic]byte, bound: Neg_Bound) {
	bound := bound
	neg_put_timestamp(codec, out, bound.item.timestamp)
	neg_put_varint(out, u64(bound.id_len))
	append(out, ..bound.item.id[:bound.id_len])
}

neg_get_timestamp :: proc(codec: ^Neg_Codec, r: ^Neg_Reader) -> (timestamp: u64, ok: bool) {
	encoded := neg_get_varint(r) or_return
	if encoded == 0 || codec.last_in == NEG_INFINITY {
		codec.last_in = NEG_INFINITY
		return NEG_INFINITY, true
	}
	offset := encoded - 1
	// Offsets past the reserved value are malformed; saturate to infinity.
	timestamp = offset > NEG_INFINITY - codec.last_in ? NEG_INFINITY : codec.last_in + offset
	codec.last_in = timestamp
	return timestamp, true
}

neg_get_bound :: proc(codec: ^Neg_Codec, r: ^Neg_Reader) -> (bound: Neg_Bound, err: string) {
	ok: bool
	if bound.item.timestamp, ok = neg_get_timestamp(codec, r); !ok do return {}, "parse ends prematurely"
	id_len, lok := neg_get_varint(r)
	if !lok do return {}, "parse ends prematurely"
	if id_len > NEG_ID_SIZE do return {}, "bound key too long"
	prefix, pok := neg_get_bytes(r, int(id_len))
	if !pok do return {}, "parse ends prematurely"
	copy(bound.item.id[:], prefix)
	bound.id_len = int(id_len)
	return bound, ""
}

// Shortest bound separating prev from curr (curr is the first item above it).
neg_minimal_bound :: proc(prev, curr: Neg_Item) -> (bound: Neg_Bound) {
	bound.item.timestamp = curr.timestamp
	if curr.timestamp != prev.timestamp do return bound
	shared := 0
	for shared < NEG_ID_SIZE && curr.id[shared] == prev.id[shared] do shared += 1
	bound.id_len = min(shared + 1, NEG_ID_SIZE)
	bound.item.id = curr.id
	for i in bound.id_len ..< NEG_ID_SIZE do bound.item.id[i] = 0
	return bound
}

neg_item_bound :: proc(item: Neg_Item) -> Neg_Bound {
	return {item = item, id_len = NEG_ID_SIZE}
}

// -- Reconciliation (responder) -------------------------------------------

neg_split_range :: proc(codec: ^Neg_Codec, items: []Neg_Item, lower, upper: int, upper_bound: Neg_Bound, o: ^[dynamic]byte) {
	count := upper - lower
	if count < NEG_BUCKETS * 2 {
		neg_put_bound(codec, o, upper_bound)
		neg_put_varint(o, u64(Neg_Mode.Id_List))
		neg_put_varint(o, u64(count))
		for &item in items[lower:upper] do append(o, ..item.id[:])
		return
	}
	per_bucket := count / NEG_BUCKETS
	with_extra := count % NEG_BUCKETS
	curr := lower
	for i in 0 ..< NEG_BUCKETS {
		size := per_bucket + (i < with_extra ? 1 : 0)
		fp := neg_fingerprint(items[curr:curr + size])
		curr += size
		next := upper_bound if curr == upper else neg_minimal_bound(items[curr - 1], items[curr])
		neg_put_bound(codec, o, next)
		neg_put_varint(o, u64(Neg_Mode.Fingerprint))
		append(o, ..fp[:])
	}
}

neg_frame_exceeded :: proc(frame_size_limit, n: int) -> bool {
	return frame_size_limit != 0 && n > frame_size_limit - 200
}

// Answers one initiator message against the sorted, duplicate-free item set.
// frame_size_limit 0 means unbounded. A newer protocol version gets a lone
// version byte so the initiator can downgrade. err != "" on malformed input.
neg_reconcile :: proc(items: []Neg_Item, query: []byte, frame_size_limit: int, allocator := context.temp_allocator) -> (out: []byte, err: string) {
	r := Neg_Reader{data = query}
	codec: Neg_Codec
	full := make([dynamic]byte, allocator)
	append(&full, NEG_PROTOCOL_VERSION)

	version, vok := neg_get_bytes(&r, 1)
	if !vok do return nil, "parse ends prematurely"
	if version[0] < 0x60 || version[0] > 0x6f do return nil, "invalid negentropy protocol version byte"
	if version[0] != NEG_PROTOCOL_VERSION do return full[:], ""

	o := make([dynamic]byte, allocator)
	prev_bound: Neg_Bound
	prev_index := 0
	skip := false
	for r.pos < len(r.data) {
		clear(&o)
		curr_bound, berr := neg_get_bound(&codec, &r)
		if berr != "" do return nil, berr
		mode, mok := neg_get_varint(&r)
		if !mok do return nil, "parse ends prematurely"

		lower := prev_index
		upper := neg_lower_bound(items, prev_index, len(items), curr_bound.item)

		switch mode {
		case u64(Neg_Mode.Skip):
			skip = true
		case u64(Neg_Mode.Fingerprint):
			theirs, fok := neg_get_bytes(&r, NEG_FINGERPRINT_SIZE)
			if !fok do return nil, "parse ends prematurely"
			ours := neg_fingerprint(items[lower:upper])
			if string(theirs) != string(ours[:]) {
				if skip {
					skip = false
					neg_put_bound(&codec, &o, prev_bound)
					neg_put_varint(&o, u64(Neg_Mode.Skip))
				}
				neg_split_range(&codec, items, lower, upper, curr_bound, &o)
			} else {
				skip = true
			}
		case u64(Neg_Mode.Id_List):
			count, cok := neg_get_varint(&r)
			if !cok || count > u64(len(r.data) - r.pos) / NEG_ID_SIZE do return nil, "parse ends prematurely"
			r.pos += int(count) * NEG_ID_SIZE // the responder only answers with its own ids
			if skip {
				skip = false
				neg_put_bound(&codec, &o, prev_bound)
				neg_put_varint(&o, u64(Neg_Mode.Skip))
			}
			end_bound := curr_bound
			ids := make([dynamic]byte, allocator)
			sent := 0
			for i in lower ..< upper {
				if neg_frame_exceeded(frame_size_limit, len(full) + len(ids)) {
					end_bound = neg_item_bound(items[i])
					upper = i // the remaining range gets its own fingerprint below
					break
				}
				append(&ids, ..items[i].id[:])
				sent += 1
			}
			neg_put_bound(&codec, &o, end_bound)
			neg_put_varint(&o, u64(Neg_Mode.Id_List))
			neg_put_varint(&o, u64(sent))
			append(&o, ..ids[:])
			delete(ids)
			append(&full, ..o[:])
			clear(&o)
		case:
			return nil, "unexpected mode"
		}

		if neg_frame_exceeded(frame_size_limit, len(full) + len(o)) {
			// Stop and hand back one fingerprint covering everything left.
			remaining := neg_fingerprint(items[upper:])
			neg_put_bound(&codec, &full, Neg_Bound{item = {timestamp = NEG_INFINITY}})
			neg_put_varint(&full, u64(Neg_Mode.Fingerprint))
			append(&full, ..remaining[:])
			break
		}
		append(&full, ..o[:])
		prev_index = upper
		prev_bound = curr_bound
	}
	return full[:], ""
}
