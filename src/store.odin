package relay

// Durable append-only log. Legacy E (event) and T (event-id tombstone)
// records remain readable. A records commit one complete logical event
// operation: its authorized deletions/supersession and insertion replay together.
// S records are A/E records that carry their event's stream seq (see
// "Streams"); H records keep a stream head across compaction. Unsequenced
// A records are events stored before streams existed or by anonymous writers.
// Framing: [type:u8][length:u32le][payload][crc32:u32le]. A/S/H checksum
// header plus payload; legacy E/T checksum only payload, exactly as before.
// An incomplete EOF tail is always truncated at boot (bytes past a torn
// append are untrustworthy, even if a suffix decodes as a valid frame);
// corrupt complete records are never discarded. Boot streams the log through
// a fixed window (REPLAY_BUFFER), never holding the whole file in memory.
// g_mu owns the file, append-failure latch and all in-memory indexes.

import "core:encoding/json"
import "core:fmt"
import "core:hash"
import "core:os"
import "core:slice"
import "core:strings"
import "core:mem"
import "core:strconv"
import "core:sync"

g_mu: sync.Mutex
g_fd: ^os.File
g_log_path: string
g_append_failed: bool
g_deleted: map[string]bool // durable IDs, including superseded versions

Stored :: struct {
	id:         string,
	pubkey:     string,
	created_at: i64,
	kind:       i64,
	d:          string, // addressable identity ("" otherwise)
	tags:       [][2]string, // retained_tag subset: indexed single-letter tags + ["owner", pk]
	json:       string, // wire JSON, echoed verbatim by REQ
	anon:       bool, // admitted via the stranger doors, counts against g_anon_bytes
	space_deletion: bool, // kind-5 with ["h", _] tags (see space_deletion_covers)
	idx:        int, // position in g_order (swap-remove bookkeeping)
	seq:        i64, // position in stream (0 = unsequenced: legacy or anonymous writer)
	stream:     ^Stream, // nil when seq == 0
}

g_events: map[string]^Stored
g_order: [dynamic]^Stored
g_deletions: [dynamic]^Stored // retained kind-5 requests, the only events that block arrivals
g_deletion_refs: map[string]int // author+id of each retained ["e", id] -> request count
g_tombs: int // tombstoned records currently wasting log bytes
g_anon_bytes: int // retained wire bytes from anonymous (non-allowlisted) writers
g_log_bytes: int // current log file size
g_live_bytes: int // size compaction would write: live E/S records + retained T records + H records

// Stranger retention quotas. The per-event size fence lives in nostr.odin
// (ANON_MAX_EVENT_BYTES); these bound the aggregate: kind-0 rotation across
// fresh keys and gift-wrap floods cannot grow the log past this, and any one
// recipient keeps at most ANON_MAX_GIFTS_PER_TARGET kind-1059 envelopes
// (further anonymous gifts are REJECTED, none are evicted).
ANON_MAX_TOTAL_BYTES :: 32 << 20
ANON_MAX_GIFTS_PER_TARGET :: 64

MAX_RECORD :: MAX_MESSAGE // same bound for acceptance, new writes and legacy replay
// S payload: [mode u8: 'A' plan | 'E' insert][seq u64le][wire JSON]; the
// prefix rides on top of the event bound, so a MAX_RECORD event stays legal.
SEQ_PREFIX :: 9
// H payload: [head u64le][stream key].
HEAD_PREFIX :: 8
MAX_PAYLOAD :: MAX_RECORD + SEQ_PREFIX
COMPACT_MIN_TOMBS :: 1024
// Online compaction: once the log is more than twice what compaction would
// write AND at least this many bytes are dead, the next commit rewrites it.
COMPACT_MIN_DEAD_BYTES :: 64 << 20
RECORD_OVERHEAD :: 9 // [type][length:u32][...][crc32]
// Boot replay window. Every complete record fits, so a record still
// incomplete after a refill is a genuine EOF tear, exactly as in a whole-file read.
REPLAY_BUFFER :: 4 << 20
#assert(REPLAY_BUFFER >= MAX_PAYLOAD + RECORD_OVERHEAD)
// Tags of one event examined by plan_operation. A kind-5 over this bound is
// REJECTED rather than partially applied: a silently truncated deletion
// leaves the client believing the relay dropped events it still serves.
MAX_PLAN_TAGS :: 256

// -- Streams (relay cursor) -------------------------------------------
//
// Every event stored by a non-anonymous writer takes the next seq of its
// stream: the first ["s", T] tag names the space stream "s:T", otherwise the
// author's personal stream "p:<pubkey>". Seqs are gap-free and never reused:
// the head only grows (deleted and superseded events keep theirs consumed),
// S records carry each seq and compaction writes every head as an H record.
// Anonymous (stranger-door) events stay unsequenced: their throwaway keys
// would otherwise each leave a permanent stream head behind.

Stream_Slot :: struct {
	seq: i64,
	s:   ^Stored, // nil once evicted; seq stays for the binary search
}

Stream :: struct {
	key:   string,
	head:  i64, // highest seq ever assigned
	slots: [dynamic]Stream_Slot, // ascending seq
	lo:    int, // slots[:lo] are all evicted: slots[lo] is the oldest kept
	holes: int, // evicted slots still present in slots
}

Stream_Cursor :: struct {
	head:   i64,
	oldest: i64, // oldest kept seq; head+1 when the stream keeps nothing
}

g_streams: map[string]^Stream

// Rebuild a stream's slots once evicted holes are both numerous and the majority.
STREAM_MIN_HOLES :: 64

stream_key :: proc(ev: ^Event, allocator := context.temp_allocator) -> string {
	for tag in ev.tags {
		if len(tag) >= 2 && tag[0] == "s" do return strings.concatenate({"s:", tag[1]}, allocator)
	}
	return strings.concatenate({"p:", ev.pubkey}, allocator)
}

stream_get :: proc(key: string) -> ^Stream {
	if st, ok := g_streams[key]; ok do return st
	st := new(Stream)
	st.key = strings.clone(key)
	g_streams[st.key] = st
	g_live_bytes += len(st.key) + HEAD_PREFIX + RECORD_OVERHEAD
	return st
}

stream_cursor :: proc(st: ^Stream) -> Stream_Cursor {
	if st == nil do return {head = 0, oldest = 1}
	return {head = st.head, oldest = st.lo < len(st.slots) ? st.slots[st.lo].seq : st.head + 1}
}

// First slot index with slot.seq >= seq.
stream_search :: proc(st: ^Stream, seq: i64) -> int {
	lo, hi := 0, len(st.slots)
	for lo < hi {
		mid := (lo + hi) / 2
		if st.slots[mid].seq < seq do lo = mid + 1
		else do hi = mid
	}
	return lo
}

stream_has :: proc(st: ^Stream, seq: i64) -> bool {
	i := stream_search(st, seq)
	return i < len(st.slots) && st.slots[i].seq == seq
}

// Writes and replayed operations arrive in seq order and append; compacted
// logs list each stream in seq order too, so the insertion is a fallback.
stream_insert :: proc(st: ^Stream, s: ^Stored) {
	n := len(st.slots)
	if n == 0 || st.slots[n-1].seq < s.seq {
		append(&st.slots, Stream_Slot{s.seq, s})
		return
	}
	i := stream_search(st, s.seq)
	inject_at(&st.slots, i, Stream_Slot{s.seq, s})
	if i <= st.lo do st.lo = i
}

stream_remove :: proc(st: ^Stream, s: ^Stored) {
	i := stream_search(st, s.seq)
	assert(i < len(st.slots) && st.slots[i].s == s)
	st.slots[i].s = nil
	st.holes += 1
	for st.lo < len(st.slots) && st.slots[st.lo].s == nil do st.lo += 1
	if st.holes < STREAM_MIN_HOLES || 2*st.holes <= len(st.slots) do return
	kept := 0
	for slot in st.slots {
		if slot.s == nil do continue
		st.slots[kept] = slot
		kept += 1
	}
	resize(&st.slots, kept)
	st.lo, st.holes = 0, 0
}

u64le_put :: proc(dst: []u8, v: u64) {
	for i in 0..<8 do dst[i] = u8(v >> uint(8*i))
}

u64le_get :: proc(src: []u8) -> u64 {
	v: u64
	for i in 0..<8 do v |= u64(src[i]) << uint(8*i)
	return v
}

// -- Kind routing (unchanged) -----------------------------------------

is_replaceable :: proc(kind: i64) -> bool {
	return kind == 0 || kind == 3 || (kind >= 10000 && kind < 20000)
}

is_addressable :: proc(kind: i64) -> bool {
	return kind >= 30000 && kind < 40000
}

d_tag :: proc(ev: ^Event) -> string {
	for tag in ev.tags {
		if len(tag) >= 2 && tag[0] == "d" do return tag[1]
	}
	return ""
}

// -- Log primitives ----------------------------------------------------

write_full :: proc(fd: ^os.File, data: []u8) -> bool {
	off := 0
	for off < len(data) {
		n, err := os.write(fd, data[off:])
		if err != nil || n <= 0 do return false
		off += n
	}
	return true
}

// Legacy E/T checksum only their payload.
record_crc_covers_header :: proc(type: u8) -> bool {
	return type == 'A' || type == 'S' || type == 'H'
}

record_max_payload :: proc(type: u8) -> int {
	return type == 'S' || type == 'H' ? MAX_PAYLOAD : MAX_RECORD
}

// The record payload is prefix ++ payload; the prefix (S/H headers) is
// framed in place rather than copied in front of a large event.
write_record_to :: proc(fd: ^os.File, type: u8, payload: string, prefix: []u8 = nil) -> bool {
	size := len(prefix) + len(payload)
	if size <= 0 || size > record_max_payload(type) do return false
	head: [5]u8
	head[0] = type
	n := u32(size)
	for i in 0..<4 do head[i+1] = u8(n >> uint(8*i))
	seed := record_crc_covers_header(type) ? hash.crc32(head[:]) : u32(0)
	crc := hash.crc32(transmute([]u8)payload, hash.crc32(prefix, seed))
	tail: [4]u8
	for i in 0..<4 do tail[i] = u8(crc >> uint(8*i))
	return write_full(fd, head[:]) && write_full(fd, prefix) && write_full(fd, transmute([]u8)payload) && write_full(fd, tail[:])
}

// S record of an event and its seq; mode 'A' replays as an operation (plan
// then apply), 'E' as a plain insert (compaction output).
write_sequenced_to :: proc(fd: ^os.File, mode: u8, seq: i64, wire: string) -> bool {
	prefix: [SEQ_PREFIX]u8
	prefix[0] = mode
	u64le_put(prefix[1:], u64(seq))
	return write_record_to(fd, 'S', wire, prefix[:])
}

write_head_to :: proc(fd: ^os.File, st: ^Stream) -> bool {
	prefix: [HEAD_PREFIX]u8
	u64le_put(prefix[:], u64(st.head))
	return write_record_to(fd, 'H', st.key, prefix[:])
}

// seq > 0 logs a sequenced operation (S, mode A); 0 an unsequenced A.
append_operation :: proc(wire: string, seq: i64 = 0) -> bool {
	if g_append_failed || g_fd == nil do return false
	written := seq > 0 ? write_sequenced_to(g_fd, 'A', seq, wire) : write_record_to(g_fd, 'A', wire)
	if !written || os.sync(g_fd) != nil {
		// Never append beyond a possibly partial/unsynced operation. Restart
		// replays the file before any writer may use it again.
		g_append_failed = true
		return false
	}
	g_log_bytes += len(wire) + RECORD_OVERHEAD + (seq > 0 ? SEQ_PREFIX : 0)
	return true
}

remember_deleted :: proc(id: string) {
	if !(id in g_deleted) {
		g_deleted[strings.clone(id)] = true
		g_live_bytes += len(id) + RECORD_OVERHEAD
	}
}

// -- In-memory index ---------------------------------------------------

// Stored tags: single-letter tags (the filterable set) plus ["owner", pk]
// consent tags, which space deletions read. Filters only name single
// letters, so retaining "owner" never changes REQ results.
retained_tag :: proc(tag: []string) -> bool {
	if len(tag) < 2 do return false
	if tag[0] == "owner" do return true
	if len(tag[0]) != 1 do return false
	ch := tag[0][0]
	return ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z'
}

// seq > 0 places the event in its stream (stream_key) and advances the head.
@(private)
intern :: proc(ev: ^Event, wire_json: string, seq: i64 = 0) -> ^Stored {
	s := new(Stored)
	s.id = strings.clone(ev.id)
	s.pubkey = strings.clone(ev.pubkey)
	s.created_at = ev.created_at
	s.kind = ev.kind
	s.json = strings.clone(wire_json)

	count := 0
	for tag in ev.tags do if retained_tag(tag) do count += 1
	s.tags = make([][2]string, count)
	i := 0
	have_d := false
	for tag in ev.tags {
		if !retained_tag(tag) do continue
		s.tags[i] = {strings.clone(tag[0]), strings.clone(tag[1])}
		if tag[0] == "d" && !have_d {
			s.d = s.tags[i][1]
			have_d = true
		}
		i += 1
	}
	s.anon = anonymous_writer(ev)
	s.space_deletion = is_space_deletion(ev)
	if s.anon do g_anon_bytes += len(s.json)
	g_live_bytes += len(s.json) + RECORD_OVERHEAD
	if seq > 0 {
		s.seq = seq
		s.stream = stream_get(stream_key(ev))
		s.stream.head = max(s.stream.head, seq)
		stream_insert(s.stream, s)
		g_live_bytes += SEQ_PREFIX
	}

	s.idx = len(g_order)
	append(&g_order, s)
	if s.kind == 5 do index_deletion(s)
	g_events[s.id] = s
	return s
}

// Arrivals look up e references instead of rescanning every retained
// request's tags: boot replay plans each record, so that scan was
// O(records x retained e tags).
index_deletion :: proc(s: ^Stored) {
	append(&g_deletions, s)
	for t in s.tags {
		if t[0] != "e" do continue
		key := strings.concatenate({s.pubkey, t[1]})
		if key in g_deletion_refs {
			g_deletion_refs[key] += 1
			delete(key)
		} else {
			g_deletion_refs[key] = 1
		}
	}
}

unindex_deletion :: proc(s: ^Stored) {
	for deletion, i in g_deletions {
		if deletion == s { unordered_remove(&g_deletions, i); break }
	}
	for t in s.tags {
		if t[0] != "e" do continue
		key := strings.concatenate({s.pubkey, t[1]}, context.temp_allocator)
		g_deletion_refs[key] -= 1
		if g_deletion_refs[key] == 0 {
			owned, _ := delete_key(&g_deletion_refs, key)
			delete(owned)
		}
	}
}

@(private)
evict :: proc(s: ^Stored) {
	remember_deleted(s.id)
	// Swap-remove from g_order, keeping idx fields honest.
	last := g_order[len(g_order) - 1]
	g_order[s.idx] = last
	last.idx = s.idx
	pop(&g_order)
	if s.kind == 5 do unindex_deletion(s)
	delete_key(&g_events, s.id)

	if s.anon do g_anon_bytes -= len(s.json)
	g_live_bytes -= len(s.json) + RECORD_OVERHEAD
	if s.stream != nil {
		stream_remove(s.stream, s)
		g_live_bytes -= SEQ_PREFIX
	}
	delete(s.id)
	delete(s.pubkey)
	for t in s.tags {
		delete(t[0])
		delete(t[1])
	}
	delete(s.tags)
	delete(s.json)
	free(s)
	g_tombs += 1
}

// -- Boot: replay, heal, compact ---------------------------------------

store_open :: proc(path: string) {
	g_log_path = strings.clone(path)
	g_events = make(map[string]^Stored)
	g_deleted = make(map[string]bool)
	g_streams = make(map[string]^Stream)
	g_append_failed = false
	g_live_bytes = 0
	g_log_bytes = 0
	fd, oerr := os.open(path, {.Read})
	if oerr == nil {
		good, torn, status, rerr := replay_file(fd)
		if rerr != nil {
			fmt.eprintln("[relay] FATAL: cannot read log:", rerr)
			os.exit(1)
		}
		if status == .Corrupt {
			fmt.eprintfln("[relay] FATAL: corrupt log at offset %d; original file untouched", good)
			os.exit(1)
		}
		if status == .Incomplete {
			fmt.printfln("[relay] store: truncating %d torn tail byte(s) at offset %d", torn, good)
			if !truncate_log(fd, good) {
				fmt.eprintln("[relay] FATAL: cannot durably recover incomplete log tail")
				os.exit(1)
			}
		}
		g_log_bytes = good
		_ = os.close(fd)
	} else if oerr != os.Error(os.General_Error.Not_Exist) {
		fmt.eprintln("[relay] FATAL: cannot read log:", oerr)
		os.exit(1)
	}
	if (g_tombs >= COMPACT_MIN_TOMBS || compaction_due()) && !compact() {
		fmt.eprintln("[relay] FATAL: compaction failed; refusing to append")
		os.exit(1)
	}
	if !reopen_for_append() {
		fmt.eprintln("[relay] FATAL: no appendable log")
		os.exit(1)
	}
	fmt.printfln("[relay] store: %d live events, %d retained deleted IDs, %d streams", len(g_order), len(g_deleted), len(g_streams))
}

Record_Status :: enum { Complete, Incomplete, Corrupt }

decode_record :: proc(data: []u8) -> (type: u8, payload: []u8, size: int, status: Record_Status) {
	if len(data) == 0 do return 0, nil, 0, .Incomplete
	type = data[0]
	if type != 'E' && type != 'T' && type != 'A' && type != 'S' && type != 'H' do return type, nil, 0, .Corrupt
	if len(data) < 5 do return type, nil, 0, .Incomplete
	n := int(data[1]) | int(data[2]) << 8 | int(data[3]) << 16 | int(data[4]) << 24
	if n <= 0 || n > record_max_payload(type) || (type == 'T' && n != 64) do return type, nil, 0, .Corrupt
	if (type == 'S' && n <= SEQ_PREFIX) || (type == 'H' && n <= HEAD_PREFIX) do return type, nil, 0, .Corrupt
	size = n + 9
	if size > len(data) do return type, nil, size, .Incomplete
	payload = data[5:5+n]
	c := data[5+n:size]
	want := u32(c[0]) | u32(c[1]) << 8 | u32(c[2]) << 16 | u32(c[3]) << 24
	seed := record_crc_covers_header(type) ? hash.crc32(data[:5]) : u32(0)
	if hash.crc32(payload, seed) != want do return type, payload, size, .Corrupt
	return type, payload, size, .Complete
}

// Replay input: the whole log in buf (fd == nil), or a window buf[lo:hi]
// over fd that refill slides forward.
Log_Source :: struct {
	fd:     ^os.File,
	buf:    []u8,
	lo, hi: int,
	eof:    bool,
	err:    os.Error,
}

// Moves the unconsumed bytes to the front, then reads until buf is full or
// fd is exhausted. A read error stops replay without judging the tail.
refill :: proc(src: ^Log_Source) -> bool {
	src.hi = copy(src.buf, src.buf[src.lo:src.hi])
	src.lo = 0
	for src.hi < len(src.buf) {
		n, err := os.read(src.fd, src.buf[src.hi:])
		src.hi += max(n, 0)
		if err == .EOF || (err == nil && n <= 0) { src.eof = true; break }
		if err != nil { src.err = err; return false }
	}
	return true
}

replay :: proc(data: []u8) -> (good: int, status: Record_Status) {
	src := Log_Source{buf = data, hi = len(data), eof = true}
	return replay_source(&src)
}

// Boot path: streams the log at fd through a REPLAY_BUFFER window, with the
// same records, offsets and status as replay over the whole file. torn is the
// byte count past good when status is .Incomplete. A non-nil err means a read
// failed and status says nothing about the file.
replay_file :: proc(fd: ^os.File) -> (good, torn: int, status: Record_Status, err: os.Error) {
	src := Log_Source{fd = fd, buf = make([]u8, REPLAY_BUFFER)}
	defer delete(src.buf)
	good, status = replay_source(&src)
	return good, src.hi - src.lo, status, src.err
}

replay_source :: proc(src: ^Log_Source) -> (good: int, status: Record_Status) {
	// Reclaim parse trees after each record, not after the entire log.
	arena: mem.Dynamic_Arena
	mem.dynamic_arena_init(&arena)
	defer mem.dynamic_arena_destroy(&arena)
	context.temp_allocator = mem.dynamic_arena_allocator(&arena)
	for {
		type, payload, size, record_status := decode_record(src.buf[src.lo:src.hi])
		if record_status == .Incomplete {
			if !src.eof {
				// The window may end mid-record: slide it. Payloads are
				// cloned by intern, so nothing references the moved bytes.
				if !refill(src) do return good, .Incomplete
				continue
			}
			if src.lo == src.hi do break
			// A torn tail is ALWAYS truncated, no rescan: bytes after an
			// interrupted append are untrustworthy, even when some suffix of
			// them happens to decode as a complete CRC-valid frame. Only
			// mid-log damage (bad CRC on a complete-sized record) is .Corrupt
			// and preserved for operator recovery.
			return good, .Incomplete
		}
		if record_status == .Corrupt do return good, .Corrupt
		if type == 'T' {
			if !is_hex64(string(payload)) do return good, .Corrupt
			remember_deleted(string(payload))
			if s, have := g_events[string(payload)]; have do evict(s)
		} else if type == 'H' {
			head := u64le_get(payload[:HEAD_PREFIX])
			if head == 0 || head > u64(max(i64)) do return good, .Corrupt
			st := stream_get(string(payload[HEAD_PREFIX:]))
			st.head = max(st.head, i64(head))
		} else {
			mode, seq, wire := type, i64(0), payload
			if type == 'S' {
				mode = payload[0]
				raw_seq := u64le_get(payload[1:SEQ_PREFIX])
				if mode != 'A' && mode != 'E' || raw_seq == 0 || raw_seq > u64(max(i64)) do return good, .Corrupt
				seq, wire = i64(raw_seq), payload[SEQ_PREFIX:]
			}
			v, jerr := json.parse(wire, .JSON, false, context.temp_allocator)
			if jerr != nil do return good, .Corrupt
			ev, perr := parse_event(v)
			if perr != "" do return good, .Corrupt
			if seq > 0 {
				// Operations were logged in seq order; compacted inserts sit at
				// or below their H head but never twice in one stream.
				st := stream_get(stream_key(&ev))
				if mode == 'A' ? seq <= st.head : stream_has(st, seq) do return good, .Corrupt
				// Consumed even if the event no longer applies: never reused.
				st.head = max(st.head, seq)
			}
			if mode == 'A' {
				victims, message, _ := plan_operation(&ev)
				if message == "" do apply_operation(&ev, string(wire), victims[:], seq)
			} else if !(ev.id in g_events) && !(ev.id in g_deleted) {
				_ = intern(&ev, string(wire), seq)
			}
		}
		good += size
		src.lo += size
		free_all(context.temp_allocator)
	}
	return good, .Complete
}

sync_log_directory :: proc() -> bool {
	fd, err := os.open(os.dir(g_log_path), {.Read}, os.Permissions_Default_File)
	if err != nil do return false
	ok := os.sync(fd) == nil
	return os.close(fd) == nil && ok
}

// Only a fully written, synced and closed temporary file may replace the log.
// A post-rename directory-sync error is fatal too: no appends may follow it.
@(private = "file")
begin_replacement :: proc() -> (fd: ^os.File, tmp: string, ok: bool) {
	tmp = fmt.tprintf("%s.tmp", g_log_path)
	err: os.Error
	fd, err = os.open(tmp, {.Write, .Create, .Trunc}, os.Permissions_Default_File)
	return fd, tmp, err == nil
}

@(private = "file")
commit_replacement :: proc(fd: ^os.File, tmp: string, written: bool) -> bool {
	ok := written && os.sync(fd) == nil
	if os.close(fd) != nil do ok = false
	if !ok { _ = os.remove(tmp); return false }
	if os.rename(tmp, g_log_path) != nil { _ = os.remove(tmp); return false }
	return sync_log_directory()
}

replace_log :: proc(prefix: []u8, compacting: bool) -> bool {
	fd, tmp, opened := begin_replacement()
	if !opened do return false
	ok := true
	if compacting {
		// Tombstones, then every stream head (seqs of evicted events stay
		// consumed), then unsequenced events, then each stream in seq order
		// so replay appends to its slots.
		for id in g_deleted {
			if !write_record_to(fd, 'T', id) { ok = false; break }
		}
		for _, st in g_streams {
			if !ok do break
			ok = write_head_to(fd, st)
		}
		for s in g_order {
			if !ok do break
			if s.seq == 0 do ok = write_record_to(fd, 'E', s.json)
		}
		for _, st in g_streams {
			for slot in st.slots[st.lo:] {
				if !ok do break
				if slot.s != nil do ok = write_sequenced_to(fd, 'E', slot.seq, slot.s.json)
			}
		}
	} else {
		ok = write_full(fd, prefix)
	}
	return commit_replacement(fd, tmp, ok)
}

// Heals a torn tail without loading the log: the trusted prefix [0, good)
// of src streams into the replacement, committed exactly like replace_log.
truncate_log :: proc(src: ^os.File, good: int) -> bool {
	fd, tmp, opened := begin_replacement()
	if !opened do return false
	buf := make([]u8, REPLAY_BUFFER)
	defer delete(buf)
	ok := true
	off := 0
	for ok && off < good {
		n, err := os.read_at(src, buf[:min(len(buf), good-off)], i64(off))
		if err != nil || n <= 0 { ok = false; break }
		ok = write_full(fd, buf[:n])
		off += n
	}
	return commit_replacement(fd, tmp, ok)
}

// Opens g_log_path for appends and records its size. On failure g_fd stays
// untouched and the caller decides: boot exits, online compaction latches.
reopen_for_append :: proc() -> bool {
	fd, err := os.open(g_log_path, {.Write, .Create, .Append}, os.Permissions_Default_File)
	if err != nil {
		fmt.eprintln("[relay] store: cannot open log for append:", err)
		return false
	}
	size, size_err := os.file_size(fd)
	if size_err != nil || os.sync(fd) != nil || !sync_log_directory() {
		fmt.eprintln("[relay] store: cannot size and sync log and directory")
		_ = os.close(fd)
		return false
	}
	g_fd = fd
	g_log_bytes = int(size)
	return true
}

compact :: proc() -> bool {
	if !replace_log(nil, true) do return false
	g_tombs = 0
	return true
}

// Dead bytes dominate: the log is over twice what compaction would write and
// at least COMPACT_MIN_DEAD_BYTES of it is superseded, deleted or rejected.
compaction_due :: proc() -> bool {
	return g_log_bytes - g_live_bytes >= COMPACT_MIN_DEAD_BYTES && g_log_bytes > 2*g_live_bytes
}

// Runs inside store_event with g_mu held, so no query or write sees the swap.
// After the rename g_fd still names the replaced inode, so it is closed and
// the new log opened. Any failure latches g_append_failed like a failed
// append: whichever file then sits at g_log_path is a complete, synced log
// (the old one, or the fsynced replacement), and restart replays it.
compact_online :: proc() {
	before := g_log_bytes
	ok := compact()
	_ = os.close(g_fd)
	g_fd = nil
	if !ok || !reopen_for_append() {
		g_append_failed = true
		fmt.eprintln("[relay] store: online compaction failed; writes refused until restart")
		return
	}
	fmt.printfln("[relay] store: compacted log online, %d -> %d bytes", before, g_log_bytes)
}

// -- store_event -------------------------------------------------------
//
// Log first, memory second: every mutation appends its records and
// fsyncs before the maps change, so memory never claims what the disk
// could lose.

// NIP-09 address identifiers may themselves contain colons. Split only the
// kind and author fields; compare the remaining d value verbatim.
deletion_tag_matches :: proc(name, value, author: string, cutoff: i64, id, pubkey: string, kind: i64, d: string, created_at: i64) -> bool {
	if pubkey != author || kind == 5 do return false
	if name == "e" do return value == id
	if name != "a" || !is_addressable(kind) || created_at > cutoff do return false
	first := strings.index(value, ":")
	if first < 0 do return false
	rest := value[first+1:]
	second := strings.index(rest, ":")
	if second < 0 || rest[:second] != author || rest[second+1:] != d do return false
	k, ok := strconv.parse_int(value[:first])
	return ok && i64(k) == kind
}

tag_present :: proc(tags: []$T, name, value: string) -> bool {
	for tag in tags {
		if len(tag) >= 2 && tag[0] == name && tag[1] == value do return true
	}
	return false
}

// Only these kind-5s consult space_deletion_covers: an e/a-only deletion
// (the common case) never pays a second pass over its tags.
is_space_deletion :: proc(ev: ^Event) -> bool {
	if ev.kind != 5 do return false
	for tag in ev.tags {
		if len(tag) >= 2 && tag[0] == "h" do return true
	}
	return false
}

// Space deletion: a kind-5 signed by `author` with ["h", T] tags covers every
// non-kind-5 event tagged ["h", T] that `author` wrote or that consents with
// ["owner", author]. The consent tag is signed by the event's own author, so
// a deletion reaches nothing else. ["k", n] tags restrict the kinds; an
// unparseable k matches no kind, so a malformed restriction never widens it.
// No created_at cutoff: a deleted space stays deleted. Incoming events carry
// [][]string tags and stored ones [][2]string, hence the parametric shapes.
space_deletion_covers :: proc(deletion: []$D, author: string, target: []$T, pubkey: string, kind: i64) -> bool {
	if kind == 5 || (pubkey != author && !tag_present(target, "owner", author)) do return false
	in_space, restricted, kind_listed := false, false, false
	for tag in deletion {
		if len(tag) < 2 do continue
		switch tag[0] {
		case "h":
			in_space = in_space || tag_present(target, "h", tag[1])
		case "k":
			restricted = true
			k, ok := strconv.parse_int(tag[1])
			kind_listed = kind_listed || (ok && i64(k) == kind)
		}
	}
	return in_space && (!restricted || kind_listed)
}

plan_operation :: proc(ev: ^Event) -> (victims: [dynamic]^Stored, message: string, rejected: bool) {
	if ev.id in g_events do return nil, "duplicate: already have this event", false
	if ev.id in g_deleted do return nil, "blocked: event was deleted", true
	// Hoisted out of every inner loop below: d_tag(ev) is a per-event scan.
	ev_d := d_tag(ev)
	ev_space_deletion := is_space_deletion(ev)
	// Replay plans every record: arrivals consult the e-reference index and
	// only retained deletions, and regular kinds (which displace nothing)
	// skip the store scan below.
	if ev.kind != 5 && strings.concatenate({ev.pubkey, ev.id}, context.temp_allocator) in g_deletion_refs {
		return nil, "blocked: event was deleted", true
	}
	for deletion in g_deletions {
		if deletion.space_deletion && space_deletion_covers(deletion.tags, deletion.pubkey, ev.tags, ev.pubkey, ev.kind) {
			return nil, "blocked: event was deleted", true
		}
		if deletion.pubkey != ev.pubkey || !is_addressable(ev.kind) do continue
		for tag in deletion.tags {
			if tag[0] == "a" && deletion_tag_matches(tag[0], tag[1], deletion.pubkey, deletion.created_at, ev.id, ev.pubkey, ev.kind, ev_d, ev.created_at) {
				return nil, "blocked: event was deleted", true
			}
		}
	}
	victims = make([dynamic]^Stored, context.temp_allocator)
	// Tag count is checked in store_event. Victims are uncapped: e/a tags
	// name at most MAX_PLAN_TAGS live events, and a space deletion must
	// leave no survivor. The A record logs only the kind-5; replay
	// re-derives this same set, so one record removes a space of any size
	// atomically. e tags name their events, so they are looked up; `named`
	// keeps repeated e tags from producing duplicate pointers (and therefore
	// double frees), and the store scan only runs for a/h tags.
	scan := is_replaceable(ev.kind) || is_addressable(ev.kind) || ev_space_deletion
	named := make(map[^Stored]bool, context.temp_allocator)
	if ev.kind == 5 {
		for tag, i in ev.tags {
			if i >= MAX_PLAN_TAGS do break
			if len(tag) < 2 do continue
			if tag[0] == "a" do scan = true
			if tag[0] != "e" do continue
			s, stored := g_events[tag[1]]
			if !stored || s in named do continue
			if deletion_tag_matches(tag[0], tag[1], ev.pubkey, ev.created_at, s.id, s.pubkey, s.kind, s.d, s.created_at) {
				named[s] = true
				append(&victims, s)
			}
		}
	}
	if !scan do return victims, "", false
	d := is_addressable(ev.kind) ? ev_d : ""
	for s in g_order {
		if s in named do continue
		victim := false
		if (is_replaceable(ev.kind) || is_addressable(ev.kind)) && s.pubkey == ev.pubkey && s.kind == ev.kind && (!is_addressable(ev.kind) || s.d == d) {
			if s.created_at > ev.created_at || (s.created_at == ev.created_at && s.id < ev.id) {
				return victims, "duplicate: have a newer version", false
			}
			victim = true
		}
		if ev.kind == 5 {
			if ev_space_deletion && space_deletion_covers(ev.tags, ev.pubkey, s.tags, s.pubkey, s.kind) do victim = true
			for tag, i in ev.tags {
				if victim || i >= MAX_PLAN_TAGS do break
				if len(tag) >= 2 && tag[0] == "a" && deletion_tag_matches(tag[0], tag[1], ev.pubkey, ev.created_at, s.id, s.pubkey, s.kind, s.d, s.created_at) do victim = true
			}
		}
		if victim do append(&victims, s)
	}
	return victims, "", false
}

apply_operation :: proc(ev: ^Event, wire: string, victims: []^Stored, seq: i64 = 0) {
	for s in victims do evict(s)
	_ = intern(ev, wire, seq)
}

// Anonymous gift wraps are bounded per recipient: once a resident holds
// ANON_MAX_GIFTS_PER_TARGET kind-1059 envelopes, further stranger gifts to
// them are rejected (nothing is evicted). Write-path only, never consulted
// during replay: anonymity depends on the dynamic allowlist, which is empty
// at boot, so a replay-time check could drop events the writer accepted.
gift_inbox_full :: proc(ev: ^Event) -> bool {
	if ev.kind != 1059 || !anonymous_writer(ev) do return false
	seen := make(map[string]bool, context.temp_allocator)
	for tag, i in ev.tags {
		if i >= MAX_PLAN_TAGS do break
		if len(tag) < 2 || tag[0] != "p" || tag[1] in seen || !write_allowed(tag[1]) do continue
		seen[tag[1]] = true
		count := 0
		for s in g_order {
			if s.kind != 1059 do continue
			for t in s.tags {
				if t[0] == "p" && t[1] == tag[1] { count += 1; break }
			}
		}
		if count >= ANON_MAX_GIFTS_PER_TARGET do return true
	}
	return false
}

// seq_out receives the stored event's stream seq (0 when unsequenced).
store_event :: proc(ev: ^Event, seq_out: ^i64 = nil) -> (ok: bool, message: string) {
	sync.lock(&g_mu)
	defer sync.unlock(&g_mu)
	if g_append_failed do return false, "error: storage requires recovery"
	// A revocation may have committed while signature verification ran.
	if !event_write_allowed(ev) do return false, "restricted: pubkey not on the allowlist"
	wire := event_json(ev)
	if len(wire) > MAX_RECORD do return false, "invalid: serialized event too large"
	if ev.kind == 5 && len(ev.tags) > MAX_PLAN_TAGS do return false, fmt.tprintf("invalid: deletion lists more than %d tags", MAX_PLAN_TAGS)
	if gift_inbox_full(ev) do return false, "blocked: recipient gift inbox is full"
	victims, msg, rejected := plan_operation(ev)
	if msg != "" do return !rejected, msg
	anon := anonymous_writer(ev)
	if anon {
		freed := 0
		for s in victims do if s.anon do freed += len(s.json)
		if g_anon_bytes - freed + len(wire) > ANON_MAX_TOTAL_BYTES {
			return false, "blocked: anonymous storage quota exceeded"
		}
	}
	// Only a committed append consumes the seq: every rejection above and a
	// failed append leave the head untouched, so the stream stays gap-free.
	seq: i64 = 0
	if !anon {
		seq = 1
		if st, have := g_streams[stream_key(ev)]; have do seq = st.head + 1
	}
	if !append_operation(wire, seq) do return false, "error: storage failure"
	apply_operation(ev, wire, victims[:], seq)
	if seq_out != nil do seq_out^ = seq
	if ev.kind == 5 || ev.kind == ALLOWLIST_KIND do refresh_dynamic_allowlist_locked()
	// The event is durable in the old log and live in memory, so it survives
	// compaction (and its failure) either way.
	if compaction_due() do compact_online()
	return true, ""
}

// -- query_filter ------------------------------------------------------

Stored_Event :: struct {
	id:   string,
	json: string,
	seq:  i64, // 0 when unsequenced
}

DEFAULT_LIMIT :: 500

@(private = "file")
matches :: proc(s: ^Stored, f: ^Filter) -> bool {
	// after: exactly the named stream, past the cursor.
	if f.has_after && (s.stream == nil || s.seq <= f.after || s.stream.key != f.stream) do return false
	if len(f.ids) > 0 && !slice.contains(f.ids, s.id) do return false
	if len(f.authors) > 0 && !slice.contains(f.authors, s.pubkey) do return false
	if len(f.kinds) > 0 && !slice.contains(f.kinds, s.kind) do return false
	if f.since != 0 && s.created_at < f.since do return false
	if f.until != 0 && s.created_at > f.until do return false
	for tf in f.tags {
		hit := false
		for t in s.tags {
			if t[0] == tf.name && slice.contains(tf.values, t[1]) {
				hit = true
				break
			}
		}
		if !hit do return false
	}
	return true
}

MAX_QUERY_BYTES :: 8 << 20
// Includes escaped subscription ID, EVENT envelope, copied ID and metadata.
QUERY_ROW_OVERHEAD :: 512

stored_before :: proc(a, b: ^Stored) -> bool {
	if a.created_at != b.created_at do return a.created_at > b.created_at
	return a.id < b.id
}

// Without `after`, a worst-first heap retains at most MAX_LIMIT pointers
// regardless of total matches, newest first. With `after`, the stream's
// slots past the cursor are already in ascending seq order and the first
// `limit` matches are the page. Clone only a byte-budgeted prefix. cursor,
// when given, receives the after stream's head and oldest kept seq from the
// same locked snapshot as the rows (limit 0 returns just the cursor).
query_filter :: proc(f: ^Filter, byte_budget := MAX_QUERY_BYTES, cursor: ^Stream_Cursor = nil) -> (rows: []Stored_Event, exhausted: bool) {
	sync.lock(&g_mu)
	defer sync.unlock(&g_mu)
	limit := int(f.has_limit || f.limit > 0 ? f.limit : DEFAULT_LIMIT)
	limit = clamp(limit, 0, MAX_LIMIT)
	storage: [MAX_LIMIT]^Stored
	if f.has_after {
		st := g_streams[f.stream]
		if cursor != nil do cursor^ = stream_cursor(st)
		if st == nil || limit == 0 || f.after >= st.head do return nil, false
		count := 0
		for i := max(stream_search(st, f.after + 1), st.lo); i < len(st.slots) && count < limit; i += 1 {
			s := st.slots[i].s
			if s == nil || !matches(s, f) do continue
			storage[count] = s
			count += 1
		}
		return budgeted_rows(storage[:count], byte_budget)
	}
	if limit == 0 do return nil, false
	count := 0
	for s in g_order {
		if !matches(s, f) do continue
		if count < limit {
			i := count
			count += 1
			storage[i] = s
			for i > 0 {
				parent := (i-1)/2
				if !stored_before(storage[parent], storage[i]) do break
				storage[parent], storage[i] = storage[i], storage[parent]
				i = parent
			}
		} else if stored_before(s, storage[0]) {
			storage[0] = s
			i := 0
			for 2*i+1 < count {
				child := 2*i+1
				if child+1 < count && stored_before(storage[child], storage[child+1]) do child += 1
				if !stored_before(storage[i], storage[child]) do break
				storage[i], storage[child] = storage[child], storage[i]
				i = child
			}
		}
	}
	hits := storage[:count]
	slice.sort_by(hits, stored_before)
	return budgeted_rows(hits, byte_budget)
}

// Clones the longest prefix of hits that fits byte_budget; exhausted when
// that prefix is shorter than hits.
@(private = "file")
budgeted_rows :: proc(hits: []^Stored, byte_budget: int) -> (rows: []Stored_Event, exhausted: bool) {
	bytes := 0
	returned := 0
	for s in hits {
		cost := len(s.json) + QUERY_ROW_OVERHEAD
		if cost > byte_budget-bytes { exhausted = true; break }
		bytes += cost
		returned += 1
	}
	rows = make([]Stored_Event, returned, context.temp_allocator)
	for s, i in hits[:returned] {
		rows[i] = {id = strings.clone(s.id, context.temp_allocator), json = strings.clone(s.json, context.temp_allocator), seq = s.seq}
	}
	return rows, exhausted
}

// NIP-77 item set: every stored event matching f, ignoring limit and the
// response byte budget (only ids are kept). Deleted and superseded events
// are never in g_order, so deletions apply exactly as in query_filter.
// Negentropy timestamps are unsigned: negative created_at cannot be ranged
// and is left out. ok=false once more than max_items match. The caller owns
// items (context.allocator).
neg_collect :: proc(f: ^Filter, max_items: int) -> (items: []Neg_Item, ok: bool) {
	out := make([dynamic]Neg_Item)
	{
		sync.lock(&g_mu)
		defer sync.unlock(&g_mu)
		for s in g_order {
			if s.created_at < 0 || !matches(s, f) do continue
			if len(out) == max_items {
				delete(out)
				return nil, false
			}
			item := Neg_Item{timestamp = u64(s.created_at)}
			for i in 0 ..< NEG_ID_SIZE do item.id[i] = hex_nibble(s.id[2*i]) << 4 | hex_nibble(s.id[2*i+1])
			append(&out, item)
		}
	}
	slice.sort_by(out[:], neg_item_less)
	return out[:], true
}

// Stored ids are validated lowercase hex (is_hex64).
@(private = "file")
hex_nibble :: proc(c: u8) -> u8 {
	return c - '0' if c <= '9' else c - 'a' + 10
}

// -- Dynamic allowlist (kind 30100 "roostr-allowlist") ----------------
//
// Resident (env-allowlisted) keys administer extra writer pubkeys by
// publishing an addressable kind-30100 event whose p-tags list them.
// Union across resident authors; refreshed at startup and whenever a
// resident stores a fresh 30100.

ALLOWLIST_KIND :: 30100

g_dynamic: map[string]bool
g_dynamic_mu: sync.Mutex

write_allowed :: proc(pubkey: string) -> bool {
	if pubkey in g_allowed do return true
	sync.lock(&g_dynamic_mu)
	defer sync.unlock(&g_dynamic_mu)
	return pubkey in g_dynamic
}

refresh_dynamic_allowlist :: proc() {
	sync.lock(&g_mu)
	defer sync.unlock(&g_mu)
	refresh_dynamic_allowlist_locked()
}

// Called with g_mu held, including publication: an older snapshot can never
// overwrite a newer revocation. Lock order is always g_mu -> g_dynamic_mu.
refresh_dynamic_allowlist_locked :: proc() {
	next := make(map[string]bool)
	for s in g_order {
		if s.kind != ALLOWLIST_KIND || !(s.pubkey in g_allowed) do continue
		for t in s.tags {
			if t[0] == "p" && is_hex64(t[1]) && !(t[1] in next) do next[strings.clone(t[1])] = true
		}
	}
	count := len(next)
	sync.lock(&g_dynamic_mu)
	old := g_dynamic
	g_dynamic = next
	sync.unlock(&g_dynamic_mu)
	if old != nil {
		for k in old do delete(k)
		delete(old)
	}
	fmt.printfln("[relay] dynamic allowlist: %d pubkey(s)", count)
}
