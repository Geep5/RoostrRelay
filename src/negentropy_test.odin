package relay

import "core:crypto/sha2"
import "core:encoding/hex"
import "core:fmt"
import "core:math/rand"
import "core:slice"
import "core:strings"
import "core:sync"
import "core:testing"

// Expected values come from the hoytech/negentropy JS reference
// (js/Negentropy.js at b3687652), generated with the same inputs.
when ODIN_TEST {
	neg_test_hex :: proc(b: []byte) -> string {
		return string(hex.encode(b, context.temp_allocator))
	}

	neg_test_unhex :: proc(s: string) -> []byte {
		b, _ := hex.decode(transmute([]byte)s, context.temp_allocator)
		return b
	}

	neg_test_sha :: proc(s: string) -> (out: [32]byte) {
		ctx: sha2.Context_256
		sha2.init_256(&ctx)
		sha2.update(&ctx, transmute([]byte)s)
		sha2.final(&ctx, out[:])
		return out
	}

	// Mirrors the reference fixture: timestamp base + i/3, id sha256("item-<i>").
	neg_test_items :: proc(n: int, skip_every := 0) -> []Neg_Item {
		out := make([dynamic]Neg_Item, context.temp_allocator)
		for i in 0 ..< n {
			if skip_every > 0 && i % skip_every == 0 do continue
			append(&out, Neg_Item{timestamp = u64(1_700_000_000 + i / 3), id = neg_test_sha(fmt.tprintf("item-%d", i))})
		}
		slice.sort_by(out[:], neg_item_less)
		return out[:]
	}

	// Initiator (client) side, test-only: mirrors the reference so the responder
	// can be driven to convergence. The relay itself never initiates.
	neg_test_initiate :: proc(items: []Neg_Item) -> []byte {
		codec: Neg_Codec
		out := make([dynamic]byte, context.temp_allocator)
		append(&out, NEG_PROTOCOL_VERSION)
		neg_split_range(&codec, items, 0, len(items), Neg_Bound{item = {timestamp = NEG_INFINITY}}, &out)
		return out[:]
	}

	// Returns nil when reconciliation is complete.
	neg_test_client_step :: proc(t: ^testing.T, items: []Neg_Item, query: []byte, frame_size_limit: int, have, need: ^map[[32]byte]bool) -> []byte {
		r := Neg_Reader{data = query}
		codec: Neg_Codec
		full := make([dynamic]byte, context.temp_allocator)
		append(&full, NEG_PROTOCOL_VERSION)
		version, _ := neg_get_bytes(&r, 1)
		testing.expect(t, version[0] == NEG_PROTOCOL_VERSION)
		o := make([dynamic]byte, context.temp_allocator)
		prev_bound: Neg_Bound
		prev_index := 0
		skip := false
		for r.pos < len(r.data) {
			clear(&o)
			curr_bound, berr := neg_get_bound(&codec, &r)
			testing.expect(t, berr == "")
			mode, _ := neg_get_varint(&r)
			lower := prev_index
			upper := neg_lower_bound(items, prev_index, len(items), curr_bound.item)
			switch Neg_Mode(mode) {
			case .Skip:
				skip = true
			case .Fingerprint:
				theirs, _ := neg_get_bytes(&r, NEG_FINGERPRINT_SIZE)
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
			case .Id_List:
				count, _ := neg_get_varint(&r)
				theirs := make(map[[32]byte]bool, context.temp_allocator)
				for _ in 0 ..< count {
					id, _ := neg_get_bytes(&r, NEG_ID_SIZE)
					key: [32]byte
					copy(key[:], id)
					theirs[key] = true
				}
				skip = true
				for item in items[lower:upper] {
					if item.id in theirs do delete_key(&theirs, item.id)
					else do have[item.id] = true
				}
				for id in theirs do need[id] = true
			}
			if neg_frame_exceeded(frame_size_limit, len(full) + len(o)) {
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
		return nil if len(full) == 1 else full[:]
	}

	@(test)
	negentropy_varint_vectors :: proc(t: ^testing.T) {
		cases := [?]struct {
			n:       u64,
			encoded: string,
		} {
			{0, "00"},
			{1, "01"},
			{127, "7f"},
			{128, "8100"},
			{255, "817f"},
			{16383, "ff7f"},
			{16384, "818000"},
			{2097151, "ffff7f"},
			{2097152, "81808000"},
			{4294967295, "8fffffff7f"},
		}
		for c in cases {
			out := make([dynamic]byte, context.temp_allocator)
			neg_put_varint(&out, c.n)
			testing.expect_value(t, neg_test_hex(out[:]), c.encoded)
			r := Neg_Reader{data = out[:]}
			n, ok := neg_get_varint(&r)
			testing.expect(t, ok && n == c.n && r.pos == len(out))
		}
		out := make([dynamic]byte, context.temp_allocator)
		neg_put_varint(&out, max(u64))
		r := Neg_Reader{data = out[:]}
		n, ok := neg_get_varint(&r)
		testing.expect(t, ok && n == max(u64))
		// Truncated and overflowing varints are malformed.
		r = Neg_Reader{data = neg_test_unhex("8181")}
		_, ok = neg_get_varint(&r)
		testing.expect(t, !ok)
		r = Neg_Reader{data = neg_test_unhex("ffffffffffffffffffff7f")}
		_, ok = neg_get_varint(&r)
		testing.expect(t, !ok)
	}

	@(test)
	negentropy_fingerprint_vectors :: proc(t: ^testing.T) {
		item :: proc(s: string) -> (it: Neg_Item) {
			copy(it.id[:], neg_test_unhex(s))
			return it
		}
		fp := neg_fingerprint(nil)
		testing.expect_value(t, neg_test_hex(fp[:]), "7f9c9e31ac8256ca2f258583df262dbc")
		ee := [?]Neg_Item{item("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")}
		fp = neg_fingerprint(ee[:])
		testing.expect_value(t, neg_test_hex(fp[:]), "d5530eded759c1cb5749aacb9bc66bb2")
		// ff..ff + 1 wraps to zero: the sum is mod 2^256, little-endian.
		carry := [?]Neg_Item{item("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"), item("0100000000000000000000000000000000000000000000000000000000000000")}
		fp = neg_fingerprint(carry[:])
		testing.expect_value(t, neg_test_hex(fp[:]), "58cc2f44d3a27866874701fbad573da9")
		// 200 items: the count varint takes two bytes.
		many := make([]Neg_Item, 200, context.temp_allocator)
		for &it, i in many do it.id = neg_test_sha(fmt.tprintf("neg-vector-%d", i))
		fp = neg_fingerprint(many)
		testing.expect_value(t, neg_test_hex(fp[:]), "eb5634975532cfd8869fdb10d87f218e")
	}

	@(test)
	negentropy_bound_vectors :: proc(t: ^testing.T) {
		full_id := neg_test_sha("bound")
		bounds := [?]Neg_Bound{
			{item = {timestamp = 100}},
			{item = {timestamp = 100, id = {0 = 0x01, 1 = 0xab}}, id_len = 2},
			{item = {timestamp = 150, id = full_id}, id_len = 32},
			{item = {timestamp = NEG_INFINITY}},
		}
		codec: Neg_Codec
		out := make([dynamic]byte, context.temp_allocator)
		for b in bounds do neg_put_bound(&codec, &out, b)
		testing.expect_value(t, neg_test_hex(out[:]), "6500010201ab33205e1cf42878df58fea7bfa45b715b7832d889092ad23e802e63912b1bfd2056300000")
		decoder: Neg_Codec
		r := Neg_Reader{data = out[:]}
		for want in bounds {
			got, err := neg_get_bound(&decoder, &r)
			testing.expect(t, err == "" && got == want)
		}
		testing.expect(t, r.pos == len(out))
		// A prefix longer than an id is rejected.
		r = Neg_Reader{data = neg_test_unhex("0121")}
		_, err := neg_get_bound(&decoder, &r)
		testing.expect_value(t, err, "bound key too long")
		// Minimal bounds: timestamp only, else the shared prefix plus one byte.
		a := Neg_Item{timestamp = 5, id = {0 = 1, 1 = 2, 2 = 3}}
		b := Neg_Item{timestamp = 5, id = {0 = 1, 1 = 2, 2 = 9}}
		m := neg_minimal_bound(a, b)
		testing.expect(t, m.id_len == 3 && m.item.timestamp == 5 && m.item.id[2] == 9)
		testing.expect(t, neg_item_less(a, m.item) && !neg_item_less(b, m.item))
		m = neg_minimal_bound(a, Neg_Item{timestamp = 6})
		testing.expect(t, m.id_len == 0 && m.item.timestamp == 6)
	}

	@(test)
	negentropy_reference_responses :: proc(t: ^testing.T) {
		single := [?]Neg_Item{{timestamp = 12345}}
		for &b in single[0].id do b = 0xee
		out, err := neg_reconcile(single[:], neg_test_unhex("6100000200"), 0)
		testing.expect(t, err == "")
		testing.expect_value(t, neg_test_hex(out), "6100000201eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")
		// Newer protocol: answer with the highest supported version only.
		out, err = neg_reconcile(single[:], neg_test_unhex("62aabbccddeeff"), 0)
		testing.expect(t, err == "" && neg_test_hex(out) == "61")

		digest :: proc(s: string) -> string {
			d := neg_test_sha(s)
			return neg_test_hex(d[:])
		}
		// Reference client initiate() over 100 items minus every 7th.
		q := "6186aacfe203011801c100b48c2de9a02d2511d6ae75e2dfcf04000138f17789da714ebad845727b7a8fe85803000194c1225f19286ba5def9f747d89414fd0301900112b8b2803fcc2f3e5e179edeeaf939dc040001563bca3bb6414456070447c2eefee5270201e60199b915d251317d918cac837505a71aed0301fb011244cd807118320283c855f757bd00880301ff0191309a10bae62ab478e9820c2e5f6cd40301ea0154e778558825f398b559ecfd524d5fe903016801d88f01ffae0fd8766bd9f45e1d8657160301dc013ac7d39a92814aa8a386e6895e7fbf930301a001dd2c521884e19b0f17df24392e33aad303019a016b367dae85dba6cbf2b5f2516aada25703012201174c653e4338e05d53739f9703a2625f03019a01e64f99e75174e61776bd672f7398c4720000016f0d7a042e9a4c91bbd6b9f1c47977f9"
		testing.expect_value(t, neg_test_hex(neg_test_initiate(neg_test_items(100, 7))), q)
		out, err = neg_reconcile(neg_test_items(100), neg_test_unhex(q), 0)
		resp := neg_test_hex(out)
		testing.expect(t, err == "" && len(resp) == 5532)
		testing.expect_value(t, digest(resp), "30453d071c885f1e7253fc4f7cc563463f5d08acfa69531529bdd1603aa234e3")
		// Empty client against 1000 items with a 4096-byte frame: truncated
		// IdList followed by a fingerprint of the remainder.
		out, err = neg_reconcile(neg_test_items(1000), neg_test_unhex("6100000200"), 4096)
		resp = neg_test_hex(out)
		testing.expect(t, err == "" && len(resp) == 7928 && len(out) <= 4096)
		testing.expect_value(t, digest(resp), "4639b68a4af087a17645a4516bb48bffca74921bf558ffd2c5baf47318cf6638")

		malformed := [?]string{"", "5f", "70", "6101", "610000", "6100000300", "610000020100", "6100000102"}
		for m in malformed {
			_, merr := neg_reconcile(neg_test_items(10), neg_test_unhex(m), 0)
			testing.expectf(t, merr != "", "%s must be rejected", m)
		}
	}

	@(test)
	negentropy_reconcile_converges :: proc(t: ^testing.T) {
		Case :: struct {
			n, client_limit, server_limit: int,
		}
		cases := [?]Case{{0, 0, 0}, {1, 0, 0}, {60, 0, 0}, {5000, 0, 0}, {20000, 60_000, NEG_FRAME_SIZE_LIMIT}, {20000, 0, 4096}, {20000, 4096, 4096}}
		gen := rand.create(77)
		context.random_generator = rand.default_random_generator(&gen)
		for c in cases {
			client := make([dynamic]Neg_Item, context.temp_allocator)
			server := make([dynamic]Neg_Item, context.temp_allocator)
			want_have := make(map[[32]byte]bool, context.temp_allocator)
			want_need := make(map[[32]byte]bool, context.temp_allocator)
			for i in 0 ..< c.n {
				// Tight timestamp spread forces same-second id-prefix bounds.
				it := Neg_Item{timestamp = u64(1_700_000_000 + rand.int_max(max(1, c.n / 10)))}
				for &b in it.id do b = u8(rand.uint32())
				switch rand.int_max(10) {
				case 0:
					append(&client, it)
					want_have[it.id] = true
				case 1:
					append(&server, it)
					want_need[it.id] = true
				case:
					append(&client, it)
					append(&server, it)
				}
			}
			slice.sort_by(client[:], neg_item_less)
			slice.sort_by(server[:], neg_item_less)
			have := make(map[[32]byte]bool, context.temp_allocator)
			need := make(map[[32]byte]bool, context.temp_allocator)
			msg := neg_test_initiate(client[:])
			rounds := 0
			for msg != nil {
				resp, err := neg_reconcile(server[:], msg, c.server_limit)
				testing.expect(t, err == "")
				if c.server_limit != 0 do testing.expect(t, len(resp) <= c.server_limit)
				msg = neg_test_client_step(t, client[:], resp, c.client_limit, &have, &need)
				rounds += 1
				if rounds > 10_000 do break
			}
			testing.expectf(t, len(have) == len(want_have) && len(need) == len(want_need), "case %v: have %d/%d need %d/%d", c, len(have), len(want_have), len(need), len(want_need))
			for id in want_have do testing.expect(t, id in have)
			for id in want_need do testing.expect(t, id in need)
		}
	}

	@(test)
	negentropy_collect_matches_filter_deletions_and_cap :: proc(t: ^testing.T) {
		sync.lock(&store_test_mu)
		defer sync.unlock(&store_test_mu)
		store_test_reset()
		defer store_test_cleanup()
		// Ten kind-1078 events (four sharing created_at 30), one kind-1, one
		// with a negative created_at that negentropy cannot range.
		for i in 1 ..= 10 {
			ev := store_test_event(i, 1078, i <= 4 ? 30 : i64(40 - i))
			_ = intern(&ev, event_json(&ev))
		}
		other := store_test_event(11, 1)
		_ = intern(&other, event_json(&other))
		negative := store_test_event(12, 1078, -5)
		_ = intern(&negative, event_json(&negative))
		victim := store_test_event(3, 1078, 30)
		del := store_test_tagged(13, victim.pubkey, 5, [][]string{{"e", victim.id}}, 50)
		_, message := store_test_apply(&del)
		testing.expect_value(t, message, "")

		// limit never trims the item set.
		f := Filter{kinds = {1078}, limit = 1, has_limit = true}
		items, ok := neg_collect(&f, MAX_NEG_ITEMS)
		defer delete(items)
		testing.expect(t, ok && len(items) == 9)
		for i in 1 ..< len(items) do testing.expect(t, neg_item_less(items[i - 1], items[i]))
		victim_id: [32]byte
		victim_id[31] = 3
		for it in items do testing.expect(t, it.id != victim_id)
		testing.expect(t, items[len(items) - 1].timestamp == 35 && items[len(items) - 1].id[31] == 5)

		capped, cok := neg_collect(&f, 8)
		testing.expect(t, !cok && capped == nil)
		exact, eok := neg_collect(&f, 9)
		defer delete(exact)
		testing.expect(t, eok && len(exact) == 9)
	}

	neg_test_reply :: proc(c: ^Conn) -> string {
		if c.out_count == 0 do return ""
		frame := ws_queue_pop(c)
		c.out_bytes -= len(frame)
		defer delete(frame, c.allocator)
		return strings.clone(string(frame), context.temp_allocator)
	}

	@(test)
	nip77_session_lifecycle :: proc(t: ^testing.T) {
		sync.lock(&store_test_mu)
		defer sync.unlock(&store_test_mu)
		store_test_reset()
		defer store_test_cleanup()
		single := store_test_event(1, 1078, 12345)
		_ = intern(&single, event_json(&single))
		c := Conn{allocator = context.allocator}
		defer ws_queue_discard(&c)
		defer neg_close_all(&c)

		handle_message(&c, `["NEG-OPEN","a",{"kinds":[1078]},"6100000200"]`)
		testing.expect(t, strings.contains(neg_test_reply(&c), fmt.tprintf(`["NEG-MSG","a","6100000201%s"]`, single.id)))
		handle_message(&c, `["NEG-MSG","a","6100000200"]`)
		testing.expect(t, strings.contains(neg_test_reply(&c), `["NEG-MSG","a","6100000201`))
		// Malformed rounds answer NEG-ERR and close the session.
		handle_message(&c, `["NEG-MSG","a","61ff"]`)
		testing.expect(t, strings.contains(neg_test_reply(&c), `["NEG-ERR","a","invalid: parse ends prematurely"]`))
		handle_message(&c, `["NEG-MSG","a","6100000200"]`)
		testing.expect(t, strings.contains(neg_test_reply(&c), `["NEG-ERR","a","closed: `))
		handle_message(&c, `["NEG-OPEN","bad",{"kinds":"x"},"6100000200"]`)
		testing.expect(t, strings.contains(neg_test_reply(&c), `["NEG-ERR","bad","invalid: bad filter"]`))

		for i in 0 ..< MAX_NEG_SESSIONS_PER_CONN {
			handle_message(&c, fmt.tprintf(`["NEG-OPEN","s%d",{{}},"6100000200"]`, i))
			testing.expect(t, strings.contains(neg_test_reply(&c), `"NEG-MSG"`))
		}
		// Reopening an id replaces its session instead of taking a slot.
		handle_message(&c, `["NEG-OPEN","s0",{},"6100000200"]`)
		testing.expect(t, strings.contains(neg_test_reply(&c), `"NEG-MSG"`))
		handle_message(&c, `["NEG-OPEN","extra",{},"6100000200"]`)
		testing.expect(t, strings.contains(neg_test_reply(&c), `["NEG-ERR","extra","blocked: `))
		handle_message(&c, `["NEG-CLOSE","s1"]`)
		testing.expect(t, len(c.negs) == MAX_NEG_SESSIONS_PER_CONN - 1)
		handle_message(&c, `["NEG-OPEN","extra",{},"6100000200"]`)
		testing.expect(t, strings.contains(neg_test_reply(&c), `"NEG-MSG"`))
		testing.expect(t, len(c.negs) == MAX_NEG_SESSIONS_PER_CONN)
	}
}
