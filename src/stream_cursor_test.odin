package relay

// Relay cursor (glonOdin docs/state-objects.md): per-stream seq, REQ
// `after`, EOSE {"head","oldest"} and EVENT {"seq"} for after subscriptions.

import "base:runtime"
import "core:encoding/json"
import "core:fmt"
import "core:mem"
import "core:os"
import "core:slice"
import "core:strings"
import "core:sync"
import "core:testing"
import "core:thread"

when ODIN_TEST {
	CURSOR_ALICE :: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	CURSOR_BOB :: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	CURSOR_STRANGER :: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

	// An event in space stream `space` ("" = the author's personal stream).
	cursor_test_event :: proc(n: int, pubkey: string, kind: i64, space: string, timestamp: i64 = 10, extra: []string = nil) -> Event {
		tags := make([dynamic][]string, context.temp_allocator)
		if space != "" do append(&tags, cursor_test_tag("s", space))
		if extra != nil do append(&tags, cursor_test_tag(extra[0], extra[1]))
		return store_test_tagged(n, pubkey, kind, tags[:], timestamp)
	}

	cursor_test_tag :: proc(name, value: string) -> []string {
		tag := make([]string, 2, context.temp_allocator)
		tag[0], tag[1] = name, value
		return tag
	}

	// Stores ev (which must be accepted as new) and returns its seq.
	cursor_test_store :: proc(t: ^testing.T, ev: ^Event, loc := #caller_location) -> i64 {
		seq: i64 = -1
		ok, message := store_event(ev, &seq)
		testing.expectf(t, ok && message == "", "store %s: %v %s", ev.id, ok, message, loc = loc)
		return seq
	}

	cursor_test_filter :: proc(t: ^testing.T, src: string, loc := #caller_location) -> Filter {
		v, err := json.parse_string(src, allocator = context.temp_allocator)
		testing.expect(t, err == nil, src, loc = loc)
		f, ok := parse_filter(v)
		testing.expect(t, ok, src, loc = loc)
		return f
	}

	cursor_test_seqs :: proc(rows: []Stored_Event) -> []i64 {
		out := make([]i64, len(rows), context.temp_allocator)
		for r, i in rows do out[i] = r.seq
		return out
	}

	cursor_test_cursor :: proc(key: string) -> Stream_Cursor {
		return stream_cursor(g_streams[key])
	}

	// Payload of the next queued server frame (always unmasked).
	cursor_test_reply :: proc(c: ^Conn) -> string {
		if c.out_count == 0 do return ""
		frame := ws_queue_pop(c)
		c.out_bytes -= len(frame)
		defer delete(frame, c.allocator)
		off := 2
		switch frame[1] & 0x7f {
		case 126: off = 4
		case 127: off = 10
		}
		return strings.clone(string(frame[off:]), context.temp_allocator)
	}

	cursor_test_drain :: proc(c: ^Conn) -> []string {
		out := make([dynamic]string, context.temp_allocator)
		for c.out_count > 0 do append(&out, cursor_test_reply(c))
		return out[:]
	}

	cursor_test_conn_free :: proc(c: ^Conn) {
		for _, &sub in c.subs do mem.dynamic_arena_destroy(&sub.arena)
		delete(c.subs)
		ws_queue_discard(c)
	}

	cursor_test_event_msg :: proc(sub: string, id: string, seq: i64 = 0) -> string {
		js := g_events[id].json
		if seq > 0 do return fmt.tprintf(`["EVENT","%s",%s,{{"seq":%d}}]`, sub, js, seq)
		return fmt.tprintf(`["EVENT","%s",%s]`, sub, js)
	}

	Cursor_Test_Env :: struct {
		path:        string,
		old_dynamic: map[string]bool,
	}

	// A fresh store on a temporary log; kind-5 commits refresh g_dynamic.
	cursor_test_open :: proc(t: ^testing.T, pattern: string) -> (env: Cursor_Test_Env, ok: bool) {
		env.old_dynamic = g_dynamic
		g_dynamic = nil
		env.path, ok = store_test_temp_log(t, pattern)
		if !ok do return
		store_test_boot(env.path)
		return env, true
	}

	cursor_test_close :: proc(env: ^Cursor_Test_Env) {
		store_test_shutdown()
		store_test_cleanup()
		os.remove(env.path)
		delete(env.path)
		for k in g_dynamic do delete(k)
		delete(g_dynamic)
		g_dynamic = env.old_dynamic
	}

	@(test)
	cursor_seq_per_stream :: proc(t: ^testing.T) {
		sync.lock(&store_test_mu)
		defer sync.unlock(&store_test_mu)
		env, ok := cursor_test_open(t, "relay-seq-stream-*")
		if !ok do return
		defer cursor_test_close(&env)

		n := 0
		next :: proc(n: ^int) -> int { n^ += 1; return n^ }
		// Space streams count every author; personal streams one author's
		// events without an s tag.
		for want in 1..=3 {
			ev := cursor_test_event(next(&n), CURSOR_ALICE, 1078, "space-1")
			testing.expect_value(t, cursor_test_store(t, &ev), i64(want))
		}
		alice1 := cursor_test_event(next(&n), CURSOR_ALICE, 1, "")
		testing.expect_value(t, cursor_test_store(t, &alice1), i64(1))
		bob1 := cursor_test_event(next(&n), CURSOR_BOB, 1, "")
		testing.expect_value(t, cursor_test_store(t, &bob1), i64(1))
		bob_space := cursor_test_event(next(&n), CURSOR_BOB, 1078, "space-1")
		testing.expect_value(t, cursor_test_store(t, &bob_space), i64(4))
		other := cursor_test_event(next(&n), CURSOR_BOB, 1078, "space-2")
		testing.expect_value(t, cursor_test_store(t, &other), i64(1))
		// The first s tag names the stream.
		both := cursor_test_event(next(&n), CURSOR_ALICE, 1078, "space-2", extra = []string{"s", "space-1"})
		testing.expect_value(t, cursor_test_store(t, &both), i64(2))
		testing.expect(t, g_events[both.id].stream.key == "s:space-2")

		// Replaceable versions take fresh seqs; an older version is not
		// stored and consumes nothing, nor does a duplicate.
		profile := cursor_test_event(next(&n), CURSOR_ALICE, 10002, "", 20)
		testing.expect_value(t, cursor_test_store(t, &profile), i64(2))
		newer := cursor_test_event(next(&n), CURSOR_ALICE, 10002, "", 30)
		testing.expect_value(t, cursor_test_store(t, &newer), i64(3))
		testing.expect(t, !(profile.id in g_events))
		stale := cursor_test_event(next(&n), CURSOR_ALICE, 10002, "", 25)
		seq: i64 = -1
		stored, message := store_event(&stale, &seq)
		testing.expect(t, stored && strings.contains(message, "newer version") && seq == -1)
		stored, message = store_event(&newer, &seq)
		testing.expect(t, stored && strings.contains(message, "already have") && seq == -1)
		doc := cursor_test_event(next(&n), CURSOR_ALICE, 30078, "space-1", extra = []string{"d", "doc"})
		testing.expect_value(t, cursor_test_store(t, &doc), i64(5))
		alice2 := cursor_test_event(next(&n), CURSOR_ALICE, 1, "")
		testing.expect_value(t, cursor_test_store(t, &alice2), i64(4))

		testing.expect_value(t, cursor_test_cursor("s:space-1"), Stream_Cursor{5, 1})
		testing.expect_value(t, cursor_test_cursor("s:space-2"), Stream_Cursor{2, 1})
		testing.expect_value(t, cursor_test_cursor("p:" + CURSOR_ALICE), Stream_Cursor{4, 1})
		testing.expect_value(t, cursor_test_cursor("p:" + CURSOR_BOB), Stream_Cursor{1, 1})
		testing.expect_value(t, cursor_test_cursor("p:nobody"), Stream_Cursor{0, 1})

		// Stranger-door events stay unsequenced and open no stream.
		old_allowed := g_allowed
		g_allowed = make(map[string]bool)
		defer { delete(g_allowed); g_allowed = old_allowed }
		g_allowed[CURSOR_ALICE] = true
		stranger := cursor_test_event(next(&n), CURSOR_STRANGER, 0, "space-1")
		testing.expect_value(t, cursor_test_store(t, &stranger), i64(0))
		testing.expect(t, g_events[stranger.id].stream == nil && !("p:" + CURSOR_STRANGER in g_streams))
		testing.expect_value(t, cursor_test_cursor("s:space-1"), Stream_Cursor{5, 1})
		resident := cursor_test_event(next(&n), CURSOR_ALICE, 1078, "space-1")
		testing.expect_value(t, cursor_test_store(t, &resident), i64(6))
	}

	Cursor_Test_Writer :: struct {
		base:     int,
		author:   string,
		writes:   int,
		failures: int,
	}

	cursor_test_writer :: proc(w: ^Cursor_Test_Writer) {
		arena: mem.Dynamic_Arena
		mem.dynamic_arena_init(&arena)
		defer mem.dynamic_arena_destroy(&arena)
		context.temp_allocator = mem.dynamic_arena_allocator(&arena)
		for i in 0..<w.writes {
			// Alternate the shared space stream and this writer's personal one.
			ev := cursor_test_event(w.base + i, w.author, 1078, i%2 == 0 ? "busy" : "")
			seq: i64
			ok, message := store_event(&ev, &seq)
			if !ok || message != "" || seq <= 0 do w.failures += 1
			free_all(context.temp_allocator)
		}
	}

	cursor_test_expect_dense :: proc(t: ^testing.T, key: string, count: int, loc := #caller_location) {
		st := g_streams[key]
		if !testing.expect(t, st != nil, key, loc = loc) do return
		testing.expect_value(t, st.head, i64(count), loc = loc)
		testing.expect_value(t, len(st.slots), count, loc = loc)
		dense := true
		for slot, i in st.slots do dense = dense && slot.seq == i64(i + 1) && slot.s != nil && slot.s.seq == slot.seq
		testing.expect(t, dense, key, loc = loc)
	}

	@(test)
	cursor_gap_free_under_concurrent_writes :: proc(t: ^testing.T) {
		// Writer threads allocate with the heap allocator; share it so frees match.
		context.allocator = runtime.heap_allocator()
		sync.lock(&store_test_mu)
		defer sync.unlock(&store_test_mu)
		env, ok := cursor_test_open(t, "relay-seq-busy-*")
		if !ok do return
		defer cursor_test_close(&env)

		WRITERS :: 6
		WRITES :: 300
		authors := [WRITERS]string{}
		writers: [WRITERS]Cursor_Test_Writer
		threads: [WRITERS]^thread.Thread
		for i in 0..<WRITERS {
			authors[i] = strings.repeat(fmt.tprintf("%x", i + 1), 64, context.temp_allocator)
			writers[i] = {base = (i + 1) * 100_000, author = authors[i], writes = WRITES}
			threads[i] = thread.create_and_start_with_poly_data(&writers[i], cursor_test_writer)
		}
		for th in threads {
			thread.join(th)
			thread.destroy(th)
		}
		for w in writers do testing.expect_value(t, w.failures, 0)
		cursor_test_expect_dense(t, "s:busy", WRITERS * WRITES / 2)
		for a in authors do cursor_test_expect_dense(t, strings.concatenate({"p:", a}, context.temp_allocator), WRITES / 2)

		// The same dense streams after replay.
		want := store_test_snapshot()
		store_test_shutdown()
		store_test_boot(env.path)
		store_test_expect_snapshot(t, want)
		cursor_test_expect_dense(t, "s:busy", WRITERS * WRITES / 2)
	}

	@(test)
	cursor_persists_across_restart_and_compaction :: proc(t: ^testing.T) {
		sync.lock(&store_test_mu)
		defer sync.unlock(&store_test_mu)
		old_dynamic := g_dynamic
		g_dynamic = nil
		defer {
			for k in g_dynamic do delete(k)
			delete(g_dynamic)
			g_dynamic = old_dynamic
		}
		defer store_test_cleanup()
		path, ok := store_test_temp_log(t, "relay-seq-persist-*")
		if !ok do return
		defer delete(path)
		defer os.remove(path)

		// A pre-cursor store: legacy A and E records, unsequenced forever.
		legacy_space := cursor_test_event(1, CURSOR_ALICE, 1078, "space-1")
		legacy_personal := cursor_test_event(2, CURSOR_ALICE, 1, "")
		{
			log := make([dynamic]u8, context.temp_allocator)
			append(&log, ..store_test_frame('A', event_json(&legacy_space)))
			append(&log, ..store_test_frame('E', event_json(&legacy_personal)))
			fd, err := os.open(path, {.Write, .Trunc})
			if !testing.expect(t, err == nil) do return
			testing.expect(t, write_full(fd, log[:]) && os.sync(fd) == nil)
			os.close(fd)
		}
		store_test_boot(path)
		defer store_test_shutdown()
		testing.expect(t, len(g_order) == 2 && len(g_streams) == 0)
		testing.expect(t, g_events[legacy_space.id].seq == 0 && g_events[legacy_personal.id].seq == 0)

		// New events start each stream at 1; `after` never returns legacy ones.
		ids: [4]string
		for i in 0..<4 {
			ev := cursor_test_event(10 + i, CURSOR_ALICE, 1078, "space-1")
			testing.expect_value(t, cursor_test_store(t, &ev), i64(i + 1))
			ids[i] = strings.clone(ev.id, context.temp_allocator)
		}
		f := cursor_test_filter(t, `{"#s":["space-1"],"after":0}`)
		rows, _ := query_filter(&f)
		testing.expect_value(t, len(rows), 4)
		plain := cursor_test_filter(t, `{"#s":["space-1"]}`)
		rows, _ = query_filter(&plain)
		testing.expect_value(t, len(rows), 5)
		// Delete the head and the oldest: the head stays consumed.
		del := cursor_test_event(20, CURSOR_ALICE, 5, "", 50)
		del.tags = [][]string{{"e", ids[3]}, {"e", ids[0]}}
		del.tags_json = canon_tags(del.tags)
		testing.expect_value(t, cursor_test_store(t, &del), i64(1))
		testing.expect_value(t, cursor_test_cursor("s:space-1"), Stream_Cursor{4, 2})

		// Restart: the S records replay seqs, heads and oldest.
		want := store_test_snapshot()
		store_test_shutdown()
		store_test_boot(path)
		store_test_expect_snapshot(t, want)
		testing.expect_value(t, cursor_test_cursor("s:space-1"), Stream_Cursor{4, 2})
		testing.expect(t, g_events[legacy_space.id].seq == 0)

		// Compaction drops the deleted events' records; H keeps the head.
		compact_online()
		testing.expect(t, !g_append_failed && g_tombs == 0)
		testing.expect_value(t, store_test_file_size(path), want.live_bytes)
		store_test_shutdown()
		store_test_boot(path)
		store_test_expect_snapshot(t, want)
		testing.expect_value(t, g_log_bytes, want.live_bytes)
		ev := cursor_test_event(30, CURSOR_BOB, 1078, "space-1")
		testing.expect_value(t, cursor_test_store(t, &ev), i64(5))
		personal := cursor_test_event(31, CURSOR_ALICE, 1, "")
		testing.expect_value(t, cursor_test_store(t, &personal), i64(2))

		// And again after the compacted log grows new S records.
		want = store_test_snapshot()
		store_test_shutdown()
		store_test_boot(path)
		store_test_expect_snapshot(t, want)
		rows, _ = query_filter(&f)
		testing.expect(t, slice.equal(cursor_test_seqs(rows), []i64{2, 3, 5}))
	}

	cursor_test_s_frame :: proc(mode: u8, seq: u64, wire: string) -> []u8 {
		payload := make([]u8, SEQ_PREFIX + len(wire), context.temp_allocator)
		payload[0] = mode
		u64le_put(payload[1:], seq)
		copy(payload[SEQ_PREFIX:], wire)
		return store_test_frame('S', string(payload))
	}

	cursor_test_h_frame :: proc(head: u64, key: string) -> []u8 {
		payload := make([]u8, HEAD_PREFIX + len(key), context.temp_allocator)
		u64le_put(payload, head)
		copy(payload[HEAD_PREFIX:], key)
		return store_test_frame('H', string(payload))
	}

	@(test)
	cursor_replay_rejects_inconsistent_seqs :: proc(t: ^testing.T) {
		sync.lock(&store_test_mu)
		defer sync.unlock(&store_test_mu)
		store_test_reset()
		defer store_test_cleanup()
		a := cursor_test_event(1, CURSOR_ALICE, 1078, "sp")
		b := cursor_test_event(2, CURSOR_ALICE, 1078, "sp")
		c := cursor_test_event(3, CURSOR_ALICE, 1078, "sp")
		wa, wb, wc := event_json(&a), event_json(&b), event_json(&c)
		Case :: struct { frames: [][]u8, status: Record_Status, live: int, head: i64 }
		cases := []Case{
			{{cursor_test_s_frame('A', 1, wa), cursor_test_s_frame('A', 2, wb)}, .Complete, 2, 2},
			// An operation at or below the head was never written by a writer.
			{{cursor_test_s_frame('A', 2, wa), cursor_test_s_frame('A', 2, wb)}, .Corrupt, 1, 2},
			{{cursor_test_s_frame('A', 1, wa), cursor_test_s_frame('X', 2, wb)}, .Corrupt, 1, 1},
			{{cursor_test_s_frame('A', 0, wa)}, .Corrupt, 0, 0},
			// Compacted shape: heads first, then inserts at or below them.
			{{cursor_test_h_frame(9, "s:sp"), cursor_test_s_frame('E', 4, wb), cursor_test_s_frame('E', 2, wa), cursor_test_s_frame('A', 10, wc)}, .Complete, 3, 10},
			{{cursor_test_h_frame(9, "s:sp"), cursor_test_s_frame('E', 4, wa), cursor_test_s_frame('E', 4, wb)}, .Corrupt, 1, 9},
			{{cursor_test_h_frame(0, "s:sp")}, .Corrupt, 0, 0},
		}
		for tc, i in cases {
			store_test_reset()
			log := make([dynamic]u8, context.temp_allocator)
			for fr in tc.frames do append(&log, ..fr)
			_, status := replay(log[:])
			testing.expectf(t, status == tc.status, "case %d: %v", i, status)
			testing.expectf(t, len(g_order) == tc.live, "case %d: %d live", i, len(g_order))
			testing.expectf(t, cursor_test_cursor("s:sp").head == tc.head, "case %d: head %d", i, cursor_test_cursor("s:sp").head)
		}
		// Out-of-order compacted inserts still index in seq order.
		store_test_reset()
		log := make([dynamic]u8, context.temp_allocator)
		for fr in ([][]u8{cursor_test_h_frame(9, "s:sp"), cursor_test_s_frame('E', 7, wc), cursor_test_s_frame('E', 4, wb), cursor_test_s_frame('E', 2, wa)}) do append(&log, ..fr)
		_, status := replay(log[:])
		testing.expect_value(t, status, Record_Status.Complete)
		f := cursor_test_filter(t, `{"#s":["sp"],"after":2}`)
		rows, _ := query_filter(&f)
		testing.expect(t, slice.equal(cursor_test_seqs(rows), []i64{4, 7}))
		testing.expect_value(t, cursor_test_cursor("s:sp"), Stream_Cursor{9, 2})
	}

	@(test)
	cursor_after_pages_in_seq_order :: proc(t: ^testing.T) {
		sync.lock(&store_test_mu)
		defer sync.unlock(&store_test_mu)
		env, ok := cursor_test_open(t, "relay-seq-page-*")
		if !ok do return
		defer cursor_test_close(&env)
		// created_at falls as seq rises: pages follow seq, not time.
		for i in 1..=10 {
			ev := cursor_test_event(i, i%3 == 0 ? CURSOR_BOB : CURSOR_ALICE, i%2 == 1 ? 1078 : 1080, "pg", i64(100 - i))
			testing.expect_value(t, cursor_test_store(t, &ev), i64(i))
		}
		for i in 1..=3 {
			ev := cursor_test_event(100 + i, CURSOR_ALICE, 1, "", i64(i))
			testing.expect_value(t, cursor_test_store(t, &ev), i64(i))
		}
		Case :: struct { filter: string, want: []i64 }
		cases := []Case{
			{`{"#s":["pg"],"after":3,"limit":4}`, {4, 5, 6, 7}},
			{`{"#s":["pg"],"after":7,"limit":4}`, {8, 9, 10}},
			{`{"#s":["pg"],"after":10,"limit":4}`, {}},
			{`{"#s":["pg"],"after":9223372036854775807}`, {}},
			{`{"#s":["pg"],"after":0,"limit":0}`, {}},
			{`{"#s":["pg"],"after":0}`, {1, 2, 3, 4, 5, 6, 7, 8, 9, 10}},
			{`{"#s":["pg"],"kinds":[1080],"after":3,"limit":2}`, {4, 6}},
			{`{"#s":["pg"],"kinds":[1078],"after":0}`, {1, 3, 5, 7, 9}},
			{`{"#s":["pg"],"authors":["` + CURSOR_BOB + `"],"after":0}`, {3, 6, 9}},
			{`{"#s":["pg"],"since":95,"after":2}`, {3, 4, 5}},
			// The personal stream excludes the author's space events.
			{`{"authors":["` + CURSOR_ALICE + `"],"after":1}`, {2, 3}},
			{`{"#s":["none"],"after":0}`, {}},
		}
		for tc in cases {
			f := cursor_test_filter(t, tc.filter)
			cursor: Stream_Cursor
			rows, exhausted := query_filter(&f, MAX_QUERY_BYTES, &cursor)
			got := cursor_test_seqs(rows)
			testing.expectf(t, slice.equal(got, tc.want) && !exhausted, "%s: %v", tc.filter, got)
		}
		cursor: Stream_Cursor
		f := cursor_test_filter(t, `{"#s":["pg"],"after":0,"limit":0}`)
		_, _ = query_filter(&f, MAX_QUERY_BYTES, &cursor)
		testing.expect_value(t, cursor, Stream_Cursor{10, 1})
		// A byte budget cuts the page to an ascending prefix.
		row_cost := len(g_streams["s:pg"].slots[0].s.json) + QUERY_ROW_OVERHEAD
		f = cursor_test_filter(t, `{"#s":["pg"],"after":0}`)
		rows, exhausted := query_filter(&f, 2*row_cost + 1)
		testing.expect(t, exhausted && slice.equal(cursor_test_seqs(rows), []i64{1, 2}))
		// NIP-77 honours after as well.
		f = cursor_test_filter(t, `{"#s":["pg"],"after":8}`)
		items, iok := neg_collect(&f, 100)
		testing.expect(t, iok && len(items) == 2)
		delete(items)
	}

	@(test)
	cursor_after_needs_one_stream :: proc(t: ^testing.T) {
		sync.lock(&store_test_mu)
		defer sync.unlock(&store_test_mu)
		store_test_reset()
		defer store_test_cleanup()
		c := Conn{allocator = context.allocator, subs = make(map[string]Sub)}
		defer cursor_test_conn_free(&c)
		defer neg_close_all(&c)
		for filters in ([]string{
			`{"after":0}`,
			`{"after":0,"kinds":[1]}`,
			`{"after":0,"#s":["a","b"]}`,
			`{"after":0,"#s":[],"authors":["` + CURSOR_ALICE + `"]}`,
			`{"after":0,"authors":["` + CURSOR_ALICE + `","` + CURSOR_BOB + `"]}`,
			`{"#s":["a"],"after":0},{"after":5}`,
		}) {
			handle_message(&c, fmt.tprintf(`["REQ","x",%s]`, filters))
			testing.expect_value(t, cursor_test_reply(&c), `["CLOSED","x","invalid: after needs one stream"]`)
			testing.expect_value(t, len(c.subs), 0)
		}
		for bad in ([]string{`{"#s":["a"],"after":-1}`, `{"#s":["a"],"after":"1"}`}) {
			handle_message(&c, fmt.tprintf(`["REQ","x",%s]`, bad))
			testing.expect_value(t, cursor_test_reply(&c), `["CLOSED","x","invalid: bad filter"]`)
		}
		handle_message(&c, `["NEG-OPEN","n",{"after":0},"6100000200"]`)
		testing.expect_value(t, cursor_test_reply(&c), `["NEG-ERR","n","invalid: after needs one stream"]`)
		testing.expect_value(t, c.out_count, 0)
	}

	@(test)
	cursor_eose_and_history_seq :: proc(t: ^testing.T) {
		sync.lock(&store_test_mu)
		defer sync.unlock(&store_test_mu)
		env, ok := cursor_test_open(t, "relay-seq-eose-*")
		if !ok do return
		defer cursor_test_close(&env)
		ids: [5]string
		for i in 0..<5 {
			ev := cursor_test_event(i + 1, CURSOR_ALICE, 1078, "eo", i64(10 + i))
			cursor_test_store(t, &ev)
			ids[i] = strings.clone(ev.id, context.temp_allocator)
		}
		personal: [2]string
		for i in 0..<2 {
			ev := cursor_test_event(10 + i, CURSOR_ALICE, 1, "")
			cursor_test_store(t, &ev)
			personal[i] = strings.clone(ev.id, context.temp_allocator)
		}
		c := Conn{allocator = context.allocator, subs = make(map[string]Sub)}
		defer cursor_test_conn_free(&c)

		handle_message(&c, `["REQ","h",{"#s":["eo"],"after":2,"limit":2}]`)
		got := cursor_test_drain(&c)
		want := []string{cursor_test_event_msg("h", ids[2], 3), cursor_test_event_msg("h", ids[3], 4), `["EOSE","h",{"head":5,"oldest":1}]`}
		testing.expectf(t, slice.equal(got, want), "%v", got)
		testing.expect(t, c.subs["h"].sequenced)

		// Several streams: one cursor per stream, keyed by #s value or author.
		handle_message(&c, `["REQ","m",{"#s":["eo"],"after":4},{"authors":["` + CURSOR_ALICE + `"],"after":0,"limit":1}]`)
		got = cursor_test_drain(&c)
		want = []string{
			cursor_test_event_msg("m", ids[4], 5),
			cursor_test_event_msg("m", personal[0], 1),
			`["EOSE","m",{"eo":{"head":5,"oldest":1},"` + CURSOR_ALICE + `":{"head":2,"oldest":1}}]`,
		}
		testing.expectf(t, slice.equal(got, want), "%v", got)
		// One stream named by two filters is still one stream.
		handle_message(&c, `["REQ","k",{"#s":["eo"],"kinds":[1],"after":0},{"#s":["eo"],"after":4}]`)
		got = cursor_test_drain(&c)
		want = []string{cursor_test_event_msg("k", ids[4], 5), `["EOSE","k",{"head":5,"oldest":1}]`}
		testing.expectf(t, slice.equal(got, want), "%v", got)
		// limit 0 probes the cursor; an unknown stream is empty.
		handle_message(&c, `["REQ","p",{"#s":["eo"],"after":0,"limit":0}]`)
		testing.expectf(t, slice.equal(cursor_test_drain(&c), []string{`["EOSE","p",{"head":5,"oldest":1}]`}), "probe")
		handle_message(&c, `["REQ","u",{"#s":["unknown"],"after":0}]`)
		testing.expectf(t, slice.equal(cursor_test_drain(&c), []string{`["EOSE","u",{"head":0,"oldest":1}]`}), "unknown")
		// A mixed subscription sees seqs on all its sequenced events.
		handle_message(&c, fmt.tprintf(`["REQ","x",{{"ids":["%s"]}},{{"#s":["eo"],"after":4}}]`, ids[0]))
		got = cursor_test_drain(&c)
		want = []string{cursor_test_event_msg("x", ids[0], 1), cursor_test_event_msg("x", ids[4], 5), `["EOSE","x",{"head":5,"oldest":1}]`}
		testing.expectf(t, slice.equal(got, want), "%v", got)

		// Subscriptions without `after` are exactly NIP-01, newest first.
		handle_message(&c, `["REQ","plain",{"#s":["eo"]}]`)
		got = cursor_test_drain(&c)
		newest_first := make([dynamic]string, context.temp_allocator)
		for i := 4; i >= 0; i -= 1 do append(&newest_first, cursor_test_event_msg("plain", ids[i]))
		append(&newest_first, `["EOSE","plain"]`)
		testing.expectf(t, slice.equal(got, newest_first[:]), "%v", got)
		testing.expect(t, !c.subs["plain"].sequenced)
	}

	@(test)
	cursor_live_events_carry_seq :: proc(t: ^testing.T) {
		sync.lock(&store_test_mu)
		defer sync.unlock(&store_test_mu)
		env, ok := cursor_test_open(t, "relay-seq-live-*")
		if !ok do return
		defer cursor_test_close(&env)
		c := Conn{allocator = context.allocator, subs = make(map[string]Sub)}
		defer cursor_test_conn_free(&c)
		sync.lock(&g_conns_mu)
		owns_registry := cap(g_conns) == 0 // the registry is allocated by this test
		append(&g_conns, &c)
		sync.unlock(&g_conns_mu)
		defer {
			sync.lock(&g_conns_mu)
			for conn, i in g_conns do if conn == &c { unordered_remove(&g_conns, i); break }
			if owns_registry && len(g_conns) == 0 { delete(g_conns); g_conns = nil }
			sync.unlock(&g_conns_mu)
		}
		for req in ([]string{
			`["REQ","live",{"#s":["lv"],"after":0}]`,
			`["REQ","plain",{"#s":["lv"]}]`,
			`["REQ","other",{"#s":["zz"],"after":0}]`,
			`["REQ","mine",{"authors":["` + CURSOR_ALICE + `"],"after":0}]`,
			`["REQ","ahead",{"#s":["lv"],"after":1}]`,
		}) {
			handle_message(&c, req)
		}
		testing.expect_value(t, len(cursor_test_drain(&c)), 5)

		publish :: proc(t: ^testing.T, ev: ^Event) -> (seq: i64) {
			seq = cursor_test_store(t, ev)
			broadcast(ev, seq)
			return
		}
		sorted :: proc(got: []string) -> []string {
			slice.sort(got)
			return got
		}
		space := cursor_test_event(1, CURSOR_ALICE, 1078, "lv")
		testing.expect_value(t, publish(t, &space), i64(1))
		got := sorted(cursor_test_drain(&c))
		want := sorted([]string{cursor_test_event_msg("live", space.id, 1), cursor_test_event_msg("plain", space.id)})
		testing.expectf(t, slice.equal(got, want), "%v", got)

		space2 := cursor_test_event(2, CURSOR_BOB, 1078, "lv")
		testing.expect_value(t, publish(t, &space2), i64(2))
		got = sorted(cursor_test_drain(&c))
		want = sorted([]string{cursor_test_event_msg("live", space2.id, 2), cursor_test_event_msg("plain", space2.id), cursor_test_event_msg("ahead", space2.id, 2)})
		testing.expectf(t, slice.equal(got, want), "%v", got)

		mine := cursor_test_event(3, CURSOR_ALICE, 1, "")
		testing.expect_value(t, publish(t, &mine), i64(1))
		got = cursor_test_drain(&c)
		testing.expectf(t, slice.equal(got, []string{cursor_test_event_msg("mine", mine.id, 1)}), "%v", got)

		// Ephemeral events are in no stream: only the plain subscription.
		eph := cursor_test_event(4, CURSOR_ALICE, 20001, "lv")
		eph_js := event_json(&eph)
		broadcast(&eph, 0)
		got = cursor_test_drain(&c)
		testing.expectf(t, slice.equal(got, []string{fmt.tprintf(`["EVENT","plain",%s]`, eph_js)}), "%v", got)
	}

	@(test)
	cursor_deletion_keeps_seq_and_advances_oldest :: proc(t: ^testing.T) {
		sync.lock(&store_test_mu)
		defer sync.unlock(&store_test_mu)
		env, ok := cursor_test_open(t, "relay-seq-delete-*")
		if !ok do return
		defer cursor_test_close(&env)
		ids: [3]string
		for i in 0..<3 {
			ev := cursor_test_event(i + 1, CURSOR_ALICE, 1078, "dl")
			cursor_test_store(t, &ev)
			ids[i] = strings.clone(ev.id, context.temp_allocator)
		}
		testing.expect_value(t, cursor_test_cursor("s:dl"), Stream_Cursor{3, 1})
		// A deletion inside the space takes the next seq itself.
		del1 := cursor_test_event(10, CURSOR_ALICE, 5, "dl", 20, []string{"e", ids[0]})
		testing.expect_value(t, cursor_test_store(t, &del1), i64(4))
		testing.expect_value(t, cursor_test_cursor("s:dl"), Stream_Cursor{4, 2})
		del2 := cursor_test_event(11, CURSOR_ALICE, 5, "", 20, []string{"e", ids[1]})
		testing.expect_value(t, cursor_test_store(t, &del2), i64(1))
		testing.expect_value(t, cursor_test_cursor("s:dl"), Stream_Cursor{4, 3})
		f := cursor_test_filter(t, `{"#s":["dl"],"after":0}`)
		rows, _ := query_filter(&f)
		testing.expect(t, slice.equal(cursor_test_seqs(rows), []i64{3, 4}))
		// Supersession leaves a hole; the head never moves back.
		v1 := cursor_test_event(12, CURSOR_ALICE, 30078, "dl", 30, []string{"d", "doc"})
		testing.expect_value(t, cursor_test_store(t, &v1), i64(5))
		v2 := cursor_test_event(13, CURSOR_ALICE, 30078, "dl", 40, []string{"d", "doc"})
		testing.expect_value(t, cursor_test_store(t, &v2), i64(6))
		del3 := cursor_test_event(14, CURSOR_ALICE, 5, "", 50, []string{"e", v2.id})
		testing.expect_value(t, cursor_test_store(t, &del3), i64(2))
		testing.expect_value(t, cursor_test_cursor("s:dl"), Stream_Cursor{6, 3})
		late := cursor_test_event(15, CURSOR_ALICE, 1078, "dl")
		testing.expect_value(t, cursor_test_store(t, &late), i64(7))
		rows, _ = query_filter(&f)
		testing.expect(t, slice.equal(cursor_test_seqs(rows), []i64{3, 4, 7}))

		// A stream that keeps nothing reports oldest = head + 1.
		gone: [2]string
		for i in 0..<2 {
			ev := cursor_test_event(20 + i, CURSOR_BOB, 1078, "gone")
			cursor_test_store(t, &ev)
			gone[i] = strings.clone(ev.id, context.temp_allocator)
		}
		wipe := cursor_test_event(22, CURSOR_BOB, 5, "", 50)
		wipe.tags = [][]string{{"e", gone[0]}, {"e", gone[1]}}
		wipe.tags_json = canon_tags(wipe.tags)
		cursor_test_store(t, &wipe)
		testing.expect_value(t, cursor_test_cursor("s:gone"), Stream_Cursor{2, 3})

		// Retention-style pruning of a long stream's oldest seqs (slots rebuild).
		COUNT :: 300
		big: [COUNT]string
		for i in 0..<COUNT {
			ev := cursor_test_event(1000 + i, CURSOR_ALICE, 1078, "big")
			cursor_test_store(t, &ev)
			big[i] = strings.clone(ev.id, context.temp_allocator)
		}
		pruned := 0
		for pruned < 250 {
			tags := make([][]string, 50, context.temp_allocator)
			for j in 0..<50 do tags[j] = cursor_test_tag("e", big[pruned + j])
			prune := cursor_test_event(5000 + pruned, CURSOR_ALICE, 5, "", 60)
			prune.tags = tags
			prune.tags_json = canon_tags(tags)
			cursor_test_store(t, &prune)
			pruned += 50
			testing.expect_value(t, cursor_test_cursor("s:big"), Stream_Cursor{COUNT, i64(pruned + 1)})
		}
		testing.expect(t, len(g_streams["s:big"].slots) < COUNT)
		f = cursor_test_filter(t, `{"#s":["big"],"after":0,"limit":3}`)
		rows, _ = query_filter(&f)
		testing.expect(t, slice.equal(cursor_test_seqs(rows), []i64{251, 252, 253}))
		f = cursor_test_filter(t, `{"#s":["big"],"after":298}`)
		rows, _ = query_filter(&f)
		testing.expect(t, slice.equal(cursor_test_seqs(rows), []i64{299, 300}))

		// All of it survives restart, compaction included.
		want := store_test_snapshot()
		store_test_shutdown()
		store_test_boot(env.path)
		store_test_expect_snapshot(t, want)
		compact_online()
		store_test_shutdown()
		store_test_boot(env.path)
		store_test_expect_snapshot(t, want)
		testing.expect_value(t, cursor_test_cursor("s:gone"), Stream_Cursor{2, 3})
		testing.expect_value(t, cursor_test_cursor("s:dl"), Stream_Cursor{7, 3})
		again := cursor_test_event(30, CURSOR_BOB, 1078, "gone")
		testing.expect_value(t, cursor_test_store(t, &again), i64(3))
	}
}
