package relay

import "core:fmt"
import "core:mem"
import "core:os"
import "core:strings"
import "core:sync"
import "core:testing"
import "core:thread"

when ODIN_TEST {
	Store_Test_Snapshot :: struct {
		events:     map[string]string, // id -> wire JSON
		deleted:    map[string]bool,
		deletions:  int,
		live_bytes: int, // exactly what compaction writes
	}

	store_test_snapshot :: proc() -> (snap: Store_Test_Snapshot) {
		snap.events = make(map[string]string, context.temp_allocator)
		snap.deleted = make(map[string]bool, context.temp_allocator)
		for s in g_order {
			snap.events[strings.clone(s.id, context.temp_allocator)] = strings.clone(s.json, context.temp_allocator)
			snap.live_bytes += len(s.json) + RECORD_OVERHEAD
		}
		for id in g_deleted {
			snap.deleted[strings.clone(id, context.temp_allocator)] = true
			snap.live_bytes += len(id) + RECORD_OVERHEAD
		}
		snap.deletions = len(g_deletions)
		return
	}

	store_test_expect_snapshot :: proc(t: ^testing.T, want: Store_Test_Snapshot) {
		got := store_test_snapshot()
		testing.expect_value(t, len(got.events), len(want.events))
		testing.expect_value(t, len(got.deleted), len(want.deleted))
		testing.expect_value(t, got.deletions, want.deletions)
		testing.expect_value(t, got.live_bytes, want.live_bytes)
		// The incremental accounting agrees with a full recount.
		testing.expect_value(t, g_live_bytes, got.live_bytes)
		missing := 0
		for id, json in want.events {
			if have, ok := got.events[id]; !ok || have != json do missing += 1
		}
		for id in want.deleted do if !(id in got.deleted) do missing += 1
		testing.expect_value(t, missing, 0)
	}

	store_test_temp_log :: proc(t: ^testing.T, pattern: string) -> (path: string, ok: bool) {
		fd, err := os.create_temp_file("", pattern)
		if !testing.expect(t, err == nil) do return "", false
		path = strings.clone(os.name(fd))
		os.close(fd)
		return path, true
	}

	store_test_file_size :: proc(path: string) -> int {
		fd, err := os.open(path)
		if err != nil do return -1
		defer os.close(fd)
		size, size_err := os.file_size(fd)
		return size_err == nil ? int(size) : -1
	}

	// A fresh process booting the log at path.
	store_test_boot :: proc(path: string) {
		store_test_cleanup()
		store_open(path)
	}

	// Process exit: drops the append fd and the path store_open cloned.
	store_test_shutdown :: proc() {
		if g_fd != nil { os.close(g_fd); g_fd = nil }
		delete(g_log_path)
		g_log_path = ""
	}

	@(test)
	store_boot_replays_bloated_log_to_same_state :: proc(t: ^testing.T) {
		sync.lock(&store_test_mu)
		defer sync.unlock(&store_test_mu)
		defer store_test_cleanup()
		old_dynamic := g_dynamic
		g_dynamic = nil
		defer {
			for k in g_dynamic do delete(k)
			delete(g_dynamic)
			g_dynamic = old_dynamic
		}
		path, ok := store_test_temp_log(t, "relay-bloated-*")
		if !ok do return
		defer delete(path)
		defer os.remove(path)
		store_test_boot(path)
		defer store_test_shutdown()

		author := strings.repeat("a", 64, context.temp_allocator)
		pad := strings.repeat("x", MAX_RECORD - 2048, context.temp_allocator)
		// Superseded versions far outnumber live events and span several
		// REPLAY_BUFFER windows; a few near-MAX_RECORD versions straddle
		// window edges.
		n := 0
		for i in 0..<COMPACT_MIN_TOMBS + 100 {
			n += 1
			ev := store_test_tagged(n, author, 30078, [][]string{{"d", fmt.tprintf("doc-%d", i%3)}}, i64(i+1))
			ev.content = i%250 == 0 ? pad : pad[:1000 + (i*37)%5000]
			stored, message := store_event(&ev)
			if !testing.expectf(t, stored, "version %d: %s", i, message) do return
		}
		first_note := n + 1
		for _ in 0..<300 {
			n += 1
			ev := store_test_tagged(n, author, 1, [][]string{{"t", "note"}}, 100)
			stored, _ := store_event(&ev)
			if !testing.expect(t, stored) do return
		}
		tags := make([][]string, 100, context.temp_allocator)
		for i in 0..<100 {
			tag := make([]string, 2, context.temp_allocator)
			tag[0] = "e"
			tag[1] = fmt.tprintf("%064x", first_note + 3*i)
			tags[i] = tag
		}
		n += 1
		del := store_test_tagged(n, author, 5, tags, 200)
		stored, _ := store_event(&del)
		testing.expect(t, stored && len(g_order) == 3 + 200 + 1)

		want := store_test_snapshot()
		logged := g_log_bytes
		testing.expect_value(t, store_test_file_size(path), logged)
		testing.expect(t, logged > 2*want.live_bytes && logged > 2*REPLAY_BUFFER)

		store_test_shutdown()
		store_test_boot(path)
		store_test_expect_snapshot(t, want)
		// Boot compaction ran (tombstones >= COMPACT_MIN_TOMBS): the log
		// now holds exactly the live state.
		size := store_test_file_size(path)
		testing.expect_value(t, size, want.live_bytes)
		testing.expect_value(t, g_log_bytes, size)
		testing.expect(t, size < logged && g_tombs == 0)

		// A torn large record heals by streamed truncation to the same state.
		n += 1
		torn := store_test_event(n, 1, 300)
		torn.content = pad
		frame := store_test_frame('A', event_json(&torn))
		fd, err := os.open(path, {.Write, .Append})
		if !testing.expect(t, err == nil) do return
		testing.expect(t, write_full(fd, frame[:len(frame)/2]) && os.sync(fd) == nil)
		os.close(fd)
		store_test_shutdown()
		store_test_boot(path)
		store_test_expect_snapshot(t, want)
		testing.expect_value(t, store_test_file_size(path), want.live_bytes)
		testing.expect(t, !(torn.id in g_events))
	}

	store_test_compare_stream :: proc(t: ^testing.T, path: string, data: []u8, loc := #caller_location) {
		fd, err := os.open(path, {.Write, .Create, .Trunc}, os.Permissions_Default_File)
		if !testing.expect(t, err == nil, loc = loc) do return
		testing.expect(t, write_full(fd, data), loc = loc)
		os.close(fd)
		store_test_reset()
		want_good, want_status := replay(data)
		want_live, want_deleted := len(g_order), len(g_deleted)
		store_test_reset()
		fd, err = os.open(path)
		if !testing.expect(t, err == nil, loc = loc) do return
		good, torn, status, read_err := replay_file(fd)
		os.close(fd)
		testing.expect(t, read_err == nil, loc = loc)
		testing.expect_value(t, good, want_good, loc = loc)
		testing.expect_value(t, status, want_status, loc = loc)
		testing.expect_value(t, len(g_order), want_live, loc = loc)
		testing.expect_value(t, len(g_deleted), want_deleted, loc = loc)
		if status == .Incomplete do testing.expect_value(t, torn, len(data) - good, loc = loc)
	}

	@(test)
	store_streamed_replay_matches_whole_file :: proc(t: ^testing.T) {
		sync.lock(&store_test_mu)
		defer sync.unlock(&store_test_mu)
		defer store_test_cleanup()
		path, ok := store_test_temp_log(t, "relay-stream-*")
		if !ok do return
		defer delete(path)
		defer os.remove(path)
		pad := strings.repeat("x", MAX_RECORD - 2048, context.temp_allocator)
		log := make([dynamic]u8, context.temp_allocator)
		big_at := -1
		n := 0
		for len(log) < 2*REPLAY_BUFFER + MAX_RECORD {
			n += 1
			ev := store_test_event(n, 30078, i64(n))
			ev.tags = [][]string{{"d", fmt.tprintf("doc-%d", n%5)}}
			ev.tags_json = canon_tags(ev.tags)
			ev.content = pad[:4000 + (n*7919)%60000]
			type: u8 = 'A'
			// A near-MAX_RECORD legacy record straddles the first window edge.
			if big_at < 0 && len(log) > REPLAY_BUFFER - (1 << 17) {
				ev.content = pad
				big_at = len(log)
				type = 'E'
			}
			append(&log, ..store_test_frame(type, event_json(&ev)))
		}
		testing.expect(t, big_at >= 0 && big_at < REPLAY_BUFFER)
		for cut in ([]int{len(log), 0, 3, big_at, big_at + 3, big_at + 1000, REPLAY_BUFFER, REPLAY_BUFFER + 1, len(log) - 1}) {
			store_test_compare_stream(t, path, log[:cut])
		}
		// Mid-log damage past the first window stays .Corrupt at its offset.
		damaged := make([]u8, len(log), context.temp_allocator)
		copy(damaged, log[:])
		damaged[big_at + 5000] ~= 1
		store_test_compare_stream(t, path, damaged)
		copy(damaged, log[:])
		damaged[len(damaged) - 3] ~= 1
		store_test_compare_stream(t, path, damaged)
	}

	Store_Test_Reader :: struct {
		stop:    bool,
		want:    int,
		queries: int,
		wrong:   int,
	}

	store_test_reader :: proc(r: ^Store_Test_Reader) {
		arena: mem.Dynamic_Arena
		mem.dynamic_arena_init(&arena)
		defer mem.dynamic_arena_destroy(&arena)
		context.temp_allocator = mem.dynamic_arena_allocator(&arena)
		f := Filter{kinds = []i64{1}, limit = MAX_LIMIT, has_limit = true}
		for !sync.atomic_load(&r.stop) {
			rows, _ := query_filter(&f)
			if len(rows) != r.want do sync.atomic_add(&r.wrong, 1)
			sync.atomic_add(&r.queries, 1)
			free_all(context.temp_allocator)
		}
	}

	@(test)
	store_online_compaction_reopens_and_replays :: proc(t: ^testing.T) {
		sync.lock(&store_test_mu)
		defer sync.unlock(&store_test_mu)
		defer store_test_cleanup()
		old_dynamic := g_dynamic
		g_dynamic = nil
		defer {
			for k in g_dynamic do delete(k)
			delete(g_dynamic)
			g_dynamic = old_dynamic
		}
		path, ok := store_test_temp_log(t, "relay-online-*")
		if !ok do return
		defer delete(path)
		defer os.remove(path)
		store_test_boot(path)
		defer store_test_shutdown()

		n := 0
		for _ in 0..<50 {
			n += 1
			ev := store_test_event(n, 1, 10)
			stored, _ := store_event(&ev)
			if !testing.expect(t, stored) do return
		}
		del := store_test_event(n + 1, 5, 20)
		del.tags = [][]string{{"e", fmt.tprintf("%064x", 1)}, {"e", fmt.tprintf("%064x", 2)}}
		del.tags_json = canon_tags(del.tags)
		n += 1
		stored, _ := store_event(&del)
		testing.expect(t, stored)

		// Queries share g_mu with the compacting commit: a reader running
		// throughout sees the same kind-1 set before, during and after.
		reader := Store_Test_Reader{want = 48}
		th := thread.create_and_start_with_poly_data(&reader, store_test_reader)
		if !testing.expect(t, th != nil) do return
		defer thread.destroy(th)
		joined := false
		defer if !joined {
			sync.atomic_store(&reader.stop, true)
			thread.join(th)
		}

		// One replaceable event rewritten until dead bytes dominate.
		pad := strings.repeat("x", MAX_RECORD - 2048, context.temp_allocator)
		writes := 0
		compacted_from := 0
		for i in 0..<2*COMPACT_MIN_DEAD_BYTES/MAX_RECORD {
			testing.expect(t, !compaction_due())
			n += 1
			ev := store_test_event(n, 10002, i64(100+i))
			ev.content = pad
			before := g_log_bytes
			stored, _ = store_event(&ev)
			if !testing.expect(t, stored) do return
			writes += 1
			if g_log_bytes < before {
				compacted_from = before + len(event_json(&ev)) + RECORD_OVERHEAD
				break
			}
		}
		testing.expect(t, compacted_from > 0 && !g_append_failed && g_tombs == 0)
		testing.expect(t, compacted_from - g_live_bytes >= COMPACT_MIN_DEAD_BYTES)
		testing.expect(t, writes >= COMPACT_MIN_DEAD_BYTES/MAX_RECORD)
		testing.expect_value(t, g_log_bytes, g_live_bytes)
		testing.expect_value(t, store_test_file_size(path), g_log_bytes)
		testing.expect(t, !os.exists(fmt.tprintf("%s.tmp", path)))

		// Appends continue on the replacement log.
		n += 1
		after := store_test_event(n, 7, 500)
		stored, _ = store_event(&after)
		testing.expect(t, stored && after.id in g_events)
		testing.expect_value(t, store_test_file_size(path), g_log_bytes)

		sync.atomic_store(&reader.stop, true)
		thread.join(th)
		joined = true
		testing.expect(t, sync.atomic_load(&reader.queries) > 0)
		testing.expect_value(t, sync.atomic_load(&reader.wrong), 0)

		want := store_test_snapshot()
		store_test_shutdown()
		store_test_boot(path)
		store_test_expect_snapshot(t, want)
		testing.expect(t, after.id in g_events && len(g_order) == 48 + 1 + 1 + 1)
	}
}
