package relay

import "core:fmt"
import "core:math/rand"
import "core:os"
import "core:slice"
import "core:strings"
import "core:sync"
import "core:testing"

when ODIN_TEST {
	// The planner before plan_operation was indexed: every retained deletion
	// and the whole store are scanned per event. The reference the indexed
	// planner must agree with, victim order included.
	store_test_plan_scan :: proc(ev: ^Event) -> (victims: [dynamic]^Stored, message: string, rejected: bool) {
		if ev.id in g_events do return nil, "duplicate: already have this event", false
		if ev.id in g_deleted do return nil, "blocked: event was deleted", true
		ev_d := d_tag(ev)
		ev_space_deletion := is_space_deletion(ev)
		if ev.kind != 5 && strings.concatenate({ev.pubkey, ev.id}, context.temp_allocator) in g_deletion_refs {
			return nil, "blocked: event was deleted", true
		}
		for deletion in g_order {
			if deletion.kind != 5 do continue
			if slice.any_of_proc(deletion.tags, proc(t: [2]string) -> bool { return t[0] == "h" }) {
				if space_deletion_covers(deletion.tags, deletion.pubkey, ev.tags, ev.pubkey, ev.kind) do return nil, "blocked: event was deleted", true
			}
			if deletion.pubkey != ev.pubkey || !is_addressable(ev.kind) do continue
			for tag in deletion.tags {
				if tag[0] == "a" && deletion_tag_matches(tag[0], tag[1], deletion.pubkey, deletion.created_at, ev.id, ev.pubkey, ev.kind, ev_d, ev.created_at) {
					return nil, "blocked: event was deleted", true
				}
			}
		}
		victims = make([dynamic]^Stored, context.temp_allocator)
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

	// The record store_event would append for ev: S (mode A) when sequenced.
	store_test_op_frame :: proc(ev: ^Event, seq: i64) -> []u8 {
		wire := event_json(ev)
		if seq == 0 do return store_test_frame('A', wire)
		payload := make([]u8, SEQ_PREFIX + len(wire), context.temp_allocator)
		payload[0] = 'A'
		u64le_put(payload[1:SEQ_PREFIX], u64(seq))
		copy(payload[SEQ_PREFIX:], wire)
		return store_test_frame('S', string(payload))
	}

	// Every live event sits where its index entries say, and nothing else
	// does.
	store_test_expect_indexes :: proc(t: ^testing.T, loc := #caller_location) -> bool {
		bad, refs, members := 0, 0, 0
		for s in g_order {
			for r in s.spaces {
				refs += 1
				if g_spaces[r.bucket.key] != r.bucket || r.pos >= len(r.bucket.members) || r.bucket.members[r.pos] != s do bad += 1
			}
			keyed := is_replaceable(s.kind) || is_addressable(s.kind)
			if keyed != (s.address != nil) || (keyed && (g_addresses[s.address.key] != s.address || !slice.contains(s.address.members[:], s))) do bad += 1
		}
		for _, b in g_spaces do members += len(b.members)
		return testing.expect_value(t, bad, 0, loc = loc) && testing.expect_value(t, members, refs, loc = loc)
	}

	store_test_fuzz_event :: proc(n: int, authors: []string, ids: []string) -> Event {
		SPACES :: [6]string{"s0", "s1", "s2", "s3", "s4", "s5:x"}
		DS :: [4]string{"x", "y", "a:b", ""}
		KINDS :: [11]i64{1078, 1078, 1079, 1, 31078, 30078, 0, 10002, 5, 5, 5}
		ADDRESS_KINDS :: [5]string{"31078", "30078", "031078", "10002", "bad"}
		KIND_FILTERS :: [4]string{"1078", "1079", "31078", "x"}
		spaces, ds, kinds, address_kinds, kind_filters := SPACES, DS, KINDS, ADDRESS_KINDS, KIND_FILTERS
		author := rand.choice(authors)
		kind := rand.choice(kinds[:])
		tags := make([dynamic][]string, context.temp_allocator)
		if kind == 5 {
			for _ in 0..<rand.int_range(1, 6) {
				switch rand.int_max(7) {
				case 0, 1, 2:
					// Mostly recent events, which are likelier to be live.
					target := len(ids) > 0 && rand.int_max(6) > 0 ? rand.choice(ids[max(0, len(ids)-40):]) : fmt.tprintf("%064x", 1 << 40 + rand.int_max(64))
					append(&tags, []string{"e", target})
				case 3, 4:
					who := rand.int_max(4) > 0 ? author : rand.choice(authors)
					append(&tags, []string{"a", fmt.tprintf("%s:%s:%s", rand.choice(address_kinds[:]), who, rand.choice(ds[:]))})
				case 5:
					append(&tags, []string{"h", rand.choice(spaces[:])})
				case 6:
					append(&tags, []string{"k", rand.choice(kind_filters[:])})
				}
			}
		} else {
			for _ in 0..<rand.int_max(4) do append(&tags, []string{"h", rand.choice(spaces[:])})
			if rand.int_max(3) == 0 do append(&tags, []string{"owner", rand.choice(authors)})
			if rand.int_max(4) == 0 do append(&tags, []string{"s", rand.choice(spaces[:])})
			if (is_addressable(kind) || is_replaceable(kind)) && rand.int_max(6) > 0 do append(&tags, []string{"d", rand.choice(ds[:])})
		}
		return store_test_tagged(n, author, kind, tags[:], i64(rand.int_max(60)))
	}

	// Random operations over few authors, spaces and addresses so that
	// supersession, e/a/h deletions, k restrictions, consent, malformed and
	// non-canonical addresses and legacy T evictions of retained deletions
	// all collide. Each plan must equal the scanning planner's; replaying
	// the operation log and compacting must reproduce the same state.
	@(test)
	store_indexed_plan_matches_scan :: proc(t: ^testing.T) {
		sync.lock(&store_test_mu)
		defer sync.unlock(&store_test_mu)
		store_test_reset()
		defer store_test_cleanup()
		gen := rand.create(t.seed)
		context.random_generator = rand.default_random_generator(&gen)
		authors := []string{strings.repeat("a", 64, context.temp_allocator), strings.repeat("b", 64, context.temp_allocator), strings.repeat("c", 64, context.temp_allocator)}
		ids := make([dynamic]string)
		defer delete(ids)
		oplog := make([dynamic]u8)
		defer delete(oplog)
		path, ok := store_test_temp_log(t, "relay-plan-index-*")
		if !ok do return
		defer delete(path)
		defer os.remove(path)
		g_log_path = path
		defer g_log_path = ""

		applied := 0
		for n in 1..=3000 {
			if n%61 == 0 {
				// A legacy T record evicts a retained deletion request.
				for s in g_order {
					if s.kind != 5 do continue
					append(&oplog, ..store_test_frame('T', s.id))
					evict(s)
					break
				}
				continue
			}
			ev := store_test_fuzz_event(n, authors, ids[:])
			append(&ids, ev.id)
			want, want_message, want_rejected := store_test_plan_scan(&ev)
			got, message, rejected := plan_operation(&ev)
			if message != want_message || rejected != want_rejected || (message == "" && !slice.equal(got[:], want[:])) {
				// Applying a divergent plan would only corrupt later steps.
				testing.expectf(t, false, "event %d kind %d tags %v: got %q %d victims, want %q %d", n, ev.kind, ev.tags, message, len(got), want_message, len(want))
				return
			}
			if message != "" do continue
			// Sequenced unless stored by an anonymous writer, as store_event does.
			seq: i64 = 0
			if n%5 != 0 {
				seq = 1
				if st, have := g_streams[stream_key(&ev)]; have do seq = st.head + 1
			}
			append(&oplog, ..store_test_op_frame(&ev, seq))
			apply_operation(&ev, event_json(&ev), got[:], seq)
			applied += 1
			if n%500 == 0 {
				if !store_test_expect_indexes(t) do return
				want_state := store_test_snapshot()
				testing.expect(t, compact())
				testing.expect_value(t, store_test_replay_file(path), Record_Status.Complete)
				store_test_expect_snapshot(t, want_state)
				if !store_test_expect_indexes(t) do return
			}
		}
		testing.expectf(t, applied > 800 && len(g_deleted) > 120 && len(g_space_deletions) > 0 && len(g_address_deletions) > 0,
			"coverage: %d applied, %d deleted, %d space and %d address deletion keys", applied, len(g_deleted), len(g_space_deletions), len(g_address_deletions))

		// Boot replay of the operation log re-derives every plan.
		store_test_expect_indexes(t)
		want_state := store_test_snapshot()
		store_test_reset()
		good, status := replay(oplog[:])
		testing.expect(t, status == .Complete && good == len(oplog))
		store_test_expect_snapshot(t, want_state)
		store_test_expect_indexes(t)
	}

	// A production-shaped log: one author republishing addressable state,
	// messages each deleted by the next request (retained deletions pile up),
	// a-tag deletions of current versions, space wipes, and a live set that
	// only grows. Plan work per record must stay flat as the log grows; the
	// scanning planner examined every live event and retained request.
	store_test_churn_log :: proc(steps: int) -> (log: [dynamic]u8, records: int) {
		author := strings.repeat("a", 64, context.temp_allocator)
		seqs := make(map[string]i64, context.temp_allocator)
		n := 0
		emit :: proc(log: ^[dynamic]u8, seqs: ^map[string]i64, ev: ^Event) {
			key := stream_key(ev)
			seqs[key] += 1
			append(log, ..store_test_op_frame(ev, seqs[key]))
		}
		for i in 0..<steps {
			space := fmt.tprintf("space-%d", i%8)
			at := i64(10*i)
			n += 1
			version := store_test_tagged(n, author, 31078, [][]string{{"d", fmt.tprintf("obj-%d", i%64)}, {"h", space}, {"s", space}}, at+5)
			emit(&log, &seqs, &version)
			n += 1
			message := store_test_tagged(n, author, 1078, [][]string{{"h", space}, {"owner", author}, {"s", space}}, at+5)
			emit(&log, &seqs, &message)
			n += 1
			kept := store_test_tagged(n, author, 1080, [][]string{{"c", "chunk"}}, at+5)
			emit(&log, &seqs, &kept)
			n += 1
			tags := [][]string{{"e", message.id}, {"e", fmt.tprintf("%064x", 1 << 40 + i)}}
			if i%4 == 0 do tags = [][]string{{"e", message.id}, {"a", fmt.tprintf("31078:%s:obj-%d", author, i%64)}}
			deletion := store_test_tagged(n, author, 5, tags, at+6)
			emit(&log, &seqs, &deletion)
			records += 4
			if i%128 == 127 {
				gone := fmt.tprintf("gone-%d", i)
				n += 1
				doomed := store_test_tagged(n, author, 1079, [][]string{{"h", gone}}, at+7)
				emit(&log, &seqs, &doomed)
				n += 1
				wipe := store_test_tagged(n, author, 5, [][]string{{"h", gone}}, at+8)
				emit(&log, &seqs, &wipe)
				records += 2
			}
		}
		return
	}

	@(test)
	store_replay_plan_work_is_linear :: proc(t: ^testing.T) {
		sync.lock(&store_test_mu)
		defer sync.unlock(&store_test_mu)
		store_test_reset()
		defer store_test_cleanup()
		per_record: [2]f64
		for steps, round in ([2]int{500, 4000}) {
			log, records := store_test_churn_log(steps)
			defer delete(log)
			store_test_reset()
			g_plan_work = 0
			good, status := replay(log[:])
			testing.expect(t, status == .Complete && good == len(log))
			// The 1080s stay live and every request stays retained.
			testing.expect(t, len(g_order) >= steps && len(g_deletion_refs) >= steps)
			per_record[round] = f64(g_plan_work) / f64(records)
		}
		testing.expectf(t, per_record[1] <= 1 && per_record[1] <= 1.1*per_record[0], "plan work per record: %v", per_record)
	}
}
