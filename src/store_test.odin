package relay

import "core:encoding/json"
import "core:fmt"
import "core:hash"
import "core:mem"
import "core:io"
import "core:os"
import "core:strings"
import "core:sync"
import "core:testing"

when ODIN_TEST {
	store_test_mu: sync.Mutex

	store_test_reset :: proc() {
		for len(g_order) > 0 do evict(g_order[len(g_order)-1])
		delete(g_order)
		delete(g_deletions)
		delete(g_deletion_refs)
		delete(g_events)
		for id in g_deleted do delete(id)
		delete(g_deleted)
		g_order = nil
		g_deletions = nil
		g_deletion_refs = nil
		g_events = make(map[string]^Stored)
		g_deleted = make(map[string]bool)
		g_tombs = 0
		g_anon_bytes = 0
		g_append_failed = false
	}

	store_test_cleanup :: proc() {
		store_test_reset()
		delete(g_events)
		delete(g_deleted)
		g_events = nil
		g_deleted = nil
	}

	store_test_event :: proc(n: int, kind: i64 = 1, timestamp: i64 = 10) -> Event {
		return Event{
			id = fmt.tprintf("%064x", n),
			pubkey = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			sig = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
			kind = kind, created_at = timestamp, tags_json = "[]", content = "test",
		}
	}

	store_test_tagged :: proc(n: int, pubkey: string, kind: i64, tags: [][]string, timestamp: i64 = 10) -> Event {
		ev := store_test_event(n, kind, timestamp)
		ev.pubkey = pubkey
		ev.tags = tags
		ev.tags_json = canon_tags(tags)
		return ev
	}

	// Plans and applies exactly as replay does; returns the victim count.
	store_test_apply :: proc(ev: ^Event) -> (victims: int, message: string) {
		planned, msg, _ := plan_operation(ev)
		if msg == "" do apply_operation(ev, event_json(ev), planned[:])
		return len(planned), msg
	}

	// Boot path: a fresh store replaying the file at `path`.
	store_test_replay_file :: proc(path: string) -> Record_Status {
		data, err := os.read_entire_file_from_path(path, context.allocator)
		if err != nil do return .Corrupt
		defer delete(data)
		store_test_reset()
		_, status := replay(data)
		return status
	}

	store_test_frame :: proc(type: u8, wire: string) -> []u8 {
		out := make([]u8, len(wire)+9, context.temp_allocator)
		out[0] = type
		n := u32(len(wire))
		for i in 0..<4 do out[i+1] = u8(n >> uint(8*i))
		copy(out[5:], transmute([]u8)wire)
		seed := type == 'A' ? hash.crc32(out[:5]) : u32(0)
		crc := hash.crc32(transmute([]u8)wire, seed)
		for i in 0..<4 do out[len(out)-4+i] = u8(crc >> uint(8*i))
		return out
	}

	Short_Write_State :: struct {
		bytes: [dynamic]u8,
		max_write: int,
		fail_at: int,
	}

	short_write_stream :: proc(data: rawptr, mode: os.File_Stream_Mode, p: []byte, offset: i64, whence: io.Seek_From, allocator: mem.Allocator) -> (i64, os.Error) {
		file := (^os.File)(data)
		state := (^Short_Write_State)(file.impl)
		if mode != .Write do return 0, .Unsupported
		if state.fail_at > 0 && len(state.bytes) >= state.fail_at do return 0, .Broken_Pipe
		n := min(len(p), state.max_write)
		if state.fail_at > 0 do n = min(n, state.fail_at-len(state.bytes))
		append(&state.bytes, ..p[:n])
		return i64(n), nil
	}

	@(test)
	store_full_write_contract :: proc(t: ^testing.T) {
		state := Short_Write_State{max_write = 2}
		defer delete(state.bytes)
		file := os.File{impl = &state, stream = {procedure = short_write_stream}}
		ev := store_test_event(1)
		wire := event_json(&ev)
		testing.expect(t, write_record_to(&file, 'A', wire))
		expected := store_test_frame('A', wire)
		testing.expect_value(t, string(state.bytes[:]), string(expected))
		_, _, _, status := decode_record(state.bytes[:])
		testing.expect_value(t, status, Record_Status.Complete)
		state.bytes[0] = 'E' // A's header is covered, unlike legacy E/T.
		_, _, _, status = decode_record(state.bytes[:])
		testing.expect_value(t, status, Record_Status.Corrupt)
		state.max_write = 0
		testing.expect(t, !write_full(&file, transmute([]u8)string("no progress")))
	}

	@(test)
	store_partial_append_failure_is_atomic :: proc(t: ^testing.T) {
		sync.lock(&store_test_mu)
		defer sync.unlock(&store_test_mu)
		defer store_test_cleanup()
		old := store_test_event(1, 30078)
		fresh := store_test_event(2, 30078, 20)
		wire := event_json(&fresh)
		for cut in ([]int{2, 50, len(wire)+7}) {
			store_test_reset()
			_ = intern(&old, event_json(&old))
			state := Short_Write_State{max_write = 2, fail_at = cut}
			file := os.File{impl = &state, stream = {procedure = short_write_stream}}
			g_fd = &file
			ok, _ := store_event(&fresh)
			testing.expect(t, !ok && g_append_failed && old.id in g_events && !(fresh.id in g_events))
			testing.expect_value(t, len(state.bytes), cut)
			ok, _ = store_event(&fresh)
			testing.expect(t, !ok && len(state.bytes) == cut)
			g_fd = nil
			delete(state.bytes)
		}
	}

	@(test)
	store_allowlist_revocation_commits :: proc(t: ^testing.T) {
		sync.lock(&store_test_mu)
		defer sync.unlock(&store_test_mu)
		store_test_reset()
		defer store_test_cleanup()
		old_allowed, old_dynamic := g_allowed, g_dynamic
		g_allowed = make(map[string]bool)
		g_dynamic = nil
		defer {
			delete(g_allowed)
			for k in g_dynamic do delete(k)
			delete(g_dynamic)
			g_allowed, g_dynamic = old_allowed, old_dynamic
		}
		fd, err := os.create_temp_file("", "relay-grant-*")
		if !testing.expect(t, err == nil) do return
		path := strings.clone(os.name(fd))
		defer delete(path)
		defer os.remove(path)
		g_fd = fd
		defer { os.close(fd); g_fd = nil }
		grant := store_test_event(1, ALLOWLIST_KIND)
		writer := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		g_allowed[grant.pubkey] = true
		grant.tags = [][]string{{"d", "roostr-allowlist"}, {"p", writer}, {"p", writer}}
		grant.tags_json = canon_tags(grant.tags)
		ok, _ := store_event(&grant)
		testing.expect(t, ok && write_allowed(writer) && len(g_dynamic) == 1)
		pending := store_test_event(2)
		pending.pubkey = writer
		testing.expect(t, event_write_allowed(&pending))
		del := store_test_event(3, 5, 20)
		del.tags = [][]string{{"e", grant.id}}
		del.tags_json = canon_tags(del.tags)
		ok, _ = store_event(&del)
		testing.expect(t, ok && !write_allowed(writer))
		// This event passed the earlier pre-crypto authorization check but
		// may not commit after revocation, even without another explicit refresh.
		message: string
		ok, message = store_event(&pending)
		testing.expect(t, !ok && strings.contains(message, "restricted") && !(pending.id in g_events))
	}

	@(test)
	store_atomic_replay_boundaries :: proc(t: ^testing.T) {
		sync.lock(&store_test_mu)
		defer sync.unlock(&store_test_mu)
		defer store_test_cleanup()
		arena: mem.Dynamic_Arena
		mem.dynamic_arena_init(&arena)
		defer mem.dynamic_arena_destroy(&arena)
		context.temp_allocator = mem.dynamic_arena_allocator(&arena)
		old := store_test_event(1, 30078)
		fresh := store_test_event(2, 30078, 20)
		legacy := store_test_frame('E', event_json(&old))
		atomic := store_test_frame('A', event_json(&fresh))
		log := make([]u8, len(legacy)+len(atomic), context.temp_allocator)
		copy(log, legacy)
		copy(log[len(legacy):], atomic)
		// Every byte boundary of an interrupted replacement keeps the old
		// version. No prefix commits its tombstone without its replacement.
		for cut in 0..<len(atomic) {
			store_test_reset()
			good, status := replay(log[:len(legacy)+cut])
			testing.expect_value(t, good, len(legacy))
			testing.expect(t, status == (cut == 0 ? Record_Status.Complete : Record_Status.Incomplete))
			testing.expect(t, old.id in g_events && !(fresh.id in g_events))
		}
		store_test_reset()
		good, status := replay(log)
		testing.expect(t, status == .Complete && good == len(log))
		testing.expect(t, fresh.id in g_events && !(old.id in g_events) && old.id in g_deleted)
	}

	@(test)
	store_corruption_preserves_suffix :: proc(t: ^testing.T) {
		sync.lock(&store_test_mu)
		defer sync.unlock(&store_test_mu)
		store_test_reset()
		defer store_test_cleanup()
		ev := store_test_event(1)
		wire := event_json(&ev)
		frame := store_test_frame('E', wire)
		log := make([]u8, len(frame)*2, context.temp_allocator)
		copy(log, frame)
		copy(log[len(frame):], frame)
		log[5] ~= 1 // Complete bad CRC followed by a valid record.
		good, status := replay(log)
		testing.expect(t, good == 0 && status == .Corrupt && len(g_order) == 0)
		copy(log, frame)
		// A damaged length is indistinguishable from a torn append: truncate.
		n := u32(len(log)+100)
		for i in 0..<4 do log[i+1] = u8(n >> uint(8*i))
		good, status = replay(log)
		testing.expect(t, good == 0 && status == .Incomplete && len(g_order) == 0)
		bad_json := store_test_frame('E', "not JSON")
		_, status = replay(bad_json)
		testing.expect_value(t, status, Record_Status.Corrupt)
		frame[0] = 'Z'
		_, _, _, status = decode_record(frame)
		testing.expect_value(t, status, Record_Status.Corrupt)
	}

	@(test)
	store_compaction_failure_keeps_original :: proc(t: ^testing.T) {
		sync.lock(&store_test_mu)
		defer sync.unlock(&store_test_mu)
		store_test_reset()
		defer store_test_cleanup()
		fd, err := os.create_temp_file("", "relay-compact-error-*")
		if !testing.expect(t, err == nil) do return
		path := strings.clone(os.name(fd))
		defer delete(path)
		defer os.remove(path)
		ev := store_test_event(1)
		wire := event_json(&ev)
		testing.expect(t, write_record_to(fd, 'E', wire) && os.sync(fd) == nil)
		os.close(fd)
		g_log_path = path
		defer g_log_path = ""
		tmp := fmt.tprintf("%s.tmp", path)
		if !testing.expect(t, os.mkdir(tmp) == nil) do return
		defer os.remove(tmp)
		g_tombs = COMPACT_MIN_TOMBS
		testing.expect(t, !compact() && g_tombs == COMPACT_MIN_TOMBS)
		data, read_err := os.read_entire_file_from_path(path, context.allocator)
		if !testing.expect(t, read_err == nil) do return
		defer delete(data)
		testing.expect_value(t, string(data), string(store_test_frame('E', wire)))
	}

	@(test)
	store_legacy_record_size_upgrade :: proc(t: ^testing.T) {
		sync.lock(&store_test_mu)
		defer sync.unlock(&store_test_mu)
		store_test_reset()
		defer store_test_cleanup()
		ev := store_test_event(1)
		base := event_json(&ev)
		content := make([]u8, MAX_RECORD-len(base)+len(ev.content), context.temp_allocator)
		for &c in content do c = 'x'
		ev.content = string(content)
		wire := event_json(&ev)
		testing.expect_value(t, len(wire), MAX_RECORD)
		frame := store_test_frame('E', wire)
		good, status := replay(frame)
		testing.expect(t, status == .Complete && good == len(frame) && ev.id in g_events)
		testing.expect_value(t, len(g_events[ev.id].json), MAX_RECORD)
		oversize := store_test_frame('A', fmt.tprintf("%sx", wire))
		_, _, _, status = decode_record(oversize)
		testing.expect_value(t, status, Record_Status.Corrupt)
		ev.id = fmt.tprintf("%064x", 2)
		ev.content = fmt.tprintf("%sx", ev.content)
		ok, message := store_event(&ev)
		testing.expect(t, !ok && strings.contains(message, "too large") && !g_append_failed)
	}

	@(test)
	store_repeated_delete_and_retained_history :: proc(t: ^testing.T) {
		sync.lock(&store_test_mu)
		defer sync.unlock(&store_test_mu)
		store_test_reset()
		defer store_test_cleanup()
		victim := store_test_event(1, 30078)
		victim.tags = [][]string{{"d", "part:one"}}
		victim.tags_json = canon_tags(victim.tags)
		_ = intern(&victim, event_json(&victim))
		del := store_test_event(2, 5, 20)
		del.tags = [][]string{{"e", victim.id}, {"e", victim.id}, {"a", fmt.tprintf("30078:%s:part:one", victim.pubkey)}, {"e", fmt.tprintf("%064x", 5)}}
		del.tags_json = canon_tags(del.tags)
		victims, message, rejected := plan_operation(&del)
		testing.expect(t, message == "" && !rejected && len(victims) == 1)
		apply_operation(&del, event_json(&del), victims[:])
		testing.expect(t, len(g_order) == 1 && victim.id in g_deleted)
		_, message, rejected = plan_operation(&victim)
		testing.expect(t, rejected && strings.contains(message, "deleted"))
		// Unknown IDs addressed by retained deletion events cannot arrive later.
		late := victim
		late.id = fmt.tprintf("%064x", 3)
		_, _, rejected = plan_operation(&late)
		testing.expect(t, rejected)
		late.created_at = 21
		_, message, rejected = plan_operation(&late)
		testing.expect(t, !rejected && message == "")
		// An e tag naming an ID never stored blocks only its author's copy.
		unknown := store_test_event(5)
		_, message, rejected = plan_operation(&unknown)
		testing.expect(t, rejected && message == "blocked: event was deleted")
		unknown.pubkey = strings.repeat("b", 64, context.temp_allocator)
		_, message, rejected = plan_operation(&unknown)
		testing.expect(t, !rejected && message == "")
		unknown.pubkey = victim.pubkey
		// Deletion events themselves cannot be deleted.
		delete_delete := store_test_event(4, 5, 30)
		delete_delete.tags = [][]string{{"e", del.id}, {"e", del.id}}
		victims, _, _ = plan_operation(&delete_delete)
		testing.expect_value(t, len(victims), 0)

		fd, err := os.create_temp_file("", "relay-compaction-*")
		if !testing.expect(t, err == nil) do return
		path := strings.clone(os.name(fd))
		defer delete(path)
		defer os.remove(path)
		os.close(fd)
		g_log_path = path
		defer g_log_path = ""
		testing.expect(t, compact())
		data, read_err := os.read_entire_file_from_path(path, context.allocator)
		if !testing.expect(t, read_err == nil) do return
		defer delete(data)
		store_test_reset()
		_, status := replay(data)
		testing.expect(t, status == .Complete && victim.id in g_deleted && del.id in g_events)
		_, _, rejected = plan_operation(&victim)
		testing.expect(t, rejected)
		late.created_at = 10
		_, _, rejected = plan_operation(&late)
		testing.expect(t, rejected)
		_, _, rejected = plan_operation(&unknown)
		testing.expect(t, rejected)
	}

	@(test)
	store_space_deletion_consent_and_kinds :: proc(t: ^testing.T) {
		sync.lock(&store_test_mu)
		defer sync.unlock(&store_test_mu)
		store_test_reset()
		defer store_test_cleanup()
		owner := strings.repeat("a", 64, context.temp_allocator)
		member := strings.repeat("b", 64, context.temp_allocator)
		attacker := strings.repeat("c", 64, context.temp_allocator)
		space := "blinded-space-tag"
		other := "blinded-other-tag"
		own := store_test_tagged(1, owner, 1078, [][]string{{"h", space}})
		consenting := store_test_tagged(2, member, 1079, [][]string{{"h", other}, {"h", space}, {"owner", owner}})
		plain := store_test_tagged(3, member, 1078, [][]string{{"h", space}})
		foreign_consent := store_test_tagged(4, member, 1078, [][]string{{"h", space}, {"owner", attacker}})
		unlisted_kind := store_test_tagged(5, owner, 1, [][]string{{"h", space}})
		other_space := store_test_tagged(6, member, 1078, [][]string{{"h", other}, {"owner", owner}})
		attacker_own := store_test_tagged(7, attacker, 1078, [][]string{{"h", space}})
		for ev in ([]^Event{&own, &consenting, &plain, &foreign_consent, &unlisted_kind, &other_space, &attacker_own}) {
			_ = intern(ev, event_json(ev))
		}

		// The owner wipes its own and consenting events of the listed kinds;
		// another author's event without ["owner", owner] survives.
		owner_delete := store_test_tagged(10, owner, 5, [][]string{{"h", space}, {"k", "1078"}, {"k", "1079"}}, 20)
		victims, message := store_test_apply(&owner_delete)
		testing.expect(t, message == "" && victims == 2)
		testing.expect(t, !(own.id in g_events) && !(consenting.id in g_events) && own.id in g_deleted && consenting.id in g_deleted)
		testing.expect(t, plain.id in g_events && foreign_consent.id in g_events && unlisted_kind.id in g_events)
		testing.expect(t, other_space.id in g_events && attacker_own.id in g_events)

		// Retained: matching late arrivals are refused, including another
		// author's consenting event; unlisted kinds and non-consenting
		// authors still pass, as does the same author in another space.
		rejected: bool
		late := store_test_tagged(11, owner, 1079, [][]string{{"h", space}}, 30)
		_, message, rejected = plan_operation(&late)
		testing.expect(t, rejected && message == "blocked: event was deleted")
		late = store_test_tagged(12, member, 1078, [][]string{{"owner", owner}, {"h", space}}, 30)
		_, message, rejected = plan_operation(&late)
		testing.expect(t, rejected && message == "blocked: event was deleted")
		late = store_test_tagged(13, owner, 1, [][]string{{"h", space}}, 30)
		_, message, rejected = plan_operation(&late)
		testing.expect(t, !rejected && message == "")
		late = store_test_tagged(14, member, 1078, [][]string{{"h", space}}, 30)
		_, message, rejected = plan_operation(&late)
		testing.expect(t, !rejected && message == "")
		late = store_test_tagged(15, owner, 1078, [][]string{{"h", other}}, 30)
		_, message, rejected = plan_operation(&late)
		testing.expect(t, !rejected && message == "")

		// Any other signer reaches only its own events and those consenting to
		// it. Its e tag naming someone else's event stays author-only NIP-09.
		attacker_delete := store_test_tagged(16, attacker, 5, [][]string{{"h", space}, {"e", plain.id}}, 40)
		victims, message = store_test_apply(&attacker_delete)
		testing.expect(t, message == "" && victims == 2)
		testing.expect(t, !(attacker_own.id in g_events) && !(foreign_consent.id in g_events))
		testing.expect(t, plain.id in g_events && unlisted_kind.id in g_events && owner_delete.id in g_events)

		// Without k tags every kind goes except deletion requests; another
		// space stays untouched even when it consents to the owner.
		owner_wipe := store_test_tagged(17, owner, 5, [][]string{{"h", space}}, 50)
		victims, message = store_test_apply(&owner_wipe)
		testing.expect(t, message == "" && victims == 1 && !(unlisted_kind.id in g_events))
		testing.expect(t, owner_delete.id in g_events && attacker_delete.id in g_events)
		testing.expect(t, plain.id in g_events && other_space.id in g_events)
		late = store_test_tagged(18, owner, 1, [][]string{{"h", space}}, 60)
		_, message, rejected = plan_operation(&late)
		testing.expect(t, rejected && message == "blocked: event was deleted")
		// Deletion requests are never victims: members backfilling
		// {kinds:[5], #h:[T]} read the owner's request as "space deleted".
		f := Filter{kinds = []i64{5}, tags = []Tag_Filter{{name = "h", values = []string{space}}}}
		rows, _ := query_filter(&f)
		testing.expect_value(t, len(rows), 3)
		f.authors = []string{owner}
		rows, _ = query_filter(&f)
		testing.expect_value(t, len(rows), 2)
		testing.expect(t, rows[0].id == owner_wipe.id && rows[1].id == owner_delete.id)
	}

	store_test_expect_space_gone :: proc(t: ^testing.T, count, kept: int, late: ^Event) {
		gone, present := 0, 0
		for i in 1..=count {
			id := fmt.tprintf("%064x", i)
			if !(id in g_events) && id in g_deleted do gone += 1
		}
		for i in count+1..=count+kept {
			if fmt.tprintf("%064x", i) in g_events do present += 1
		}
		testing.expect_value(t, gone, count)
		testing.expect_value(t, present, kept)
		testing.expect_value(t, len(g_order), kept)
		_, message, rejected := plan_operation(late)
		testing.expect(t, rejected && message == "blocked: event was deleted")
	}

	@(test)
	store_space_deletion_complete_across_replay_and_compaction :: proc(t: ^testing.T) {
		sync.lock(&store_test_mu)
		defer sync.unlock(&store_test_mu)
		store_test_reset()
		defer store_test_cleanup()
		old_dynamic := g_dynamic
		g_dynamic = nil
		defer {
			for k in g_dynamic do delete(k)
			delete(g_dynamic)
			g_dynamic = old_dynamic
		}
		owner := strings.repeat("a", 64, context.temp_allocator)
		member := strings.repeat("b", 64, context.temp_allocator)
		space := "blinded-space-tag"
		own_tags := [][]string{{"h", space}}
		consent_tags := [][]string{{"h", space}, {"owner", owner}}
		// Several MAX_LIMIT pages of owner and consenting member events, then
		// member events that never consented.
		count := 2*MAX_LIMIT + 7
		survivors := 3
		log := make([dynamic]u8, context.temp_allocator)
		for i in 0..<count+survivors {
			ev: Event
			switch {
			case i >= count: ev = store_test_tagged(i+1, member, 1078, own_tags)
			case i%2 == 0:   ev = store_test_tagged(i+1, owner, 1078, own_tags)
			case:            ev = store_test_tagged(i+1, member, 1079, consent_tags)
			}
			append(&log, ..store_test_frame('A', event_json(&ev)))
		}
		fd, err := os.create_temp_file("", "relay-space-*")
		if !testing.expect(t, err == nil) do return
		path := strings.clone(os.name(fd))
		defer delete(path)
		defer os.remove(path)
		testing.expect(t, write_full(fd, log[:]) && os.sync(fd) == nil)
		os.close(fd)
		g_log_path = path
		defer g_log_path = ""
		testing.expect_value(t, store_test_replay_file(path), Record_Status.Complete)
		testing.expect_value(t, len(g_order), count+survivors)

		// One accepted deletion, logged as one A record, empties the space.
		fd, err = os.open(path, {.Write, .Append}, os.Permissions_Default_File)
		if !testing.expect(t, err == nil) do return
		g_fd = fd
		del := store_test_tagged(count+survivors+1, owner, 5, [][]string{{"h", space}, {"k", "1078"}, {"k", "1079"}}, 20)
		ok, message := store_event(&del)
		os.close(fd)
		g_fd = nil
		testing.expect(t, ok && message == "")
		late := store_test_tagged(count+survivors+2, member, 1079, consent_tags, 30)
		store_test_expect_space_gone(t, count, survivors+1, &late)

		// Boot replay re-derives the same victims from that record and would
		// compact; the compacted log keeps the deletion and its retention.
		testing.expect_value(t, store_test_replay_file(path), Record_Status.Complete)
		store_test_expect_space_gone(t, count, survivors+1, &late)
		testing.expect(t, g_tombs >= COMPACT_MIN_TOMBS && compact())
		testing.expect_value(t, store_test_replay_file(path), Record_Status.Complete)
		store_test_expect_space_gone(t, count, survivors+1, &late)
		resurrect := store_test_tagged(1, owner, 1078, own_tags)
		_, message, _ = plan_operation(&resurrect)
		testing.expect_value(t, message, "blocked: event was deleted")
	}

	@(test)
	store_rejects_deletion_beyond_plan_tags :: proc(t: ^testing.T) {
		sync.lock(&store_test_mu)
		defer sync.unlock(&store_test_mu)
		store_test_reset()
		defer store_test_cleanup()
		// One more victim than the planner examines: accepting the request
		// would delete the first MAX_PLAN_TAGS and silently keep the last.
		count := MAX_PLAN_TAGS + 1
		tags := make([][]string, count, context.temp_allocator)
		for i in 0..<count {
			victim := store_test_event(i + 1)
			_ = intern(&victim, event_json(&victim))
			tag := make([]string, 2, context.temp_allocator)
			tag[0] = "e"
			tag[1] = fmt.tprintf("%064x", i + 1)
			tags[i] = tag
		}
		del := store_test_event(count + 1, 5, 20)
		del.tags = tags
		del.tags_json = canon_tags(del.tags)
		ok, message := store_event(&del)
		testing.expect(t, !ok && strings.contains(message, "more than"))
		testing.expect_value(t, len(g_order), count)
		// Exactly at the bound the whole request applies.
		del.tags = tags[:MAX_PLAN_TAGS]
		del.tags_json = canon_tags(del.tags)
		victims, msg, rejected := plan_operation(&del)
		testing.expect(t, msg == "" && !rejected)
		testing.expect_value(t, len(victims), MAX_PLAN_TAGS)
	}

	@(test)
	store_append_failure_latches :: proc(t: ^testing.T) {
		sync.lock(&store_test_mu)
		defer sync.unlock(&store_test_mu)
		store_test_reset()
		defer store_test_cleanup()
		fd, err := os.create_temp_file("", "relay-append-*")
		if !testing.expect(t, err == nil) do return
		path := strings.clone(os.name(fd))
		defer delete(path)
		defer os.remove(path)
		os.close(fd)
		fd, err = os.open(path, {.Read}, os.Permissions_Default_File)
		if !testing.expect(t, err == nil) do return
		g_fd = fd
		ev := store_test_event(1)
		ok, _ := store_event(&ev)
		testing.expect(t, !ok && g_append_failed && len(g_order) == 0)
		os.close(fd)
		fd, err = os.open(path, {.Write, .Append}, os.Permissions_Default_File)
		if !testing.expect(t, err == nil) { g_fd = nil; return }
		g_fd = fd
		defer { os.close(fd); g_fd = nil }
		ok, _ = store_event(&ev)
		size, size_err := os.file_size(fd)
		testing.expect(t, !ok && size_err == nil && size == 0 && len(g_order) == 0)
	}

	@(test)
	store_query_topk_and_byte_budget :: proc(t: ^testing.T) {
		sync.lock(&store_test_mu)
		defer sync.unlock(&store_test_mu)
		store_test_reset()
		defer store_test_cleanup()
		for i in 0..<MAX_LIMIT+37 {
			ev := store_test_event(i+1, 1, i64(i/2))
			_ = intern(&ev, event_json(&ev))
		}
		f := Filter{limit = 3, has_limit = true}
		rows, exhausted := query_filter(&f)
		testing.expect(t, len(rows) == 3 && !exhausted)
		for i in 1..<len(rows) do testing.expect(t, stored_before(g_events[rows[i-1].id], g_events[rows[i].id]))
		best := g_events[rows[0].id]
		for s in g_order do testing.expect(t, !stored_before(s, best))
		last := g_events[rows[len(rows)-1].id]
		for s in g_order {
			selected := false
			for row in rows do if row.id == s.id { selected = true; break }
			if !selected do testing.expect(t, !stored_before(s, last))
		}
		budget := len(rows[0].json)+QUERY_ROW_OVERHEAD
		rows, exhausted = query_filter(&f, budget)
		testing.expect(t, len(rows) == 1 && exhausted)
		rows, exhausted = query_filter(&f, budget-1)
		testing.expect(t, len(rows) == 0 && exhausted)
		f.limit = 0
		rows, exhausted = query_filter(&f)
		testing.expect(t, len(rows) == 0 && !exhausted)
		f.limit = MAX_LIMIT+1000
		rows, exhausted = query_filter(&f)
		testing.expect(t, len(rows) == MAX_LIMIT && !exhausted)
	}

	@(test)
	store_filter_cardinality_contract :: proc(t: ^testing.T) {
		v, err := json.parse(transmute([]u8)string(`{"limit":0,"#d":["part:one"]}`), allocator = context.temp_allocator)
		testing.expect(t, err == nil)
		f, ok := parse_filter(v)
		testing.expect(t, ok && f.has_limit && f.limit == 0)
		sb := strings.builder_make(context.temp_allocator)
		strings.write_string(&sb, `{"authors":[`)
		for i in 0..=MAX_FILTER_VALUES {
			if i > 0 do strings.write_byte(&sb, ',')
			strings.write_string(&sb, `"a"`)
		}
		strings.write_string(&sb, "]}")
		v, err = json.parse(transmute([]u8)strings.to_string(sb), allocator = context.temp_allocator)
		testing.expect(t, err == nil)
		_, ok = parse_filter(v)
		testing.expect(t, !ok)
	}

	@(test)
	store_torn_tail_always_truncates :: proc(t: ^testing.T) {
		sync.lock(&store_test_mu)
		defer sync.unlock(&store_test_mu)
		defer store_test_cleanup()
		ev1 := store_test_event(1)
		ev2 := store_test_event(2, 1, 20)
		frame1 := store_test_frame('A', event_json(&ev1))
		frame2 := store_test_frame('A', event_json(&ev2))

		// Plain torn tail: heals by truncating the partial record.
		store_test_reset()
		log := make([]u8, len(frame1)+7, context.temp_allocator)
		copy(log, frame1)
		copy(log[len(frame1):], frame2[:7])
		good, status := replay(log)
		testing.expect(t, status == .Incomplete && good == len(frame1))
		testing.expect(t, ev1.id in g_events && !(ev2.id in g_events))

		// A valid frame PLANTED after torn bytes is discarded with the tail:
		// bytes past an interrupted append are untrustworthy. Boot must heal,
		// never FATAL. The torn header claims a length past end-of-file.
		store_test_reset()
		torn: [5]u8
		torn[0] = 'A'
		n := u32(64 << 10)
		for i in 0..<4 do torn[i+1] = u8(n >> uint(8*i))
		log2 := make([]u8, len(frame1)+len(torn)+len(frame2), context.temp_allocator)
		copy(log2, frame1)
		copy(log2[len(frame1):], torn[:])
		copy(log2[len(frame1)+len(torn):], frame2)
		good, status = replay(log2)
		testing.expect(t, status == .Incomplete && good == len(frame1))
		testing.expect(t, ev1.id in g_events && !(ev2.id in g_events))

		// The healed file replays clean and keeps only the trusted prefix.
		fd, err := os.create_temp_file("", "relay-heal-*")
		if !testing.expect(t, err == nil) do return
		path := strings.clone(os.name(fd))
		defer delete(path)
		defer os.remove(path)
		os.close(fd)
		g_log_path = path
		defer g_log_path = ""
		testing.expect(t, replace_log(log2[:good], false))
		store_test_reset()
		data, rerr := os.read_entire_file_from_path(path, context.allocator)
		if !testing.expect(t, rerr == nil) do return
		defer delete(data)
		good, status = replay(data)
		testing.expect(t, status == .Complete && good == len(frame1))
		testing.expect(t, ev1.id in g_events && !(ev2.id in g_events))

		// Mid-log CRC damage on a complete-sized record still refuses to boot.
		store_test_reset()
		log3 := make([]u8, len(frame1)+len(frame2), context.temp_allocator)
		copy(log3, frame1)
		copy(log3[len(frame1):], frame2)
		log3[len(frame1)+5] ~= 1
		good, status = replay(log3)
		testing.expect(t, status == .Corrupt && good == len(frame1))
	}

	@(test)
	store_anonymous_quotas :: proc(t: ^testing.T) {
		sync.lock(&store_test_mu)
		defer sync.unlock(&store_test_mu)
		store_test_reset()
		defer store_test_cleanup()
		old_allowed := g_allowed
		g_allowed = make(map[string]bool)
		defer { delete(g_allowed); g_allowed = old_allowed }
		resident := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		stranger := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		g_allowed[resident] = true
		fd, err := os.create_temp_file("", "relay-quota-*")
		if !testing.expect(t, err == nil) do return
		path := strings.clone(os.name(fd))
		defer delete(path)
		defer os.remove(path)
		g_fd = fd
		defer { os.close(fd); g_fd = nil }

		// Gift cap: ANON_MAX_GIFTS_PER_TARGET per resident recipient, then
		// further stranger gifts are rejected (nothing is evicted).
		for i in 0..<ANON_MAX_GIFTS_PER_TARGET {
			gift := store_test_event(i+1, 1059)
			gift.pubkey = stranger
			gift.tags = [][]string{{"p", resident}}
			gift.tags_json = canon_tags(gift.tags)
			ok, _ := store_event(&gift)
			testing.expect(t, ok)
		}
		testing.expect(t, g_anon_bytes > 0)
		gift := store_test_event(1000, 1059)
		gift.pubkey = stranger
		gift.tags = [][]string{{"p", resident}}
		gift.tags_json = canon_tags(gift.tags)
		ok, message := store_event(&gift)
		testing.expect(t, !ok && strings.contains(message, "gift inbox") && !(gift.id in g_events))
		// A different resident's inbox is unaffected, and a resident's own
		// gifts are not capped.
		other := "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
		g_allowed[other] = true
		gift.id = fmt.tprintf("%064x", 1001)
		gift.tags = [][]string{{"p", other}}
		gift.tags_json = canon_tags(gift.tags)
		ok, _ = store_event(&gift)
		testing.expect(t, ok)
		gift.id = fmt.tprintf("%064x", 1002)
		gift.pubkey = resident
		gift.tags = [][]string{{"p", resident}}
		gift.tags_json = canon_tags(gift.tags)
		ok, _ = store_event(&gift)
		testing.expect(t, ok)

		// Byte cap: strangers cannot retain more than ANON_MAX_TOTAL_BYTES in
		// aggregate, even rotating fresh keys (kind-0 is 1 per pubkey).
		content := strings.repeat("x", 1 << 20 - 1024, context.temp_allocator)
		stored := 0
		for i in 0..<64 {
			ev := store_test_event(2000+i, 0)
			ev.pubkey = fmt.tprintf("%064x", i+0x1000)
			ev.content = content
			ok, message = store_event(&ev)
			if !ok {
				testing.expect(t, strings.contains(message, "quota") && !(ev.id in g_events))
				break
			}
			stored += 1
		}
		testing.expect(t, stored >= 31 && stored < 64 && g_anon_bytes <= ANON_MAX_TOTAL_BYTES)
		// A stranger updating their OWN kind-0 supersedes the old copy and its
		// bytes, so a writer at the quota boundary is never locked out.
		ev := store_test_event(3000, 0, 20)
		ev.pubkey = fmt.tprintf("%064x", 0x1000)
		ok, _ = store_event(&ev)
		testing.expect(t, ok)
	}
}
