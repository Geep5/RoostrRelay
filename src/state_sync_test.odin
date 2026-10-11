package relay

// State sync (glonOdin docs/state-sync.md): bases are addressable kind
// 31078, overflow parts regular kind 1080, live deltas kind 1078 tagged
// ["b", base_hash]. Devices query #b/#c/#d/#h and reconcile them via NIP-77.

import "core:encoding/json"
import "core:strings"
import "core:sync"
import "core:testing"

when ODIN_TEST {
	state_test_filter :: proc(t: ^testing.T, src: string) -> Filter {
		v, err := json.parse_string(src, allocator = context.temp_allocator)
		testing.expect(t, err == nil, src)
		f, ok := parse_filter(v)
		testing.expect(t, ok, src)
		return f
	}

	state_test_ids :: proc(f: ^Filter) -> map[string]bool {
		rows, _ := query_filter(f)
		out := make(map[string]bool, context.temp_allocator)
		for r in rows do out[r.id] = true
		return out
	}

	@(test)
	state_sync_kinds_and_tag_filters :: proc(t: ^testing.T) {
		sync.lock(&store_test_mu)
		defer sync.unlock(&store_test_mu)
		store_test_reset()
		defer store_test_cleanup()
		me := strings.repeat("a", 64, context.temp_allocator)
		obj := "obj-1"

		base1 := store_test_tagged(1, me, 31078, [][]string{{"d", obj}, {"h", "space"}}, 10)
		base_other := store_test_tagged(2, me, 31078, [][]string{{"d", "obj-2"}}, 10)
		part_a := store_test_tagged(3, me, 1080, [][]string{{"c", "gid"}}, 11)
		part_b := store_test_tagged(4, me, 1080, [][]string{{"c", "gid"}}, 11)
		delta := store_test_tagged(5, me, 1078, [][]string{{"b", "hash1"}, {"h", "space"}}, 12)
		delta2 := store_test_tagged(6, me, 1078, [][]string{{"b", "hash2"}}, 12)
		for ev in ([]^Event{&base1, &base_other, &part_a, &part_b, &delta, &delta2}) {
			_, msg := store_test_apply(ev)
			testing.expect_value(t, msg, "")
		}
		// 1080 is regular: both parts stay.
		testing.expect(t, part_a.id in g_events && part_b.id in g_events)

		// Newer base for the same (pubkey, 31078, d) replaces the older one.
		base2 := store_test_tagged(7, me, 31078, [][]string{{"d", obj}, {"c", "gid"}}, 20)
		victims, msg := store_test_apply(&base2)
		testing.expect(t, msg == "" && victims == 1)
		testing.expect(t, !(base1.id in g_events) && base1.id in g_deleted && base2.id in g_events)
		testing.expect(t, base_other.id in g_events)
		// An older base arriving late never displaces the newer one.
		late := store_test_tagged(8, me, 31078, [][]string{{"d", obj}}, 15)
		_, _ = store_test_apply(&late)
		testing.expect(t, base2.id in g_events)

		// Single-letter tag filters.
		f := state_test_filter(t, `{"kinds":[1078],"#b":["hash1"]}`)
		got := state_test_ids(&f)
		testing.expect(t, len(got) == 1 && delta.id in got)
		f = state_test_filter(t, `{"kinds":[1080],"#c":["gid"]}`)
		got = state_test_ids(&f)
		testing.expect(t, len(got) == 2 && part_a.id in got && part_b.id in got)
		f = state_test_filter(t, `{"kinds":[31078],"#d":["obj-1"]}`)
		got = state_test_ids(&f)
		testing.expect(t, len(got) == 1 && base2.id in got)
		f = state_test_filter(t, `{"#h":["space"]}`)
		got = state_test_ids(&f)
		testing.expect(t, len(got) == 1 && delta.id in got) // base1 (also #h) was replaced

		// NIP-77 item sets honour the same filters.
		f = state_test_filter(t, `{"kinds":[1078],"#b":["hash1","hash2"]}`)
		items, ok := neg_collect(&f, 100)
		testing.expect(t, ok && len(items) == 2)
		delete(items)
		f = state_test_filter(t, `{"kinds":[31078],"authors":["` + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" + `"]}`)
		items, ok = neg_collect(&f, 100)
		testing.expect(t, ok && len(items) == 2)
		delete(items)
		f = state_test_filter(t, `{"kinds":[1080],"#c":["gid"]}`)
		items, ok = neg_collect(&f, 100)
		testing.expect(t, ok && len(items) == 2)
		delete(items)

		// NIP-09 `a` deletion removes the base (and versions up to its created_at).
		del := store_test_tagged(9, me, 5, [][]string{{"a", "31078:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:obj-1"}}, 30)
		victims, msg = store_test_apply(&del)
		testing.expect(t, msg == "" && victims == 1 && !(base2.id in g_events))
		testing.expect(t, base_other.id in g_events)
		// ... and blocks re-publishing an older version afterwards.
		stale := store_test_tagged(10, me, 31078, [][]string{{"d", obj}}, 25)
		_, msg = store_test_apply(&stale)
		testing.expect(t, msg != "" && !(stale.id in g_events))
		// A newer base after the deletion is accepted.
		fresh := store_test_tagged(11, me, 31078, [][]string{{"d", obj}}, 40)
		_, msg = store_test_apply(&fresh)
		testing.expect(t, msg == "" && fresh.id in g_events)
	}
}
