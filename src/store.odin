package relay

// Pure-Odin storage: an append-only log of framed records plus in-memory
// indexes rebuilt on boot. No sqlite, no C.
//
// Why this shape fits a relay: events are immutable and content-addressed,
// "updates" are supersedes (replaceable/addressable kinds) and NIP-09
// deletions - both are tombstones here. The log is truth; memory mirrors
// it. And the relay itself is a cache in the Roostr architecture (the
// .pb files on devices are truth; harnesses republish what the relay
// lacks at startup reconcile), so even catastrophic loss self-heals.
//
// Record framing:  [1B type][u32le len][payload][u32le crc32(payload)]
//   'E'  event, payload = wire JSON (the exact bytes REQ echoes back)
//   'T'  tombstone, payload = 64-char hex event id
// A torn tail (crash mid-append) fails the length/CRC check and is
// truncated on boot - everything before it is intact.
//
// Concurrency matches the sqlite version: one process-wide mutex over
// both the file and the maps. At Roostr scale a reader/writer split is
// still premature; the seam (store_open/store_event/query_filter) is
// unchanged, so that upgrade stays a drop-in.

import "core:encoding/json"
import "core:fmt"
import "core:hash"
import "core:os"
import "core:slice"
import "core:strings"
import "core:sync"

g_mu: sync.Mutex
g_fd: ^os.File
g_log_path: string

Stored :: struct {
	id:         string,
	pubkey:     string,
	created_at: i64,
	kind:       i64,
	d:          string, // addressable identity ("" otherwise)
	tags:       [][2]string, // single-letter tags only (the indexed set)
	json:       string, // wire JSON, echoed verbatim by REQ
	idx:        int, // position in g_order (swap-remove bookkeeping)
}

g_events: map[string]^Stored
g_order: [dynamic]^Stored
g_tombs: int // tombstoned records currently wasting log bytes

MAX_RECORD :: 1 << 19 // 512 KiB - relay caps messages far below this
COMPACT_MIN_TOMBS :: 1024

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

@(private = "file")
write_record :: proc(type: u8, payload: string) -> bool {
	head: [5]u8
	head[0] = type
	n := u32(len(payload))
	head[1] = u8(n)
	head[2] = u8(n >> 8)
	head[3] = u8(n >> 16)
	head[4] = u8(n >> 24)
	crc := hash.crc32(transmute([]u8)payload)
	tail: [4]u8
	tail[0] = u8(crc)
	tail[1] = u8(crc >> 8)
	tail[2] = u8(crc >> 16)
	tail[3] = u8(crc >> 24)
	if _, err := os.write(g_fd, head[:]); err != nil do return false
	if _, err := os.write(g_fd, transmute([]u8)payload); err != nil do return false
	if _, err := os.write(g_fd, tail[:]); err != nil do return false
	return true
}

@(private = "file")
sync_log :: proc() -> bool {
	return os.sync(g_fd) == nil
}

// -- In-memory index ---------------------------------------------------

@(private = "file")
intern :: proc(ev: ^Event, wire_json: string) -> ^Stored {
	s := new(Stored)
	s.id = strings.clone(ev.id)
	s.pubkey = strings.clone(ev.pubkey)
	s.created_at = ev.created_at
	s.kind = ev.kind
	s.json = strings.clone(wire_json)

	count := 0
	for tag in ev.tags {
		if len(tag) >= 2 && len(tag[0]) == 1 {
			ch := tag[0][0]
			if ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' do count += 1
		}
	}
	s.tags = make([][2]string, count)
	i := 0
	for tag in ev.tags {
		if len(tag) >= 2 && len(tag[0]) == 1 {
			ch := tag[0][0]
			if ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' {
				s.tags[i] = {strings.clone(tag[0]), strings.clone(tag[1])}
				if tag[0] == "d" && s.d == "" do s.d = s.tags[i][1]
				i += 1
			}
		}
	}

	s.idx = len(g_order)
	append(&g_order, s)
	g_events[s.id] = s
	return s
}

@(private = "file")
evict :: proc(s: ^Stored) {
	// Swap-remove from g_order, keeping idx fields honest.
	last := g_order[len(g_order) - 1]
	g_order[s.idx] = last
	last.idx = s.idx
	pop(&g_order)
	delete_key(&g_events, s.id)

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

	if data, rerr := os.read_entire_file_from_path(path, context.allocator); rerr == nil {
		defer delete(data)
		// A leftover sqlite file is not ours to parse - set it aside and
		// start fresh; harness startup reconcile repopulates the cache.
		if len(data) >= 16 && string(data[:15]) == "SQLite format 3" {
			bak := fmt.tprintf("%s.sqlite.bak", path)
			_ = os.rename(path, bak)
			fmt.printfln("[relay] found sqlite store; moved to %s and starting a fresh log", bak)
		} else {
			replay(data)
		}
	}

	if g_tombs >= COMPACT_MIN_TOMBS {
		compact()
	} else {
		// Reopen for appends (replay may have truncated a torn tail).
		reopen_for_append()
	}
	fmt.printfln("[relay] store: %d event(s), %d tombstone(s) in log", len(g_order), g_tombs)
}

@(private = "file")
replay :: proc(data: []u8) {
	off := 0
	good := 0 // byte offset after the last valid record
	for off + 9 <= len(data) {
		type := data[off]
		n := int(data[off + 1]) | int(data[off + 2]) << 8 | int(data[off + 3]) << 16 | int(data[off + 4]) << 24
		if (type != 'E' && type != 'T') || n <= 0 || n > MAX_RECORD || off + 5 + n + 4 > len(data) do break
		payload := data[off + 5:off + 5 + n]
		c := data[off + 5 + n:off + 5 + n + 4]
		want := u32(c[0]) | u32(c[1]) << 8 | u32(c[2]) << 16 | u32(c[3]) << 24
		if hash.crc32(payload) != want do break

		switch type {
		case 'E':
			apply_event_record(string(payload))
		case 'T':
			if s, have := g_events[string(payload)]; have do evict(s)
		}
		off += 5 + n + 4
		good = off
	}
	if good < len(data) {
		fmt.printfln("[relay] log: truncating %d torn byte(s) at offset %d", len(data) - good, good)
		truncate_log(good, data[:good])
	}
}

@(private = "file")
apply_event_record :: proc(wire: string) {
	v, jerr := json.parse(transmute([]u8)wire, .JSON, false, context.temp_allocator)
	if jerr != nil do return
	ev, perr := parse_event(v)
	if perr != "" do return
	if _, have := g_events[ev.id]; have do return
	_ = intern(&ev, wire)
}

@(private = "file")
truncate_log :: proc(size: int, good: []u8) {
	// os.truncate is not portable across Odin targets; rewrite is - and a
	// torn tail is a rare crash artifact, not a hot path.
	tmp := fmt.tprintf("%s.tmp", g_log_path)
	if os.write_entire_file(tmp, good) != nil {
		fmt.eprintln("[relay] log: could not rewrite torn tail; keeping as-is")
		return
	}
	if os.rename(tmp, g_log_path) != nil do fmt.eprintln("[relay] log: rename failed after tail rewrite")
}

@(private = "file")
reopen_for_append :: proc() {
	fd, err := os.open(g_log_path, {.Write, .Create, .Append}, os.Permissions_Default_File)
	if err != nil {
		fmt.eprintln("[relay] FATAL: cannot open log for append:", err)
		os.exit(1)
	}
	g_fd = fd
}

/** Rewrite the log with only live events; tombstones and their victims
 *  vanish. Boot-only, before the socket opens - no concurrency. */
@(private = "file")
compact :: proc() {
	tmp := fmt.tprintf("%s.tmp", g_log_path)
	fd, err := os.open(tmp, {.Write, .Create, .Trunc}, os.Permissions_Default_File)
	if err != nil {
		fmt.eprintln("[relay] compact: cannot open tmp, keeping log as-is:", err)
		reopen_for_append()
		return
	}
	g_fd = fd
	ok := true
	for s in g_order {
		if !write_record('E', s.json) {
			ok = false
			break
		}
	}
	if !ok || os.sync(g_fd) != nil {
		fmt.eprintln("[relay] compact failed; keeping original log")
		os.close(g_fd)
		_ = os.remove(tmp)
		reopen_for_append()
		return
	}
	os.close(g_fd)
	if os.rename(tmp, g_log_path) != nil do fmt.eprintln("[relay] compact: rename failed; log may be stale")
	fmt.printfln("[relay] compacted: %d live event(s), %d tombstone(s) dropped", len(g_order), g_tombs)
	g_tombs = 0
	reopen_for_append()
}

// -- store_event -------------------------------------------------------
//
// Log first, memory second: every mutation appends its records and
// fsyncs before the maps change, so memory never claims what the disk
// could lose.

store_event :: proc(ev: ^Event) -> (ok: bool, message: string) {
	sync.lock(&g_mu)
	defer sync.unlock(&g_mu)

	if _, have := g_events[ev.id]; have {
		return true, "duplicate: already have this event"
	}

	// Replaceable/addressable: reject if we hold a newer (or same-age,
	// lower-id) version; otherwise the older one is superseded.
	supersede: ^Stored
	if is_replaceable(ev.kind) || is_addressable(ev.kind) {
		d := is_addressable(ev.kind) ? d_tag(ev) : ""
		for s in g_order {
			if s.pubkey != ev.pubkey || s.kind != ev.kind do continue
			if is_addressable(ev.kind) && s.d != d do continue
			if s.created_at > ev.created_at || (s.created_at == ev.created_at && s.id < ev.id) {
				return true, "duplicate: have a newer version"
			}
			supersede = s
		}
	}

	// NIP-09: collect victims first; the deletion event itself stores too.
	victims := make([dynamic]^Stored, context.temp_allocator)
	if ev.kind == 5 {
		for tag in ev.tags {
			if len(tag) < 2 do continue
			if tag[0] == "e" {
				if s, have := g_events[tag[1]]; have && s.pubkey == ev.pubkey && s.kind != 5 {
					append(&victims, s)
				}
			} else if tag[0] == "a" {
				parts := strings.split(tag[1], ":", context.temp_allocator)
				if len(parts) != 3 || parts[1] != ev.pubkey do continue
				for s in g_order {
					if s.pubkey != ev.pubkey do continue
					if fmt.tprintf("%d", s.kind) != parts[0] do continue
					if s.d != parts[2] || s.created_at > ev.created_at do continue
					append(&victims, s)
				}
			}
		}
	}

	wire := event_json(ev)
	if supersede != nil && !write_record('T', supersede.id) {
		return false, "error: storage failure"
	}
	for s in victims {
		if !write_record('T', s.id) do return false, "error: storage failure"
	}
	if !write_record('E', wire) do return false, "error: storage failure"
	if !sync_log() do return false, "error: storage failure"

	if supersede != nil do evict(supersede)
	for s in victims do evict(s)
	_ = intern(ev, wire)
	return true, ""
}

// -- query_filter ------------------------------------------------------

Stored_Event :: struct {
	id:   string,
	json: string,
}

DEFAULT_LIMIT :: 500

@(private = "file")
matches :: proc(s: ^Stored, f: ^Filter) -> bool {
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

// Results newest-first (created_at DESC, id ASC), temp-allocated - the
// same contract the SQL version kept.
query_filter :: proc(f: ^Filter) -> []Stored_Event {
	sync.lock(&g_mu)
	defer sync.unlock(&g_mu)

	hits := make([dynamic]^Stored, context.temp_allocator)
	for s in g_order {
		if matches(s, f) do append(&hits, s)
	}
	slice.sort_by(hits[:], proc(a, b: ^Stored) -> bool {
		if a.created_at != b.created_at do return a.created_at > b.created_at
		return a.id < b.id
	})

	limit := int(f.limit > 0 ? f.limit : DEFAULT_LIMIT)
	if len(hits) > limit do resize(&hits, limit)

	out := make([]Stored_Event, len(hits), context.temp_allocator)
	for s, i in hits {
		out[i] = {id = strings.clone(s.id, context.temp_allocator), json = strings.clone(s.json, context.temp_allocator)}
	}
	return out
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
	next := make(map[string]bool)
	{
		sync.lock(&g_mu)
		defer sync.unlock(&g_mu)
		for s in g_order {
			if s.kind != ALLOWLIST_KIND do continue
			if !(s.pubkey in g_allowed) do continue
			for t in s.tags {
				if t[0] == "p" && is_hex64(t[1]) do next[strings.clone(t[1])] = true
			}
		}
	}
	sync.lock(&g_dynamic_mu)
	old := g_dynamic
	g_dynamic = next
	sync.unlock(&g_dynamic_mu)
	if old != nil {
		for k, _ in old do delete_key(&old, k)
		delete(old)
	}
	fmt.printfln("[relay] dynamic allowlist: %d pubkey(s)", len(next))
}
