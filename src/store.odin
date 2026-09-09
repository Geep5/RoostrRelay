package relay

// Durable append-only log. Legacy E (event) and T (event-id tombstone)
// records remain readable. New A records commit one complete logical event
// operation: its authorized deletions/supersession and insertion replay together.
// Framing: [type:u8][length:u32le][payload][crc32:u32le]. A checksums header
// plus payload; legacy E/T checksum only payload, exactly as before.
// Incomplete EOF is recoverable; corrupt complete records are never discarded.
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
	tags:       [][2]string, // single-letter tags only (the indexed set)
	json:       string, // wire JSON, echoed verbatim by REQ
	idx:        int, // position in g_order (swap-remove bookkeeping)
}

g_events: map[string]^Stored
g_order: [dynamic]^Stored
g_tombs: int // tombstoned records currently wasting log bytes

MAX_RECORD :: MAX_MESSAGE // same bound for acceptance, new writes and legacy replay
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

write_full :: proc(fd: ^os.File, data: []u8) -> bool {
	off := 0
	for off < len(data) {
		n, err := os.write(fd, data[off:])
		if err != nil || n <= 0 do return false
		off += n
	}
	return true
}

write_record_to :: proc(fd: ^os.File, type: u8, payload: string) -> bool {
	if len(payload) <= 0 || len(payload) > MAX_RECORD do return false
	head: [5]u8
	head[0] = type
	n := u32(len(payload))
	for i in 0..<4 do head[i+1] = u8(n >> uint(8*i))
	seed := type == 'A' ? hash.crc32(head[:]) : u32(0)
	crc := hash.crc32(transmute([]u8)payload, seed)
	tail: [4]u8
	for i in 0..<4 do tail[i] = u8(crc >> uint(8*i))
	return write_full(fd, head[:]) && write_full(fd, transmute([]u8)payload) && write_full(fd, tail[:])
}

append_operation :: proc(wire: string) -> bool {
	if g_append_failed || g_fd == nil do return false
	if !write_record_to(g_fd, 'A', wire) || os.sync(g_fd) != nil {
		// Never append beyond a possibly partial/unsynced operation. Restart
		// replays the file before any writer may use it again.
		g_append_failed = true
		return false
	}
	return true
}

remember_deleted :: proc(id: string) {
	if !(id in g_deleted) do g_deleted[strings.clone(id)] = true
}

// -- In-memory index ---------------------------------------------------

@(private)
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
	have_d := false
	for tag in ev.tags {
		if len(tag) >= 2 && len(tag[0]) == 1 {
			ch := tag[0][0]
			if ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' {
				s.tags[i] = {strings.clone(tag[0]), strings.clone(tag[1])}
				if tag[0] == "d" && !have_d {
					s.d = s.tags[i][1]
					have_d = true
				}
				i += 1
			}
		}
	}

	s.idx = len(g_order)
	append(&g_order, s)
	g_events[s.id] = s
	return s
}

@(private)
evict :: proc(s: ^Stored) {
	remember_deleted(s.id)
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
	g_deleted = make(map[string]bool)
	g_append_failed = false
	data, rerr := os.read_entire_file_from_path(path, context.allocator)
	if rerr == nil {
		defer delete(data)
		good, status := replay(data)
		if status == .Corrupt {
			fmt.eprintfln("[relay] FATAL: corrupt log at offset %d; original file untouched", good)
			os.exit(1)
		}
		if status == .Incomplete && !replace_log(data[:good], false) {
			fmt.eprintln("[relay] FATAL: cannot durably recover incomplete log tail")
			os.exit(1)
		}
	} else if rerr != os.Error(os.General_Error.Not_Exist) {
		fmt.eprintln("[relay] FATAL: cannot read log:", rerr)
		os.exit(1)
	}
	if g_tombs >= COMPACT_MIN_TOMBS && !compact() {
		fmt.eprintln("[relay] FATAL: compaction failed; refusing to append")
		os.exit(1)
	}
	reopen_for_append()
	fmt.printfln("[relay] store: %d live events, %d retained deleted IDs", len(g_order), len(g_deleted))
}

Record_Status :: enum { Complete, Incomplete, Corrupt }

decode_record :: proc(data: []u8) -> (type: u8, payload: []u8, size: int, status: Record_Status) {
	if len(data) == 0 do return 0, nil, 0, .Incomplete
	type = data[0]
	if type != 'E' && type != 'T' && type != 'A' do return type, nil, 0, .Corrupt
	if len(data) < 5 do return type, nil, 0, .Incomplete
	n := int(data[1]) | int(data[2]) << 8 | int(data[3]) << 16 | int(data[4]) << 24
	if n <= 0 || n > MAX_RECORD || (type == 'T' && n != 64) do return type, nil, 0, .Corrupt
	size = n + 9
	if size > len(data) do return type, nil, size, .Incomplete
	payload = data[5:5+n]
	c := data[5+n:size]
	want := u32(c[0]) | u32(c[1]) << 8 | u32(c[2]) << 16 | u32(c[3]) << 24
	seed := type == 'A' ? hash.crc32(data[:5]) : u32(0)
	if hash.crc32(payload, seed) != want do return type, payload, size, .Corrupt
	return type, payload, size, .Complete
}

replay :: proc(data: []u8) -> (good: int, status: Record_Status) {
	// Reclaim parse trees after each record, not after the entire log.
	arena: mem.Dynamic_Arena
	mem.dynamic_arena_init(&arena)
	defer mem.dynamic_arena_destroy(&arena)
	context.temp_allocator = mem.dynamic_arena_allocator(&arena)
	for good < len(data) {
		type, payload, size, record_status := decode_record(data[good:])
		if record_status == .Incomplete {
			// A damaged length must not cause a valid suffix to be discarded.
			// Any complete CRC-valid frame beyond the failure is ambiguous:
			// preserve the whole file and require operator recovery instead.
			for i := good+1; i+9 <= len(data); i += 1 {
				_, _, _, suffix_status := decode_record(data[i:])
				if suffix_status == .Complete do return good, .Corrupt
			}
			return good, .Incomplete
		}
		if record_status == .Corrupt do return good, .Corrupt
		if type == 'T' {
			if !is_hex64(string(payload)) do return good, .Corrupt
			remember_deleted(string(payload))
			if s, have := g_events[string(payload)]; have do evict(s)
		} else {
			v, jerr := json.parse(payload, .JSON, false, context.temp_allocator)
			if jerr != nil do return good, .Corrupt
			ev, perr := parse_event(v)
			if perr != "" do return good, .Corrupt
			if type == 'A' {
				victims, message, _ := plan_operation(&ev)
				if message == "" do apply_operation(&ev, string(payload), victims[:])
			} else if !(ev.id in g_events) && !(ev.id in g_deleted) {
				_ = intern(&ev, string(payload))
			}
		}
		good += size
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
replace_log :: proc(prefix: []u8, compacting: bool) -> bool {
	tmp := fmt.tprintf("%s.tmp", g_log_path)
	fd, err := os.open(tmp, {.Write, .Create, .Trunc}, os.Permissions_Default_File)
	if err != nil do return false
	ok := true
	if compacting {
		for id in g_deleted {
			if !write_record_to(fd, 'T', id) { ok = false; break }
		}
		if ok {
			for s in g_order {
				if !write_record_to(fd, 'E', s.json) { ok = false; break }
			}
		}
	} else {
		ok = write_full(fd, prefix)
	}
	if ok do ok = os.sync(fd) == nil
	if os.close(fd) != nil do ok = false
	if !ok { _ = os.remove(tmp); return false }
	if os.rename(tmp, g_log_path) != nil { _ = os.remove(tmp); return false }
	return sync_log_directory()
}

reopen_for_append :: proc() {
	fd, err := os.open(g_log_path, {.Write, .Create, .Append}, os.Permissions_Default_File)
	if err != nil {
		fmt.eprintln("[relay] FATAL: cannot open log for append:", err)
		os.exit(1)
	}
	g_fd = fd
	if os.sync(fd) != nil || !sync_log_directory() {
		fmt.eprintln("[relay] FATAL: cannot sync log and directory")
		os.exit(1)
	}
}

compact :: proc() -> bool {
	if !replace_log(nil, true) do return false
	g_tombs = 0
	return true
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

plan_operation :: proc(ev: ^Event) -> (victims: [dynamic]^Stored, message: string, rejected: bool) {
	if ev.id in g_events do return nil, "duplicate: already have this event", false
	if ev.id in g_deleted do return nil, "blocked: event was deleted", true
	for deletion in g_order {
		if deletion.kind != 5 || deletion.pubkey != ev.pubkey do continue
		for tag in deletion.tags {
			if deletion_tag_matches(tag[0], tag[1], deletion.pubkey, deletion.created_at, ev.id, ev.pubkey, ev.kind, d_tag(ev), ev.created_at) {
				return nil, "blocked: event was deleted", true
			}
		}
	}
	victims = make([dynamic]^Stored, context.temp_allocator)
	d := is_addressable(ev.kind) ? d_tag(ev) : ""
	// Visit each stored event exactly once. Repeated e/a tags can never
	// produce duplicate pointers (and therefore cannot double-free victims).
	for s in g_order {
		victim := false
		if (is_replaceable(ev.kind) || is_addressable(ev.kind)) && s.pubkey == ev.pubkey && s.kind == ev.kind && (!is_addressable(ev.kind) || s.d == d) {
			if s.created_at > ev.created_at || (s.created_at == ev.created_at && s.id < ev.id) {
				return victims, "duplicate: have a newer version", false
			}
			victim = true
		}
		if ev.kind == 5 {
			for tag in ev.tags {
				if len(tag) >= 2 && deletion_tag_matches(tag[0], tag[1], ev.pubkey, ev.created_at, s.id, s.pubkey, s.kind, s.d, s.created_at) {
					victim = true
					break
				}
			}
		}
		if victim do append(&victims, s)
	}
	return victims, "", false
}

apply_operation :: proc(ev: ^Event, wire: string, victims: []^Stored) {
	for s in victims do evict(s)
	_ = intern(ev, wire)
}

store_event :: proc(ev: ^Event) -> (ok: bool, message: string) {
	sync.lock(&g_mu)
	defer sync.unlock(&g_mu)
	if g_append_failed do return false, "error: storage requires recovery"
	// A revocation may have committed while signature verification ran.
	if !event_write_allowed(ev) do return false, "restricted: pubkey not on the allowlist"
	wire := event_json(ev)
	if len(wire) > MAX_RECORD do return false, "invalid: serialized event too large"
	victims, msg, rejected := plan_operation(ev)
	if msg != "" do return !rejected, msg
	if !append_operation(wire) do return false, "error: storage failure"
	apply_operation(ev, wire, victims[:])
	if ev.kind == 5 || ev.kind == ALLOWLIST_KIND do refresh_dynamic_allowlist_locked()
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

MAX_QUERY_BYTES :: 8 << 20
// Includes escaped subscription ID, EVENT envelope, copied ID and metadata.
QUERY_ROW_OVERHEAD :: 512

stored_before :: proc(a, b: ^Stored) -> bool {
	if a.created_at != b.created_at do return a.created_at > b.created_at
	return a.id < b.id
}

// A worst-first heap retains at most MAX_LIMIT pointers regardless of total
// matches. Clone only a byte-budgeted prefix after sorting those candidates.
query_filter :: proc(f: ^Filter, byte_budget := MAX_QUERY_BYTES) -> (rows: []Stored_Event, exhausted: bool) {
	sync.lock(&g_mu)
	defer sync.unlock(&g_mu)
	limit := int(f.has_limit || f.limit > 0 ? f.limit : DEFAULT_LIMIT)
	limit = clamp(limit, 0, MAX_LIMIT)
	if limit == 0 do return nil, false
	storage: [MAX_LIMIT]^Stored
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
		rows[i] = {id = strings.clone(s.id, context.temp_allocator), json = strings.clone(s.json, context.temp_allocator)}
	}
	return rows, exhausted
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
