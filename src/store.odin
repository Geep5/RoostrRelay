package relay

// SQLite storage behind a narrow seam: store_event / query_filter /
// delete-by-request. Hand bindings against the stable C API (12 calls).
// One process-wide write path serialized under g_db_mu; WAL mode keeps
// this workable. (Single connection, single mutex - at Roostr scale the
// reader/writer split is premature; the seam makes it a later upgrade,
// and the same seam is where a libsql/Turso swap would happen.)

import "core:c"
import "core:fmt"
import "core:os"
import "core:strings"
import "core:sync"

foreign import sq "system:sqlite3"

SQLITE_OK :: 0
SQLITE_ROW :: 100
SQLITE_DONE :: 101
SQLITE_OPEN_READWRITE :: 0x02
SQLITE_OPEN_CREATE :: 0x04
SQLITE_TRANSIENT := rawptr(~uintptr(0))

foreign sq {
	sqlite3_open_v2 :: proc "c" (filename: cstring, db: ^rawptr, flags: c.int, vfs: cstring) -> c.int ---
	sqlite3_close :: proc "c" (db: rawptr) -> c.int ---
	sqlite3_exec :: proc "c" (db: rawptr, sql: cstring, cb: rawptr, arg: rawptr, errmsg: ^cstring) -> c.int ---
	sqlite3_prepare_v2 :: proc "c" (db: rawptr, sql: cstring, nbyte: c.int, stmt: ^rawptr, tail: ^cstring) -> c.int ---
	sqlite3_bind_text :: proc "c" (stmt: rawptr, idx: c.int, text: [^]u8, nbyte: c.int, destructor: rawptr) -> c.int ---
	sqlite3_bind_int64 :: proc "c" (stmt: rawptr, idx: c.int, value: i64) -> c.int ---
	sqlite3_step :: proc "c" (stmt: rawptr) -> c.int ---
	sqlite3_column_text :: proc "c" (stmt: rawptr, col: c.int) -> cstring ---
	sqlite3_column_int64 :: proc "c" (stmt: rawptr, col: c.int) -> i64 ---
	sqlite3_finalize :: proc "c" (stmt: rawptr) -> c.int ---
	sqlite3_errmsg :: proc "c" (db: rawptr) -> cstring ---
	sqlite3_changes :: proc "c" (db: rawptr) -> c.int ---
}

g_db: rawptr
g_db_mu: sync.Mutex

SCHEMA :: `
PRAGMA journal_mode = WAL;
PRAGMA synchronous  = NORMAL;
PRAGMA busy_timeout = 5000;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS events (
  id          TEXT PRIMARY KEY,
  pubkey      TEXT NOT NULL,
  created_at  INTEGER NOT NULL,
  kind        INTEGER NOT NULL,
  tags        TEXT NOT NULL,
  content     TEXT NOT NULL,
  sig         TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tags (
  event_id    TEXT NOT NULL REFERENCES events(id) ON DELETE CASCADE,
  name        TEXT NOT NULL,
  value       TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_created ON events(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_events_kind    ON events(kind, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_events_pubkey  ON events(pubkey, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_tags_lookup    ON tags(name, value, event_id);
`

store_open :: proc(path: string) {
	cpath := strings.clone_to_cstring(path)
	rc := sqlite3_open_v2(cpath, &g_db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nil)
	if rc != SQLITE_OK {
		fmt.eprintln("[relay] sqlite open failed:", path)
		os.exit(1)
	}
	errmsg: cstring
	if sqlite3_exec(g_db, SCHEMA, nil, nil, &errmsg) != SQLITE_OK {
		fmt.eprintln("[relay] schema failed:", errmsg)
		os.exit(1)
	}
}

// -- Small statement helpers ------------------------------------------

prep :: proc(sql: string) -> (rawptr, bool) {
	stmt: rawptr
	csql := strings.clone_to_cstring(sql, context.temp_allocator)
	if sqlite3_prepare_v2(g_db, csql, -1, &stmt, nil) != SQLITE_OK {
		fmt.eprintln("[relay] prepare failed:", sqlite3_errmsg(g_db), "sql:", sql)
		return nil, false
	}
	return stmt, true
}

g_empty_byte: [1]u8

bind_str :: proc(stmt: rawptr, idx: int, s: string) {
	// raw_data("") is nil, and sqlite3_bind_text(NULL) binds SQL NULL
	// no matter what nbyte says - route empty strings through a real
	// pointer so they stay TEXT ''.
	data := raw_data(s)
	if data == nil do data = &g_empty_byte[0]
	sqlite3_bind_text(stmt, c.int(idx), data, c.int(len(s)), SQLITE_TRANSIENT)
}

exec_simple :: proc(sql: string) -> bool {
	errmsg: cstring
	csql := strings.clone_to_cstring(sql, context.temp_allocator)
	return sqlite3_exec(g_db, csql, nil, nil, &errmsg) == SQLITE_OK
}

// -- store_event ------------------------------------------------------
//
// Kind routing (ephemeral is handled before we get here):
//   0, 3, 10000-19999          replaceable: newest per (pubkey, kind)
//   30000-39999                addressable: newest per (pubkey, kind, d)
//   5                          NIP-09 deletion request
//   everything else            regular insert

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

store_event :: proc(ev: ^Event) -> (ok: bool, message: string) {
	sync.lock(&g_db_mu)
	defer sync.unlock(&g_db_mu)

	// Duplicate check up front - cheapest path, and the OK message
	// convention lets clients distinguish it.
	{
		stmt, pok := prep("SELECT 1 FROM events WHERE id = ?")
		if !pok do return false, "error: storage failure"
		bind_str(stmt, 1, ev.id)
		dup := sqlite3_step(stmt) == SQLITE_ROW
		sqlite3_finalize(stmt)
		if dup do return true, "duplicate: already have this event"
	}

	// Replaceable/addressable: reject if we hold a newer (or same-age,
	// lower-id) version; otherwise delete the older one inside the tx.
	supersede_id := ""
	if is_replaceable(ev.kind) || is_addressable(ev.kind) {
		d := is_addressable(ev.kind) ? d_tag(ev) : ""
		sql := `SELECT id, created_at FROM events WHERE pubkey = ?1 AND kind = ?2`
		if is_addressable(ev.kind) {
			sql = `SELECT e.id, e.created_at FROM events e
			 WHERE e.pubkey = ?1 AND e.kind = ?2
			   AND EXISTS (SELECT 1 FROM tags t WHERE t.event_id = e.id AND t.name = 'd' AND t.value = ?3)`
		}
		stmt, pok := prep(sql)
		if !pok do return false, "error: storage failure"
		bind_str(stmt, 1, ev.pubkey)
		sqlite3_bind_int64(stmt, 2, ev.kind)
		if is_addressable(ev.kind) do bind_str(stmt, 3, d)
		for sqlite3_step(stmt) == SQLITE_ROW {
			old_id := strings.clone_from_cstring(sqlite3_column_text(stmt, 0), context.temp_allocator)
			old_at := sqlite3_column_int64(stmt, 1)
			if old_at > ev.created_at || (old_at == ev.created_at && old_id < ev.id) {
				sqlite3_finalize(stmt)
				return true, "duplicate: have a newer version"
			}
			supersede_id = old_id
		}
		sqlite3_finalize(stmt)
	}

	if !exec_simple("BEGIN IMMEDIATE") do return false, "error: storage busy"
	committed := false
	defer if !committed do exec_simple("ROLLBACK")

	if supersede_id != "" {
		stmt, pok := prep("DELETE FROM events WHERE id = ?")
		if !pok do return false, "error: storage failure"
		bind_str(stmt, 1, supersede_id)
		sqlite3_step(stmt)
		sqlite3_finalize(stmt)
	}

	{
		stmt, pok := prep("INSERT INTO events (id, pubkey, created_at, kind, tags, content, sig) VALUES (?,?,?,?,?,?,?)")
		if !pok do return false, "error: storage failure"
		bind_str(stmt, 1, ev.id)
		bind_str(stmt, 2, ev.pubkey)
		sqlite3_bind_int64(stmt, 3, ev.created_at)
		sqlite3_bind_int64(stmt, 4, ev.kind)
		bind_str(stmt, 5, ev.tags_json)
		bind_str(stmt, 6, ev.content)
		bind_str(stmt, 7, ev.sig)
		rc := sqlite3_step(stmt)
		sqlite3_finalize(stmt)
		if rc != SQLITE_DONE {
			fmt.eprintln("[relay] insert failed:", sqlite3_errmsg(g_db))
			return false, "error: insert failed"
		}
	}

	// Single-letter tags into the index table.
	for tag in ev.tags {
		if len(tag) < 2 || len(tag[0]) != 1 do continue
		ch := tag[0][0]
		if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z') do continue
		stmt, pok := prep("INSERT INTO tags (event_id, name, value) VALUES (?,?,?)")
		if !pok do return false, "error: storage failure"
		bind_str(stmt, 1, ev.id)
		bind_str(stmt, 2, tag[0])
		bind_str(stmt, 3, tag[1])
		sqlite3_step(stmt)
		sqlite3_finalize(stmt)
	}

	// NIP-09: deletion request. Only the author's own events die.
	if ev.kind == 5 {
		for tag in ev.tags {
			if len(tag) < 2 do continue
			if tag[0] == "e" {
				stmt, pok := prep("DELETE FROM events WHERE id = ? AND pubkey = ? AND kind != 5")
				if !pok do continue
				bind_str(stmt, 1, tag[1])
				bind_str(stmt, 2, ev.pubkey)
				sqlite3_step(stmt)
				sqlite3_finalize(stmt)
			} else if tag[0] == "a" {
				// kind:pubkey:d - addressable delete, same author only.
				parts := strings.split(tag[1], ":", context.temp_allocator)
				if len(parts) != 3 || parts[1] != ev.pubkey do continue
				stmt, pok := prep(
					`DELETE FROM events WHERE pubkey = ?1 AND kind = ?2 AND created_at <= ?3
					   AND EXISTS (SELECT 1 FROM tags t WHERE t.event_id = events.id AND t.name = 'd' AND t.value = ?4)`)
				if !pok do continue
				bind_str(stmt, 1, ev.pubkey)
				bind_str(stmt, 2, parts[0]) // sqlite coerces numeric text
				sqlite3_bind_int64(stmt, 3, ev.created_at)
				bind_str(stmt, 4, parts[2])
				sqlite3_step(stmt)
				sqlite3_finalize(stmt)
			}
		}
	}

	if !exec_simple("COMMIT") do return false, "error: commit failed"
	committed = true
	return true, ""
}

// -- query_filter -----------------------------------------------------

Stored_Event :: struct {
	id:   string,
	json: string,
}

DEFAULT_LIMIT :: 500

// Builds one parameterized SELECT per filter. Values are always bound,
// never spliced. Results newest-first, temp-allocated.
query_filter :: proc(f: ^Filter) -> []Stored_Event {
	sb := strings.builder_make(context.temp_allocator)
	strings.write_string(&sb, "SELECT id, pubkey, created_at, kind, tags, content, sig FROM events WHERE 1=1")

	str_args := make([dynamic]string, context.temp_allocator)
	int_args := make([dynamic]i64, context.temp_allocator)
	arg_order := make([dynamic]u8, context.temp_allocator) // 's' or 'i'

	in_list :: proc(sb: ^strings.Builder, col: string, n: int) {
		strings.write_string(sb, " AND ")
		strings.write_string(sb, col)
		strings.write_string(sb, " IN (")
		for i in 0 ..< n {
			if i > 0 do strings.write_byte(sb, ',')
			strings.write_byte(sb, '?')
		}
		strings.write_byte(sb, ')')
	}

	if len(f.ids) > 0 {
		in_list(&sb, "id", len(f.ids))
		for v in f.ids { append(&str_args, v); append(&arg_order, 's') }
	}
	if len(f.authors) > 0 {
		in_list(&sb, "pubkey", len(f.authors))
		for v in f.authors { append(&str_args, v); append(&arg_order, 's') }
	}
	if len(f.kinds) > 0 {
		in_list(&sb, "kind", len(f.kinds))
		for v in f.kinds { append(&int_args, v); append(&arg_order, 'i') }
	}
	if f.since != 0 {
		strings.write_string(&sb, " AND created_at >= ?")
		append(&int_args, f.since); append(&arg_order, 'i')
	}
	if f.until != 0 {
		strings.write_string(&sb, " AND created_at <= ?")
		append(&int_args, f.until); append(&arg_order, 'i')
	}
	for tf in f.tags {
		strings.write_string(&sb, " AND EXISTS (SELECT 1 FROM tags t WHERE t.event_id = events.id AND t.name = ? AND t.value IN (")
		for i in 0 ..< len(tf.values) {
			if i > 0 do strings.write_byte(&sb, ',')
			strings.write_byte(&sb, '?')
		}
		strings.write_string(&sb, "))")
		append(&str_args, tf.name); append(&arg_order, 's')
		for v in tf.values { append(&str_args, v); append(&arg_order, 's') }
	}

	limit := f.limit > 0 ? f.limit : DEFAULT_LIMIT
	strings.write_string(&sb, " ORDER BY created_at DESC, id ASC LIMIT ?")
	append(&int_args, limit); append(&arg_order, 'i')

	sync.lock(&g_db_mu)
	defer sync.unlock(&g_db_mu)

	stmt, pok := prep(strings.to_string(sb))
	if !pok do return {}
	si, ii := 0, 0
	for kind, i in arg_order {
		if kind == 's' {
			bind_str(stmt, i + 1, str_args[si]); si += 1
		} else {
			sqlite3_bind_int64(stmt, c.int(i + 1), int_args[ii]); ii += 1
		}
	}

	out := make([dynamic]Stored_Event, context.temp_allocator)
	for sqlite3_step(stmt) == SQLITE_ROW {
		ev: Event
		ev.id = strings.clone_from_cstring(sqlite3_column_text(stmt, 0), context.temp_allocator)
		ev.pubkey = strings.clone_from_cstring(sqlite3_column_text(stmt, 1), context.temp_allocator)
		ev.created_at = sqlite3_column_int64(stmt, 2)
		ev.kind = sqlite3_column_int64(stmt, 3)
		ev.tags_json = strings.clone_from_cstring(sqlite3_column_text(stmt, 4), context.temp_allocator)
		ev.content = strings.clone_from_cstring(sqlite3_column_text(stmt, 5), context.temp_allocator)
		ev.sig = strings.clone_from_cstring(sqlite3_column_text(stmt, 6), context.temp_allocator)
		append(&out, Stored_Event{id = ev.id, json = event_json(&ev)})
	}
	sqlite3_finalize(stmt)
	return out[:]
}
