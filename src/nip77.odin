package relay

// NIP-77 negentropy sync: NEG-OPEN / NEG-MSG / NEG-CLOSE around the
// responder in negentropy.odin. A session snapshots the sorted (created_at,
// id) set of every stored event matching its filter at NEG-OPEN, so later
// rounds reconcile against a stable set. Session ids are a namespace separate
// from REQ. Sessions belong to the connection's reader thread (dispatch and
// teardown), so they need no lock.

import "core:encoding/hex"
import "core:fmt"
import "core:encoding/json"
import "core:strings"

MAX_NEG_SESSIONS_PER_CONN :: 8
MAX_NEG_ITEMS :: 500_000

Neg_Session :: struct {
	items: []Neg_Item, // sorted, owned (context.allocator)
}

send_neg :: proc(c: ^Conn, verb, sub_id, payload: string) {
	sb := strings.builder_make(context.temp_allocator)
	strings.write_string(&sb, `["`)
	strings.write_string(&sb, verb)
	strings.write_string(&sb, `",`)
	canon_escape(&sb, sub_id)
	strings.write_byte(&sb, ',')
	canon_escape(&sb, payload)
	strings.write_byte(&sb, ']')
	ws_send_text(c, strings.to_string(sb))
}

neg_close :: proc(c: ^Conn, sub_id: string) {
	if !(sub_id in c.negs) do return
	key, session := delete_key(&c.negs, sub_id)
	delete(key)
	delete(session.items)
}

neg_close_all :: proc(c: ^Conn) {
	for key, session in c.negs {
		delete(key)
		delete(session.items)
	}
	delete(c.negs)
}

// Runs one round and answers NEG-MSG; on malformed input the session closes.
neg_answer :: proc(c: ^Conn, sub_id: string, items: []Neg_Item, message_hex: string) -> bool {
	query, ok := hex.decode(transmute([]byte)message_hex, context.temp_allocator)
	if !ok {
		send_neg(c, "NEG-ERR", sub_id, "invalid: message is not hex")
		return false
	}
	out, err := neg_reconcile(items, query, NEG_FRAME_SIZE_LIMIT)
	if err != "" {
		send_neg(c, "NEG-ERR", sub_id, fmt.tprintf("invalid: %s", err))
		return false
	}
	send_neg(c, "NEG-MSG", sub_id, string(hex.encode(out, context.temp_allocator)))
	return true
}

handle_neg_open :: proc(c: ^Conn, sub_id: string, filter_value: json.Value, message_hex: string) {
	neg_close(c, sub_id) // NIP-77: reopening an id closes the old session first
	f, fok := parse_filter(filter_value)
	if !fok {
		send_neg(c, "NEG-ERR", sub_id, "invalid: bad filter")
		return
	}
	if f.has_after && f.stream == "" {
		send_neg(c, "NEG-ERR", sub_id, "invalid: after needs one stream")
		return
	}
	if len(c.negs) >= MAX_NEG_SESSIONS_PER_CONN {
		send_neg(c, "NEG-ERR", sub_id, fmt.tprintf("blocked: at most %d negentropy sessions per connection", MAX_NEG_SESSIONS_PER_CONN))
		return
	}
	items, iok := neg_collect(&f, MAX_NEG_ITEMS)
	if !iok {
		send_neg(c, "NEG-ERR", sub_id, fmt.tprintf("blocked: filter matches more than %d events; narrow it", MAX_NEG_ITEMS))
		return
	}
	if !neg_answer(c, sub_id, items, message_hex) {
		delete(items)
		return
	}
	c.negs[strings.clone(sub_id)] = Neg_Session{items = items}
}

handle_neg_msg :: proc(c: ^Conn, sub_id: string, message_hex: string) {
	session, ok := c.negs[sub_id]
	if !ok {
		send_neg(c, "NEG-ERR", sub_id, "closed: no open negentropy session with this id")
		return
	}
	if !neg_answer(c, sub_id, session.items, message_hex) do neg_close(c, sub_id)
}
