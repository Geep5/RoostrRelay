package relay

// NIP-01 protocol: event parsing, canonical ID serialization, filters,
// message dispatch. NIP-09 deletion, kind semantics routing.
//
// The event ID is sha256 over the byte-exact canonical serialization
// [0,pubkey,created_at,kind,tags,content]. core:encoding/json is used
// for PARSING only - the canonical form is hand-rolled because the
// escape set is fixed by the NIP (\n \" \\ \r \t \b \f, everything
// else verbatim) and any general marshaller will diverge.

import "core:crypto/sha2"
import "core:encoding/hex"
import "core:encoding/json"
import "core:fmt"
import "core:strings"

Event :: struct {
	id:         string,
	pubkey:     string,
	created_at: i64,
	kind:       i64,
	tags:       [][]string,
	content:    string,
	sig:        string,
	tags_json:  string, // canonical serialization, stored + echoed verbatim
}

Tag_Filter :: struct {
	name:   string, // single letter
	values: []string,
}

Filter :: struct {
	ids:     []string,
	authors: []string,
	kinds:   []i64,
	tags:    []Tag_Filter,
	since:   i64, // 0 = unset
	until:   i64, // 0 = unset
	limit:   i64, // 0 = unset
}

// -- Canonical serialization ------------------------------------------

canon_escape :: proc(sb: ^strings.Builder, s: string) {
	strings.write_byte(sb, '"')
	for i in 0 ..< len(s) {
		c := s[i]
		switch c {
		case '\n': strings.write_string(sb, "\\n")
		case '"':  strings.write_string(sb, "\\\"")
		case '\\': strings.write_string(sb, "\\\\")
		case '\r': strings.write_string(sb, "\\r")
		case '\t': strings.write_string(sb, "\\t")
		case 0x08: strings.write_string(sb, "\\b")
		case 0x0C: strings.write_string(sb, "\\f")
		case:      strings.write_byte(sb, c)
		}
	}
	strings.write_byte(sb, '"')
}

canon_tags :: proc(tags: [][]string, allocator := context.temp_allocator) -> string {
	sb := strings.builder_make(allocator)
	strings.write_byte(&sb, '[')
	for tag, i in tags {
		if i > 0 do strings.write_byte(&sb, ',')
		strings.write_byte(&sb, '[')
		for item, j in tag {
			if j > 0 do strings.write_byte(&sb, ',')
			canon_escape(&sb, item)
		}
		strings.write_byte(&sb, ']')
	}
	strings.write_byte(&sb, ']')
	return strings.to_string(sb)
}

// sha256 of [0,pubkey,created_at,kind,tags,content] -> lowercase hex.
compute_event_id :: proc(ev: ^Event) -> string {
	sb := strings.builder_make(context.temp_allocator)
	strings.write_string(&sb, "[0,")
	canon_escape(&sb, ev.pubkey)
	fmt.sbprintf(&sb, ",%d,%d,", ev.created_at, ev.kind)
	strings.write_string(&sb, ev.tags_json)
	strings.write_byte(&sb, ',')
	canon_escape(&sb, ev.content)
	strings.write_byte(&sb, ']')

	digest: [32]byte
	ctx: sha2.Context_256
	sha2.init_256(&ctx)
	sha2.update(&ctx, transmute([]byte)strings.to_string(sb))
	sha2.final(&ctx, digest[:])
	out, _ := hex.encode(digest[:], context.temp_allocator)
	return string(out)
}

// -- Parsing ----------------------------------------------------------

jstr :: proc(v: json.Value) -> (string, bool) {
	s, ok := v.(json.String)
	return string(s), ok
}

jint :: proc(v: json.Value) -> (i64, bool) {
	#partial switch n in v {
	case json.Integer: return i64(n), true
	case json.Float:   return i64(n), true
	}
	return 0, false
}

is_hex64 :: proc(s: string) -> bool {
	if len(s) != 64 do return false
	for c in s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') do return false
	}
	return true
}

parse_event :: proc(v: json.Value) -> (ev: Event, err: string) {
	obj, ok := v.(json.Object)
	if !ok do return {}, "invalid: event is not an object"

	if ev.id, ok = jstr(obj["id"]); !ok do return {}, "invalid: missing id"
	if ev.pubkey, ok = jstr(obj["pubkey"]); !ok do return {}, "invalid: missing pubkey"
	if ev.sig, ok = jstr(obj["sig"]); !ok do return {}, "invalid: missing sig"
	if ev.content, ok = jstr(obj["content"]); !ok do return {}, "invalid: missing content"
	if ev.created_at, ok = jint(obj["created_at"]); !ok do return {}, "invalid: missing created_at"
	if ev.kind, ok = jint(obj["kind"]); !ok do return {}, "invalid: missing kind"

	if !is_hex64(ev.id) do return {}, "invalid: id must be 64-char lowercase hex"
	if !is_hex64(ev.pubkey) do return {}, "invalid: pubkey must be 64-char lowercase hex"
	if len(ev.sig) != 128 do return {}, "invalid: sig must be 128-char hex"

	tags_v, has_tags := obj["tags"]
	if !has_tags do return {}, "invalid: missing tags"
	tags_arr, tok := tags_v.(json.Array)
	if !tok do return {}, "invalid: tags is not an array"

	tags := make([][]string, len(tags_arr), context.temp_allocator)
	for tv, i in tags_arr {
		inner, iok := tv.(json.Array)
		if !iok do return {}, "invalid: tag is not an array"
		tag := make([]string, len(inner), context.temp_allocator)
		for item, j in inner {
			s, sok := jstr(item)
			if !sok do return {}, "invalid: tag item is not a string"
			tag[j] = s
		}
		tags[i] = tag
	}
	ev.tags = tags
	ev.tags_json = canon_tags(tags)
	return ev, ""
}

parse_filter :: proc(v: json.Value) -> (f: Filter, ok: bool) {
	obj, is_obj := v.(json.Object)
	if !is_obj do return {}, false

	str_list :: proc(v: json.Value) -> ([]string, bool) {
		arr, aok := v.(json.Array)
		if !aok do return nil, false
		out := make([]string, len(arr), context.temp_allocator)
		for item, i in arr {
			s, sok := jstr(item)
			if !sok do return nil, false
			out[i] = s
		}
		return out, true
	}

	tag_filters := make([dynamic]Tag_Filter, context.temp_allocator)
	for key, val in obj {
		switch {
		case key == "ids":
			if f.ids, ok = str_list(val); !ok do return {}, false
		case key == "authors":
			if f.authors, ok = str_list(val); !ok do return {}, false
		case key == "kinds":
			arr, aok := val.(json.Array)
			if !aok do return {}, false
			f.kinds = make([]i64, len(arr), context.temp_allocator)
			for item, i in arr {
				n, nok := jint(item)
				if !nok do return {}, false
				f.kinds[i] = n
			}
		case key == "since":
			if f.since, ok = jint(val); !ok do return {}, false
		case key == "until":
			if f.until, ok = jint(val); !ok do return {}, false
		case key == "limit":
			if f.limit, ok = jint(val); !ok do return {}, false
		case len(key) == 2 && key[0] == '#':
			vals, vok := str_list(val)
			if !vok do return {}, false
			append(&tag_filters, Tag_Filter{name = key[1:], values = vals})
		}
	}
	f.tags = tag_filters[:]
	if f.limit > MAX_LIMIT do f.limit = MAX_LIMIT
	return f, true
}

// -- In-memory filter matching (live subscriptions) -------------------

match_filter :: proc(f: ^Filter, ev: ^Event) -> bool {
	if f.since != 0 && ev.created_at < f.since do return false
	if f.until != 0 && ev.created_at > f.until do return false

	if len(f.ids) > 0 {
		found := false
		for id in f.ids do if id == ev.id { found = true; break }
		if !found do return false
	}
	if len(f.authors) > 0 {
		found := false
		for a in f.authors do if a == ev.pubkey { found = true; break }
		if !found do return false
	}
	if len(f.kinds) > 0 {
		found := false
		for k in f.kinds do if k == ev.kind { found = true; break }
		if !found do return false
	}
	for tf in f.tags {
		found := false
		outer: for tag in ev.tags {
			if len(tag) >= 2 && tag[0] == tf.name {
				for v in tf.values do if v == tag[1] { found = true; break outer }
			}
		}
		if !found do return false
	}
	return true
}

match_any :: proc(filters: []Filter, ev: ^Event) -> bool {
	for &f in filters do if match_filter(&f, ev) do return true
	return false
}

// -- Wire helpers -----------------------------------------------------

// Rebuilds the event JSON from parts (canonical escaping, tags verbatim).
event_json :: proc(ev: ^Event, allocator := context.temp_allocator) -> string {
	sb := strings.builder_make(allocator)
	strings.write_string(&sb, `{"id":"`)
	strings.write_string(&sb, ev.id)
	strings.write_string(&sb, `","pubkey":"`)
	strings.write_string(&sb, ev.pubkey)
	fmt.sbprintf(&sb, `","created_at":%d,"kind":%d,"tags":`, ev.created_at, ev.kind)
	strings.write_string(&sb, ev.tags_json)
	strings.write_string(&sb, `,"content":`)
	canon_escape(&sb, ev.content)
	strings.write_string(&sb, `,"sig":"`)
	strings.write_string(&sb, ev.sig)
	strings.write_string(&sb, `"}`)
	return strings.to_string(sb)
}

send_ok :: proc(c: ^Conn, id: string, accepted: bool, message: string) {
	sb := strings.builder_make(context.temp_allocator)
	strings.write_string(&sb, `["OK",`)
	canon_escape(&sb, id)
	strings.write_string(&sb, accepted ? ",true," : ",false,")
	canon_escape(&sb, message)
	strings.write_byte(&sb, ']')
	ws_send_text(c, strings.to_string(sb))
}

send_notice :: proc(c: ^Conn, message: string) {
	sb := strings.builder_make(context.temp_allocator)
	strings.write_string(&sb, `["NOTICE",`)
	canon_escape(&sb, message)
	strings.write_byte(&sb, ']')
	ws_send_text(c, strings.to_string(sb))
}

send_closed :: proc(c: ^Conn, sub_id: string, message: string) {
	sb := strings.builder_make(context.temp_allocator)
	strings.write_string(&sb, `["CLOSED",`)
	canon_escape(&sb, sub_id)
	strings.write_byte(&sb, ',')
	canon_escape(&sb, message)
	strings.write_byte(&sb, ']')
	ws_send_text(c, strings.to_string(sb))
}

send_event :: proc(c: ^Conn, sub_id: string, ev_json: string) -> bool {
	sb := strings.builder_make(context.temp_allocator)
	strings.write_string(&sb, `["EVENT",`)
	canon_escape(&sb, sub_id)
	strings.write_byte(&sb, ',')
	strings.write_string(&sb, ev_json)
	strings.write_byte(&sb, ']')
	return ws_send_text(c, strings.to_string(sb))
}

// -- Dispatch ---------------------------------------------------------

MAX_CONTENT :: 900 * 1024 // leave frame headroom under MAX_MESSAGE
CREATED_AT_SLOP_FUTURE :: 15 * 60 // 15 min clock skew allowance
MAX_TAGS :: 4096

handle_message :: proc(c: ^Conn, raw: string) {
	parsed, perr := json.parse(transmute([]byte)raw, allocator = context.temp_allocator)
	if perr != nil {
		send_notice(c, "invalid: not JSON")
		return
	}
	arr, aok := parsed.(json.Array)
	if !aok || len(arr) < 1 {
		send_notice(c, "invalid: not a message array")
		return
	}
	verb, vok := jstr(arr[0])
	if !vok {
		send_notice(c, "invalid: message type must be a string")
		return
	}

	switch verb {
	case "EVENT":
		if len(arr) < 2 {
			send_notice(c, "invalid: EVENT needs an event")
			return
		}
		handle_event(c, arr[1])
	case "REQ":
		if len(arr) < 3 {
			send_notice(c, "invalid: REQ needs sub id and filter")
			return
		}
		sub_id, sok := jstr(arr[1])
		if !sok || len(sub_id) == 0 || len(sub_id) > 64 {
			send_notice(c, "invalid: bad subscription id")
			return
		}
		handle_req(c, sub_id, arr[2:])
	case "CLOSE":
		if len(arr) < 2 do return
		sub_id, sok := jstr(arr[1])
		if !sok do return
		sync.lock(&g_conns_mu)
		sub, exists := c.subs[sub_id]
		if exists do delete_key(&c.subs, sub_id)
		sync.unlock(&g_conns_mu)
		if exists do mem.dynamic_arena_destroy(&sub.arena)
	case:
		send_notice(c, fmt.tprintf("invalid: unknown message type %s", verb))
	}
}

handle_event :: proc(c: ^Conn, v: json.Value) {
	ev, perr := parse_event(v)
	if perr != "" {
		// No trustworthy id to reference; NOTICE is the best we can do
		// for a parse failure, OK for anything with a plausible id.
		if ev.id != "" do send_ok(c, ev.id, false, perr)
		else do send_notice(c, perr)
		return
	}

	// Policy before crypto: cheap checks first.
	// Strangers get two doors: (1) kind-1059 gift wraps ADDRESSED (p-tag)
	// to a resident pubkey - that's how join requests reach the owner -
	// and (2) membership in the dynamic allowlist, which resident keys
	// administer by publishing kind-30100 "roostr-allowlist" events.
	if len(g_allowed) > 0 && !write_allowed(ev.pubkey) {
		wrap_ok := false
		if ev.kind == 1059 {
			for tag in ev.tags {
				if len(tag) >= 2 && tag[0] == "p" && write_allowed(tag[1]) {
					wrap_ok = true
					break
				}
			}
		}
		if !wrap_ok {
			send_ok(c, ev.id, false, "restricted: pubkey not on the allowlist")
			return
		}
	}
	if len(ev.content) > MAX_CONTENT {
		send_ok(c, ev.id, false, "invalid: content too large")
		return
	}
	if len(ev.tags) > MAX_TAGS {
		send_ok(c, ev.id, false, "invalid: too many tags")
		return
	}
	if ev.created_at > unix_now() + CREATED_AT_SLOP_FUTURE {
		send_ok(c, ev.id, false, "invalid: created_at too far in the future")
		return
	}

	if compute_event_id(&ev) != ev.id {
		send_ok(c, ev.id, false, "invalid: id does not match serialized event")
		return
	}
	if !verify_sig(ev.id, ev.pubkey, ev.sig) {
		send_ok(c, ev.id, false, "invalid: bad signature")
		return
	}

	// Kind semantics.
	ephemeral := ev.kind >= 20000 && ev.kind < 30000
	stored_msg := ""
	if !ephemeral {
		ok, msg := store_event(&ev)
		if !ok {
			send_ok(c, ev.id, false, msg)
			return
		}
		stored_msg = msg
		if ev.kind == ALLOWLIST_KIND && (ev.pubkey in g_allowed) {
			refresh_dynamic_allowlist()
		}
	}

	send_ok(c, ev.id, true, stored_msg)
	broadcast(&ev)
}

handle_req :: proc(c: ^Conn, sub_id: string, filter_values: []json.Value) {
	if len(filter_values) > MAX_FILTERS_PER_REQ {
		send_closed(c, sub_id, "error: too many filters")
		return
	}
	if len(c.subs) >= MAX_SUBS_PER_CONN && !(sub_id in c.subs) {
		send_closed(c, sub_id, "error: too many subscriptions")
		return
	}

	// Parse in the message arena, then DEEP-CLONE into the sub's own
	// arena. The parsed strings reference the JSON tree of THIS message,
	// which ws_serve frees after dispatch - a registered filter keeping
	// those pointers matches garbage as soon as the connection handles
	// its next message (exactly what a busy pool connection does).
	sub: Sub
	mem.dynamic_arena_init(&sub.arena)
	sub_alloc := mem.dynamic_arena_allocator(&sub.arena)

	{
		filters := make([]Filter, len(filter_values), context.temp_allocator)
		ok := true
		for v, i in filter_values {
			f, fok := parse_filter(v)
			if !fok {
				ok = false
				break
			}
			filters[i] = f
		}
		if !ok {
			mem.dynamic_arena_destroy(&sub.arena)
			send_closed(c, sub_id, "invalid: bad filter")
			return
		}
		sub.filters = clone_filters(filters, sub_alloc)
	}

	// Serve stored events, newest first, deduped across filters.
	seen := make(map[string]bool, context.temp_allocator)
	for &f in sub.filters {
		rows := query_filter(&f)
		for row in rows {
			if row.id in seen do continue
			seen[row.id] = true
			if !send_event(c, sub_id, row.json) {
				mem.dynamic_arena_destroy(&sub.arena)
				return
			}
		}
	}
	{
		sb := strings.builder_make(context.temp_allocator)
		strings.write_string(&sb, `["EOSE",`)
		canon_escape(&sb, sub_id)
		strings.write_byte(&sb, ']')
		ws_send_text(c, strings.to_string(sb))
	}

	// Replace any existing sub with the same id.
	key := strings.clone(sub_id, mem.dynamic_arena_allocator(&sub.arena))
	sync.lock(&g_conns_mu)
	old, had_old := c.subs[sub_id]
	if had_old do delete_key(&c.subs, sub_id)
	c.subs[key] = sub
	sync.unlock(&g_conns_mu)
	if had_old do mem.dynamic_arena_destroy(&old.arena)
}

clone_strs :: proc(src: []string, allocator: mem.Allocator) -> []string {
	out := make([]string, len(src), allocator)
	for s, i in src do out[i] = strings.clone(s, allocator)
	return out
}

clone_filters :: proc(filters: []Filter, allocator: mem.Allocator) -> []Filter {
	out := make([]Filter, len(filters), allocator)
	for f, i in filters {
		nf := f
		nf.ids = clone_strs(f.ids, allocator)
		nf.authors = clone_strs(f.authors, allocator)
		nf.kinds = make([]i64, len(f.kinds), allocator)
		copy(nf.kinds, f.kinds)
		nf.tags = make([]Tag_Filter, len(f.tags), allocator)
		for tf, j in f.tags {
			nf.tags[j] = Tag_Filter{name = strings.clone(tf.name, allocator), values = clone_strs(tf.values, allocator)}
		}
		out[i] = nf
	}
	return out
}

// Push a freshly accepted event to every matching open subscription.
broadcast :: proc(ev: ^Event) {
	ev_js := event_json(ev)
	sync.lock(&g_conns_mu)
	defer sync.unlock(&g_conns_mu)
	when #config(RELAY_TRACE, false) {
		fmt.eprintfln("[trace] broadcast kind=%d conns=%d", ev.kind, len(g_conns))
	}
	for c in g_conns {
		for sub_id, &sub in c.subs {
			matched := match_any(sub.filters, ev)
			when #config(RELAY_TRACE, false) {
				fmt.eprintfln("[trace] sub %s filters=%d matched=%v", sub_id, len(sub.filters), matched)
				for f in sub.filters {
					fmt.eprintfln("[trace]   kinds=%v tags=%v since=%d", f.kinds, f.tags, f.since)
				}
			}
			if matched {
				send_event(c, sub_id, ev_js)
			}
		}
	}
}

import "core:mem"
import "core:sync"
