package relay

// Blossom blob storage (BUD-01 / BUD-02 / BUD-06 / BUD-11) on the relay's
// HTTP port. Contract: glonOdin docs/state-sync.md "Files on Blossom".
//
//   GET|HEAD /<sha256>[.ext]   public by hash, single Range supported
//   PUT      /upload           auth t=upload, x=sha256; allowlisted writers
//   HEAD     /upload           BUD-06 preflight (same checks, no body)
//   DELETE   /<sha256>         auth t=delete; drops the caller's claim
//   GET      /list/<pubkey>    auth t=list by <pubkey>; its own uploads
//
// Storage: <dir of DB_PATH>/blobs/<sha256>, plus <sha256>.meta holding the
// size, content type and uploader claims (one "pubkey uploaded" line each).
// Uploads stream to blobs/.tmp-*, hashed on the fly, fsynced, then renamed.
// The meta file is renamed into place BEFORE the blob, so a crash leaves at
// worst a meta without a blob (dropped at boot), never an unowned blob.
// Every transfer runs on its connection's own thread in BLOB_IO_CHUNK
// pieces; nothing holds g_blob_mu across network I/O.

import "core:crypto/sha2"
import "core:encoding/base64"
import "core:encoding/hex"
import "core:encoding/json"
import "core:fmt"
import "core:net"
import "core:os"
import "core:slice"
import "core:strconv"
import "core:strings"
import "core:sync"
import "core:time"

BLOB_MAX_SIZE :: i64(512) << 20
BLOB_IO_CHUNK :: 256 << 10
BLOB_MAX_TRANSFERS :: 64 // concurrent blob GET/PUT bodies; excess gets 503
BLOB_AUTH_KIND :: 24242
BLOB_AUTH_MAX_BYTES :: 16 << 10 // base64 header length cap
BLOB_AUTH_FUTURE_SKEW :: 60 // seconds of clock skew tolerated on created_at
BLOB_DRAIN_BYTES :: 4 << 20 // unread body swallowed after an early reject
BLOB_DRAIN_TIMEOUT :: 2 * time.Second

Blob_Owner :: struct {
	pubkey:   string,
	uploaded: i64,
}

Blob_Meta :: struct {
	size:   i64,
	type:   string,
	owners: [dynamic]Blob_Owner,
}

g_blob_dir: string
g_blob_mu: sync.Mutex // owns g_blobs and every meta/blob rename or removal
g_blobs: map[string]^Blob_Meta
g_blob_transfers: int // atomic
g_blob_seq: u64 // atomic, temp file names

blob_path :: proc(sha: string) -> string {
	return fmt.tprintf("%s/%s", g_blob_dir, sha)
}

blob_meta_path :: proc(sha: string) -> string {
	return fmt.tprintf("%s/%s.meta", g_blob_dir, sha)
}

// -- Boot ------------------------------------------------------------------

blob_open :: proc(db_path: string) {
	g_blob_dir = strings.clone(fmt.tprintf("%s/blobs", os.dir(db_path)))
	g_blobs = make(map[string]^Blob_Meta)
	if err := os.make_directory_all(g_blob_dir); err != nil && !os.exists(g_blob_dir) {
		fmt.eprintln("[relay] FATAL: cannot create blob dir:", g_blob_dir, err)
		os.exit(1)
	}
	entries, err := os.read_all_directory_by_path(g_blob_dir, context.temp_allocator)
	if err != nil {
		fmt.eprintln("[relay] FATAL: cannot read blob dir:", err)
		os.exit(1)
	}
	names := make(map[string]bool, context.temp_allocator)
	for e in entries do names[e.name] = true
	for e in entries {
		name := e.name
		switch {
		case strings.has_prefix(name, ".tmp-"):
			_ = os.remove(fmt.tprintf("%s/%s", g_blob_dir, name)) // torn upload
		case len(name) == 69 && strings.has_suffix(name, ".meta") && is_hex64(name[:64]):
			if !(name[:64] in names) {
				_ = os.remove(fmt.tprintf("%s/%s", g_blob_dir, name)) // crash before blob rename
				continue
			}
			if m := blob_read_meta(name[:64]); m != nil do g_blobs[strings.clone(name[:64])] = m
		case len(name) == 64 && is_hex64(name):
			if !(fmt.tprintf("%s.meta", name) in names) {
				// Blob without claims (meta lost): still served; the next upload claims it.
				m := new(Blob_Meta)
				m.size = e.size
				m.type = strings.clone("application/octet-stream")
				g_blobs[strings.clone(name)] = m
			}
		}
	}
	total: i64
	for _, m in g_blobs do total += m.size
	fmt.printfln("[relay] blossom: %d blob(s), %d bytes in %s", len(g_blobs), total, g_blob_dir)
}

blob_read_meta :: proc(sha: string) -> ^Blob_Meta {
	data, err := os.read_entire_file_from_path(blob_meta_path(sha), context.temp_allocator)
	if err != nil do return nil
	lines := strings.split_lines(string(data), context.temp_allocator)
	if len(lines) == 0 do return nil
	head := strings.fields(lines[0], context.temp_allocator)
	if len(head) != 2 do return nil
	size, ok := strconv.parse_i64(head[0])
	if !ok do return nil
	m := new(Blob_Meta)
	m.size = size
	m.type = strings.clone(head[1])
	for line in lines[1:] {
		f := strings.fields(line, context.temp_allocator)
		if len(f) != 2 || !is_hex64(f[0]) do continue
		up, uok := strconv.parse_i64(f[1])
		if !uok do continue
		append(&m.owners, Blob_Owner{pubkey = strings.clone(f[0]), uploaded = up})
	}
	return m
}

blob_free_meta :: proc(m: ^Blob_Meta) {
	for o in m.owners do delete(o.pubkey)
	delete(m.owners)
	delete(m.type)
	free(m)
}

blob_sync_dir :: proc() -> bool {
	fd, err := os.open(g_blob_dir, {.Read}, os.Permissions_Default_File)
	if err != nil do return false
	ok := os.sync(fd) == nil
	return os.close(fd) == nil && ok
}

// Caller holds g_blob_mu. Durable write-then-rename of <sha>.meta.
blob_write_meta :: proc(sha: string, m: ^Blob_Meta) -> bool {
	sb := strings.builder_make(context.temp_allocator)
	fmt.sbprintf(&sb, "%d %s\n", m.size, m.type)
	for o in m.owners do fmt.sbprintf(&sb, "%s %d\n", o.pubkey, o.uploaded)
	tmp := fmt.tprintf("%s/.tmp-meta-%s", g_blob_dir, sha)
	fd, err := os.open(tmp, {.Write, .Create, .Trunc}, os.Permissions_Default_File)
	if err != nil do return false
	ok := write_full(fd, transmute([]u8)strings.to_string(sb)) && os.sync(fd) == nil
	if os.close(fd) != nil do ok = false
	if ok do ok = os.rename(tmp, blob_meta_path(sha)) == nil
	if !ok { _ = os.remove(tmp); return false }
	return blob_sync_dir()
}

// -- HTTP helpers ----------------------------------------------------------

blob_respond :: proc(sock: net.TCP_Socket, status, content_type: string, body: []byte, extra := "") {
	head := fmt.tprintf(
		"HTTP/1.1 %s\r\n%s%sContent-Type: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n",
		status, CORS, extra, content_type, len(body))
	if send_all(sock, transmute([]byte)head) && len(body) > 0 do send_all(sock, body)
}

blob_fail :: proc(sock: net.TCP_Socket, status, reason: string) {
	blob_respond(sock, status, "text/plain", transmute([]byte)reason, fmt.tprintf("X-Reason: %s\r\n", reason))
}

// After answering without reading the body, swallow a bounded amount of it so
// closing with unread bytes does not RST the response away before the client
// reads it. Larger bodies get the RST; the client sees a failed upload either way.
blob_drain :: proc(sock: net.TCP_Socket) {
	net.shutdown(sock, .Send)
	net.set_option(sock, .Receive_Timeout, BLOB_DRAIN_TIMEOUT)
	buf: [16 << 10]byte
	total := 0
	for total < BLOB_DRAIN_BYTES {
		n, err := net.recv_tcp(sock, buf[:])
		if err != nil || n <= 0 do return
		total += n
	}
}

blob_transfer_begin :: proc(sock: net.TCP_Socket) -> bool {
	if sync.atomic_add(&g_blob_transfers, 1) >= BLOB_MAX_TRANSFERS {
		sync.atomic_sub(&g_blob_transfers, 1)
		blob_fail(sock, "503 Service Unavailable", "too many concurrent transfers")
		return false
	}
	return true
}

blob_transfer_end :: proc() {
	sync.atomic_sub(&g_blob_transfers, 1)
}

// "/<sha256>[.ext]" -> sha, ext. Query strings are ignored.
blob_parse_path :: proc(path: string) -> (sha, ext: string, ok: bool) {
	p := path
	if q := strings.index_byte(p, '?'); q >= 0 do p = p[:q]
	if len(p) < 65 || p[0] != '/' do return
	p = p[1:]
	if !is_hex64(p[:64]) do return
	if len(p) == 64 do return p, "", true
	if p[64] != '.' || strings.contains_any(p[65:], "/.") || len(p) > 64+1+16 do return
	return p[:64], p[65:], true
}

blob_type_for_ext :: proc(ext: string) -> string {
	switch strings.to_lower(ext, context.temp_allocator) {
	case "png": return "image/png"
	case "jpg", "jpeg": return "image/jpeg"
	case "gif": return "image/gif"
	case "webp": return "image/webp"
	case "pdf": return "application/pdf"
	case "txt": return "text/plain"
	case "json": return "application/json"
	case "mp4": return "video/mp4"
	case "mp3": return "audio/mpeg"
	}
	return "application/octet-stream"
}

// Content types are echoed into headers and meta lines: keep them to one token.
blob_clean_type :: proc(t: string) -> string {
	t := strings.trim_space(t)
	if semi := strings.index_byte(t, ';'); semi >= 0 do t = strings.trim_space(t[:semi])
	if t == "" || len(t) > 127 do return "application/octet-stream"
	for c in transmute([]u8)t {
		if c <= ' ' || c >= 0x7f || c == '"' || c == '\\' do return "application/octet-stream"
	}
	return t
}

blob_base_url :: proc(req: ^Request) -> string {
	if base := os.get_env("BLOSSOM_PUBLIC_URL", context.temp_allocator); base != "" {
		return strings.trim_right(base, "/")
	}
	proto := req.headers["x-forwarded-proto"]
	if proto != "https" do proto = "http"
	host := req.headers["host"]
	if host == "" || strings.contains_any(host, "\"\\/ ") do host = "localhost"
	return fmt.tprintf("%s://%s", proto, host)
}

blob_descriptor :: proc(sb: ^strings.Builder, base, sha: string, size: i64, type: string, uploaded: i64) {
	strings.write_string(sb, `{"url":`)
	canon_escape(sb, fmt.tprintf("%s/%s", base, sha))
	fmt.sbprintf(sb, `,"sha256":"%s","size":%d,"type":`, sha, size)
	canon_escape(sb, type)
	fmt.sbprintf(sb, `,"uploaded":%d`, uploaded)
	strings.write_byte(sb, '}')
}

// -- BUD-11 authorization --------------------------------------------------

// Verifies the `Authorization: Nostr <base64 kind-24242>` header for `action`.
// The caller checks `x` tags and the allowlist.
blob_auth :: proc(req: ^Request, action: string) -> (ev: Event, reason: string) {
	h := req.headers["authorization"]
	if len(h) < 6 || strings.to_lower(h[:6], context.temp_allocator) != "nostr " {
		return {}, "missing Nostr authorization"
	}
	b64 := strings.trim_space(h[6:])
	if len(b64) == 0 || len(b64) > BLOB_AUTH_MAX_BYTES do return {}, "invalid authorization header"
	// Accept base64url and missing padding as well as standard base64.
	norm := make([]u8, len(b64) + 3, context.temp_allocator)
	n := 0
	for c in transmute([]u8)b64 {
		switch c {
		case '-': norm[n] = '+'
		case '_': norm[n] = '/'
		case: norm[n] = c
		}
		n += 1
	}
	for n % 4 != 0 { norm[n] = '='; n += 1 }
	raw, derr := base64.decode(string(norm[:n]), allocator = context.temp_allocator)
	if derr != nil || !json_depth_ok(raw, 16) do return {}, "authorization is not base64 JSON"
	v, jerr := json.parse(raw, allocator = context.temp_allocator)
	if jerr != nil do return {}, "authorization is not base64 JSON"
	perr: string
	ev, perr = parse_event(v)
	if perr != "" do return {}, fmt.tprintf("authorization event %s", perr)
	if ev.kind != BLOB_AUTH_KIND do return {}, "authorization event must be kind 24242"
	if compute_event_id(&ev) != ev.id do return {}, "authorization event id mismatch"
	if !verify_sig(ev.id, ev.pubkey, ev.sig) do return {}, "authorization event bad signature"
	now := unix_now()
	if ev.created_at > now + BLOB_AUTH_FUTURE_SKEW do return {}, "authorization created_at is in the future"
	expiration: i64 = -1
	verb_ok := false
	for tag in ev.tags {
		if len(tag) < 2 do continue
		switch tag[0] {
		case "expiration":
			if e, ok := strconv.parse_i64(tag[1]); ok do expiration = e
		case "t":
			if tag[1] == action do verb_ok = true
		}
	}
	if expiration < 0 do return {}, "authorization missing expiration"
	if expiration <= now do return {}, "authorization expired"
	if !verb_ok do return {}, fmt.tprintf("authorization t tag must be %s", action)
	return ev, ""
}

blob_auth_has_x :: proc(ev: ^Event, sha: string) -> bool {
	for tag in ev.tags do if len(tag) >= 2 && tag[0] == "x" && tag[1] == sha do return true
	return false
}

blob_writer_allowed :: proc(pubkey: string) -> bool {
	return len(g_allowed) == 0 || write_allowed(pubkey)
}

// -- Routing ---------------------------------------------------------------

// Handles Blossom routes; false = not a Blossom request (caller continues).
blossom_route :: proc(sock: net.TCP_Socket, req: ^Request) -> bool {
	path := req.path
	if q := strings.index_byte(path, '?'); q >= 0 do path = path[:q]
	sha, ext, is_blob := blob_parse_path(path)
	is_upload := path == "/upload"
	is_list := strings.has_prefix(path, "/list/")
	if !is_blob && !is_upload && !is_list do return false

	switch {
	case req.method == "OPTIONS":
		blob_respond(sock, "204 No Content", "text/plain", nil)
	case is_upload && req.method == "PUT":
		blob_upload(sock, req)
	case is_upload && req.method == "HEAD":
		blob_upload_check(sock, req)
	case is_list && req.method == "GET":
		blob_list(sock, req, path[len("/list/"):])
	case is_blob && (req.method == "GET" || req.method == "HEAD"):
		blob_get(sock, req, sha, ext)
	case is_blob && req.method == "DELETE":
		blob_delete(sock, req, sha)
	case:
		blob_fail(sock, "405 Method Not Allowed", "method not allowed")
	}
	return true
}

// -- BUD-01 GET / HEAD -----------------------------------------------------

// Single "bytes=" range against size. ok=false means unsatisfiable.
blob_parse_range :: proc(h: string, size: i64) -> (start, end: i64, partial, ok: bool) {
	if h == "" do return 0, size - 1, false, true
	spec := strings.trim_space(h)
	if !strings.has_prefix(spec, "bytes=") || strings.contains_rune(spec, ',') {
		return 0, size - 1, false, true // unsupported unit or multi-range: full body (RFC 9110 allows ignoring)
	}
	spec = spec[len("bytes="):]
	dash := strings.index_byte(spec, '-')
	if dash < 0 do return 0, size - 1, false, true
	a, b := strings.trim_space(spec[:dash]), strings.trim_space(spec[dash+1:])
	if a == "" {
		n, nok := strconv.parse_i64(b)
		if !nok || n <= 0 || size == 0 do return 0, 0, true, false
		return max(size - n, 0), size - 1, true, true
	}
	s, sok := strconv.parse_i64(a)
	if !sok || s < 0 || s >= size do return 0, 0, true, false
	e := size - 1
	if b != "" {
		v, vok := strconv.parse_i64(b)
		if !vok || v < s do return 0, 0, true, false
		e = min(v, size - 1)
	}
	return s, e, true, true
}

blob_get :: proc(sock: net.TCP_Socket, req: ^Request, sha, ext: string) {
	type := ""
	sync.lock(&g_blob_mu)
	if m, ok := g_blobs[sha]; ok do type = strings.clone(m.type, context.temp_allocator)
	fd, err := os.open(blob_path(sha), {.Read}, os.Permissions_Default_File)
	sync.unlock(&g_blob_mu)
	if err != nil {
		blob_fail(sock, "404 Not Found", "blob not found")
		return
	}
	defer os.close(fd)
	size, serr := os.file_size(fd)
	if serr != nil {
		blob_fail(sock, "500 Internal Server Error", "cannot stat blob")
		return
	}
	if type == "" || type == "application/octet-stream" do type = ext != "" ? blob_type_for_ext(ext) : "application/octet-stream"

	start, end, partial, rok := blob_parse_range(req.headers["range"], size)
	if !rok {
		blob_respond(sock, "416 Range Not Satisfiable", "text/plain", nil,
			fmt.tprintf("Content-Range: bytes */%d\r\nX-Reason: range not satisfiable\r\n", size))
		return
	}
	length := size == 0 ? 0 : end - start + 1
	status := partial ? "206 Partial Content" : "200 OK"
	range_hdr := partial ? fmt.tprintf("Content-Range: bytes %d-%d/%d\r\n", start, end, size) : ""
	head := fmt.tprintf(
		"HTTP/1.1 %s\r\n%sContent-Type: %s\r\nContent-Length: %d\r\n%sAccept-Ranges: bytes\r\n"+
		"Cache-Control: public, max-age=31536000, immutable\r\nETag: \"%s\"\r\nConnection: close\r\n\r\n",
		status, CORS, type, length, range_hdr, sha)
	if !send_all(sock, transmute([]byte)head) || req.method == "HEAD" || length == 0 do return

	if !blob_transfer_begin(sock) do return // headers already sent; closing truncates
	defer blob_transfer_end()
	buf := make([]byte, BLOB_IO_CHUNK)
	defer delete(buf)
	off := start
	for off <= end {
		want := min(i64(len(buf)), end - off + 1)
		n, rerr := os.read_at(fd, buf[:want], off)
		if n <= 0 || (rerr != nil && n <= 0) do return
		if !send_all(sock, buf[:n]) do return
		off += i64(n)
	}
}

// -- BUD-02 PUT /upload ----------------------------------------------------

// Shared admission checks for PUT and the BUD-06 HEAD preflight.
blob_upload_admit :: proc(sock: net.TCP_Socket, req: ^Request, length_header: string) -> (ev: Event, length: i64, x_header: string, ok: bool) {
	reason: string
	ev, reason = blob_auth(req, "upload")
	if reason != "" {
		blob_fail(sock, "401 Unauthorized", reason)
		return
	}
	if !blob_writer_allowed(ev.pubkey) {
		blob_fail(sock, "403 Forbidden", "pubkey not on the allowlist")
		return
	}
	if req.headers["transfer-encoding"] != "" {
		blob_fail(sock, "411 Length Required", "send Content-Length, not chunked")
		return
	}
	cl := req.headers[length_header]
	if cl == "" {
		blob_fail(sock, "411 Length Required", "Content-Length required")
		return
	}
	n, nok := strconv.parse_i64(cl)
	if !nok || n < 0 {
		blob_fail(sock, "400 Bad Request", "invalid Content-Length")
		return
	}
	if n > BLOB_MAX_SIZE {
		blob_fail(sock, "413 Content Too Large", fmt.tprintf("blob exceeds %d bytes", BLOB_MAX_SIZE))
		return
	}
	x_header = strings.to_lower(req.headers["x-sha-256"], context.temp_allocator)
	if x_header != "" {
		if !is_hex64(x_header) {
			blob_fail(sock, "400 Bad Request", "invalid X-SHA-256")
			return
		}
		if !blob_auth_has_x(&ev, x_header) {
			blob_fail(sock, "401 Unauthorized", "authorization x tag does not match X-SHA-256")
			return
		}
	}
	return ev, n, x_header, true
}

blob_upload_check :: proc(sock: net.TCP_Socket, req: ^Request) {
	if _, _, _, ok := blob_upload_admit(sock, req, "x-content-length"); ok {
		blob_respond(sock, "200 OK", "text/plain", nil)
	}
}

blob_upload :: proc(sock: net.TCP_Socket, req: ^Request) {
	ev, length, x_header, ok := blob_upload_admit(sock, req, "content-length")
	if !ok {
		blob_drain(sock)
		return
	}
	if !blob_transfer_begin(sock) {
		blob_drain(sock)
		return
	}
	defer blob_transfer_end()
	if strings.to_lower(req.headers["expect"], context.temp_allocator) == "100-continue" {
		if !send_all(sock, transmute([]byte)string("HTTP/1.1 100 Continue\r\n\r\n")) do return
	}

	tmp := fmt.tprintf("%s/.tmp-%d-%d", g_blob_dir, time.now()._nsec, sync.atomic_add(&g_blob_seq, 1))
	fd, err := os.open(tmp, {.Write, .Create, .Trunc}, os.Permissions_Default_File)
	if err != nil {
		blob_fail(sock, "500 Internal Server Error", "cannot create temp file")
		blob_drain(sock)
		return
	}
	committed := false
	closed := false
	defer {
		if !closed do os.close(fd)
		if !committed do _ = os.remove(tmp)
	}

	ctx: sha2.Context_256
	sha2.init_256(&ctx)
	received: i64
	prefix := req.rest
	if i64(len(prefix)) > length do prefix = prefix[:length]
	if len(prefix) > 0 {
		sha2.update(&ctx, prefix)
		if !write_full(fd, prefix) {
			blob_fail(sock, "500 Internal Server Error", "write failed")
			return
		}
		received = i64(len(prefix))
	}
	buf := make([]byte, BLOB_IO_CHUNK)
	defer delete(buf)
	for received < length {
		want := min(i64(len(buf)), length - received)
		n, rerr := net.recv_tcp(sock, buf[:want])
		if rerr != nil || n <= 0 do return // client went away or stalled past the receive deadline
		sha2.update(&ctx, buf[:n])
		if !write_full(fd, buf[:n]) {
			blob_fail(sock, "500 Internal Server Error", "write failed")
			return
		}
		received += i64(n)
	}
	digest: [32]u8
	sha2.final(&ctx, digest[:])
	sha := string(hex.encode(digest[:], context.temp_allocator))

	if x_header != "" && x_header != sha {
		blob_fail(sock, "409 Conflict", "body sha256 does not match X-SHA-256")
		return
	}
	if !blob_auth_has_x(&ev, sha) {
		blob_fail(sock, "401 Unauthorized", "authorization x tag does not match body sha256")
		return
	}
	if os.sync(fd) != nil {
		blob_fail(sock, "500 Internal Server Error", "fsync failed")
		return
	}
	os.close(fd)
	closed = true

	type := blob_clean_type(req.headers["content-type"])
	now := unix_now()
	uploaded := now
	stored_type := type
	{
		sync.lock(&g_blob_mu)
		defer sync.unlock(&g_blob_mu)
		m, exists := g_blobs[sha]
		if exists && os.exists(blob_path(sha)) {
			// Same bytes already stored: record this uploader's claim only.
			stored_type = strings.clone(m.type, context.temp_allocator)
			claimed := false
			for o in m.owners do if o.pubkey == ev.pubkey { uploaded = o.uploaded; claimed = true }
			if !claimed {
				append(&m.owners, Blob_Owner{pubkey = strings.clone(ev.pubkey), uploaded = now})
				if !blob_write_meta(sha, m) {
					pop(&m.owners)
					blob_fail(sock, "500 Internal Server Error", "cannot record uploader")
					return
				}
			}
		} else {
			fresh := new(Blob_Meta)
			fresh.size = length
			fresh.type = strings.clone(type)
			append(&fresh.owners, Blob_Owner{pubkey = strings.clone(ev.pubkey), uploaded = now})
			if !blob_write_meta(sha, fresh) || os.rename(tmp, blob_path(sha)) != nil || !blob_sync_dir() {
				blob_free_meta(fresh)
				_ = os.remove(blob_meta_path(sha))
				blob_fail(sock, "500 Internal Server Error", "cannot store blob")
				return
			}
			committed = true
			if exists {
				key, _ := delete_key(&g_blobs, sha)
				delete(key)
				blob_free_meta(m)
			}
			g_blobs[strings.clone(sha)] = fresh
		}
	}

	sb := strings.builder_make(context.temp_allocator)
	blob_descriptor(&sb, blob_base_url(req), sha, length, stored_type, uploaded)
	blob_respond(sock, "200 OK", "application/json", transmute([]byte)strings.to_string(sb))
}

// -- BUD-02 DELETE ---------------------------------------------------------

blob_delete :: proc(sock: net.TCP_Socket, req: ^Request, sha: string) {
	ev, reason := blob_auth(req, "delete")
	if reason != "" {
		blob_fail(sock, "401 Unauthorized", reason)
		return
	}
	if !blob_auth_has_x(&ev, sha) {
		blob_fail(sock, "401 Unauthorized", "authorization x tag does not match blob")
		return
	}
	sync.lock(&g_blob_mu)
	defer sync.unlock(&g_blob_mu)
	m, exists := g_blobs[sha]
	if !exists {
		blob_fail(sock, "404 Not Found", "blob not found")
		return
	}
	idx := -1
	for o, i in m.owners do if o.pubkey == ev.pubkey { idx = i; break }
	if idx < 0 {
		blob_fail(sock, "403 Forbidden", "not the uploader")
		return
	}
	owner := m.owners[idx]
	ordered_remove(&m.owners, idx)
	if len(m.owners) > 0 {
		if !blob_write_meta(sha, m) {
			inject_at(&m.owners, idx, owner)
			blob_fail(sock, "500 Internal Server Error", "cannot update uploader record")
			return
		}
		delete(owner.pubkey)
	} else {
		// Blob first: a crash in between leaves a meta without a blob, dropped at boot.
		if rerr := os.remove(blob_path(sha)); rerr != nil && os.exists(blob_path(sha)) {
			inject_at(&m.owners, idx, owner)
			blob_fail(sock, "500 Internal Server Error", "cannot remove blob")
			return
		}
		_ = os.remove(blob_meta_path(sha))
		_ = blob_sync_dir()
		delete(owner.pubkey)
		key, _ := delete_key(&g_blobs, sha)
		delete(key)
		blob_free_meta(m)
	}
	blob_respond(sock, "200 OK", "text/plain", transmute([]byte)string("deleted"))
}

// -- BUD-02 GET /list/<pubkey> ---------------------------------------------

blob_list :: proc(sock: net.TCP_Socket, req: ^Request, pubkey: string) {
	if !is_hex64(pubkey) {
		blob_fail(sock, "400 Bad Request", "invalid pubkey")
		return
	}
	ev, reason := blob_auth(req, "list")
	if reason != "" {
		blob_fail(sock, "401 Unauthorized", reason)
		return
	}
	if ev.pubkey != pubkey {
		blob_fail(sock, "403 Forbidden", "only the uploader may list its blobs")
		return
	}
	Row :: struct {
		sha:      string,
		size:     i64,
		type:     string,
		uploaded: i64,
	}
	rows := make([dynamic]Row, context.temp_allocator)
	{
		sync.lock(&g_blob_mu)
		defer sync.unlock(&g_blob_mu)
		for sha, m in g_blobs {
			for o in m.owners do if o.pubkey == pubkey {
				append(&rows, Row{
					sha = strings.clone(sha, context.temp_allocator), size = m.size,
					type = strings.clone(m.type, context.temp_allocator), uploaded = o.uploaded,
				})
				break
			}
		}
	}
	slice.sort_by(rows[:], proc(a, b: Row) -> bool {
		return a.uploaded != b.uploaded ? a.uploaded > b.uploaded : a.sha < b.sha
	})
	base := blob_base_url(req)
	sb := strings.builder_make(context.temp_allocator)
	strings.write_byte(&sb, '[')
	for r, i in rows {
		if i > 0 do strings.write_byte(&sb, ',')
		blob_descriptor(&sb, base, r.sha, r.size, r.type, r.uploaded)
	}
	strings.write_byte(&sb, ']')
	blob_respond(sock, "200 OK", "application/json", transmute([]byte)strings.to_string(sb))
}
