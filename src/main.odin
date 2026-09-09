package relay

// RoostrRelay - a Nostr relay in Odin.
//
// One process, one reader and one joined sender per WebSocket (blocking
// core:net). TLS terminates at the Fly proxy; we
// listen on plaintext PORT. Storage is SQLite on a local file; writes
// are serialized under g_db_mu, WAL keeps readers unblocked.
//
// Config (env):
//   PORT                    listen port          (default 7777)
//   DB_PATH                 sqlite file          (default ./relay.db)
//   RELAY_ALLOWED_PUBKEYS   comma-separated hex; empty = open writes
//   RELAY_NAME / RELAY_DESCRIPTION / RELAY_PUBKEY / RELAY_CONTACT
//                           NIP-11 fields

import "core:fmt"
import "core:net"
import "core:os"
import "core:mem"
import "core:thread"
import "core:sync"
import "core:strings"
import "core:strconv"
import "core:time"

MAX_MESSAGE :: 1 << 20 // 1 MiB whole-message cap (Roostr snapshots ride events)

g_allowed: map[string]bool // pubkey whitelist; empty map = writes open

main :: proc() {
	port := 7777
	if p, ok := os.lookup_env("PORT", context.allocator); ok {
		if n, nok := strconv.parse_int(p); nok do port = n
	}
	db_path := os.get_env("DB_PATH", context.allocator)
	if db_path == "" do db_path = "./relay.db"

	g_allowed = make(map[string]bool)
	if wl, ok := os.lookup_env("RELAY_ALLOWED_PUBKEYS", context.allocator); ok && wl != "" {
		for pk in strings.split(wl, ",", context.allocator) {
			t := strings.trim_space(pk)
			if len(t) == 64 do g_allowed[strings.to_lower(t)] = true
		}
	}

	verify_init()
	store_open(db_path)
	refresh_dynamic_allowlist()

	endpoint := net.Endpoint{address = net.IP4_Address{0, 0, 0, 0}, port = port}
	sock, err := net.listen_tcp(endpoint)
	if err != nil {
		fmt.eprintln("[relay] listen failed:", err)
		os.exit(1)
	}
	fmt.printfln("[relay] listening on 0.0.0.0:%d (db: %s, whitelist: %d keys)",
		port, db_path, len(g_allowed))

	pinger := thread.create_and_start(ping_loop)
	_ = pinger

	for {
		client, _, aerr := net.accept_tcp(sock)
		if aerr != nil do continue
		sync.lock(&g_conns_mu)
		full := len(g_conns) >= MAX_CONNECTIONS
		sync.unlock(&g_conns_mu)
		if full {
			net.close(client) // refuse overflow without spending a thread
			continue
		}
		// self_cleanup: thread detaches and frees its own ^Thread on exit.
		thread.run_with_poly_data(client, handle_connection)
	}
}

// -- HTTP entry: upgrade to WebSocket or answer NIP-11 ----------------

Request :: struct {
	method:  string,
	path:    string,
	headers: map[string]string, // lowercased keys
}

handle_connection :: proc(sock: net.TCP_Socket) {
	arena: mem.Dynamic_Arena
	mem.dynamic_arena_init(&arena)
	context.temp_allocator = mem.dynamic_arena_allocator(&arena)
	defer mem.dynamic_arena_destroy(&arena)

	net.set_option(sock, .Send_Timeout, WS_SEND_TIMEOUT)
	// Bounds the pre-upgrade head read (slowloris) and silent dead peers; a
	// pong-answering client can never trip it (see WS_RECV_TIMEOUT). A recv
	// timeout surfaces from recv like EOF: read_head/ws_read_step close cleanly.
	net.set_option(sock, .Receive_Timeout, WS_RECV_TIMEOUT)

	req, ok := read_head(sock)
	if !ok {
		net.close(sock)
		return
	}

	upgrade := strings.to_lower(req.headers["upgrade"], context.temp_allocator)
	if upgrade == "websocket" {
		key := req.headers["sec-websocket-key"]
		if key == "" || !ws_handshake(sock, key) {
			net.close(sock)
			return
		}
		ws_serve(sock) // owns the socket from here
		return
	}

	switch {
	case req.method == "GET" && req.path == "/health":
		respond(sock, "200 OK", "text/plain", transmute([]byte)string("ok"))
	case req.method == "GET" || req.method == "OPTIONS":
		// NIP-11 relay information document; also the browser landing text.
		accept := req.headers["accept"]
		if strings.contains(accept, "application/nostr+json") || req.method == "OPTIONS" {
			respond(sock, "200 OK", "application/nostr+json", nip11_doc())
		} else {
			respond(sock, "200 OK", "text/plain",
				transmute([]byte)string("RoostrRelay - a Nostr relay. Connect with wss://\n"))
		}
	case:
		respond(sock, "404 Not Found", "text/plain", transmute([]byte)string("not found"))
	}
	net.close(sock)
}

read_head :: proc(sock: net.TCP_Socket) -> (Request, bool) {
	buf := make([dynamic]byte, context.temp_allocator)
	chunk: [8192]byte
	header_end := -1
	for header_end < 0 {
		n, rerr := net.recv_tcp(sock, chunk[:])
		if rerr != nil || n <= 0 do return {}, false
		append(&buf, ..chunk[:n])
		if len(buf) > 32768 do return {}, false
		header_end = strings.index(string(buf[:]), "\r\n\r\n")
	}

	head := string(buf[:header_end])
	lines := strings.split(head, "\r\n", context.temp_allocator)
	if len(lines) == 0 do return {}, false

	first := strings.split(lines[0], " ", context.temp_allocator)
	if len(first) < 2 do return {}, false

	req: Request
	req.method = first[0]
	req.path = first[1]
	req.headers = make(map[string]string, context.temp_allocator)
	for line in lines[1:] {
		colon := strings.index(line, ":")
		if colon < 0 do continue
		k := strings.to_lower(strings.trim_space(line[:colon]), context.temp_allocator)
		v := strings.trim_space(line[colon + 1:])
		req.headers[k] = v
	}
	return req, true
}

CORS :: "Access-Control-Allow-Origin: *\r\nAccess-Control-Allow-Headers: *\r\nAccess-Control-Allow-Methods: GET, OPTIONS\r\n"

respond :: proc(sock: net.TCP_Socket, status: string, content_type: string, body: []byte) {
	head := fmt.tprintf(
		"HTTP/1.1 %s\r\n%sContent-Type: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n",
		status, CORS, content_type, len(body))
	if send_all(sock, transmute([]byte)head) {
		send_all(sock, body)
	}
}

send_all :: proc(sock: net.TCP_Socket, data: []byte) -> bool {
	started := time.now()
	sent := 0
	for sent < len(data) {
		remaining := WS_SEND_TIMEOUT - time.since(started)
		if remaining < time.Millisecond do return false
		// Bound the whole frame/response, not each successful partial write.
		if net.set_option(sock, .Send_Timeout, remaining) != nil do return false
		// net.send_tcp loops internally; use one syscall so partial progress
		// cannot reset the deadline indefinitely on a trickle-reading client.
		n := send_once(sock, data[sent:])
		if n <= 0 do return false
		sent += n
	}
	return true
}
