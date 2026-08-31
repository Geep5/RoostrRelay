package relay

// RFC 6455 server-side WebSocket: handshake, frame codec, message loop.
//
// Client frames are always masked (we unmask); server frames are never
// masked. Fragmented messages are reassembled up to MAX_MESSAGE. Pings
// are answered inline; a global ping loop (main.odin) keeps NAT and the
// Fly proxy from reaping idle connections and drops dead ones.

import "core:net"
import "core:fmt"
import "core:mem"
import "core:strings"
import "core:sync"
import "core:time"
import "core:encoding/base64"
import "core:crypto/legacy/sha1"

WS_MAGIC :: "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

ws_handshake :: proc(sock: net.TCP_Socket, key: string) -> bool {
	joined := fmt.tprintf("%s%s", key, WS_MAGIC)
	digest: [20]byte
	ctx: sha1.Context
	sha1.init(&ctx)
	sha1.update(&ctx, transmute([]byte)joined)
	sha1.final(&ctx, digest[:])
	accept, _ := base64.encode(digest[:], base64.ENC_TABLE, context.temp_allocator)

	resp := fmt.tprintf(
		"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n",
		accept)
	return send_all(sock, transmute([]byte)resp)
}

// -- Connection registry ----------------------------------------------

Sub :: struct {
	arena:   mem.Dynamic_Arena, // owns every string/slice in filters
	filters: []Filter,
}

Conn :: struct {
	sock:      net.TCP_Socket,
	send_mu:   sync.Mutex,
	subs:      map[string]Sub,
	last_pong: i64, // unix seconds
}

g_conns: [dynamic]^Conn
g_conns_mu: sync.Mutex

MAX_SUBS_PER_CONN :: 32
MAX_FILTERS_PER_REQ :: 10
MAX_LIMIT :: 1000
PING_INTERVAL :: 30 // seconds
PONG_DEADLINE :: 95 // drop if no pong for this long

// -- Frame codec ------------------------------------------------------

Opcode :: enum u8 {
	Continuation = 0x0,
	Text         = 0x1,
	Binary       = 0x2,
	Close        = 0x8,
	Ping         = 0x9,
	Pong         = 0xA,
}

// Reads exactly n bytes or fails.
recv_exact :: proc(sock: net.TCP_Socket, buf: []byte) -> bool {
	got := 0
	for got < len(buf) {
		n, err := net.recv_tcp(sock, buf[got:])
		if err != nil || n <= 0 do return false
		got += n
	}
	return true
}

Frame :: struct {
	fin:     bool,
	op:      Opcode,
	payload: []byte, // unmasked, temp-allocated
}

read_frame :: proc(sock: net.TCP_Socket) -> (Frame, bool) {
	hdr: [2]byte
	if !recv_exact(sock, hdr[:]) do return {}, false

	fin := hdr[0] & 0x80 != 0
	if hdr[0] & 0x70 != 0 do return {}, false // RSV bits: no extensions negotiated
	op := Opcode(hdr[0] & 0x0F)
	masked := hdr[1] & 0x80 != 0
	if !masked do return {}, false // clients MUST mask
	plen := u64(hdr[1] & 0x7F)

	if plen == 126 {
		ext: [2]byte
		if !recv_exact(sock, ext[:]) do return {}, false
		plen = u64(ext[0]) << 8 | u64(ext[1])
	} else if plen == 127 {
		ext: [8]byte
		if !recv_exact(sock, ext[:]) do return {}, false
		plen = 0
		for b in ext do plen = plen << 8 | u64(b)
	}
	if plen > MAX_MESSAGE do return {}, false

	mask: [4]byte
	if !recv_exact(sock, mask[:]) do return {}, false

	payload := make([]byte, int(plen), context.temp_allocator)
	if plen > 0 && !recv_exact(sock, payload) do return {}, false
	for i in 0 ..< len(payload) {
		payload[i] ~= mask[i % 4]
	}
	return Frame{fin = fin, op = op, payload = payload}, true
}

// Serializes a server frame (unmasked) and sends it under the conn's
// send mutex so broadcast pushes never interleave with loop replies.
ws_send :: proc(c: ^Conn, op: Opcode, payload: []byte) -> bool {
	hdr: [10]byte
	hdr[0] = 0x80 | u8(op)
	n := 2
	plen := len(payload)
	switch {
	case plen < 126:
		hdr[1] = u8(plen)
	case plen < 65536:
		hdr[1] = 126
		hdr[2] = u8(plen >> 8)
		hdr[3] = u8(plen)
		n = 4
	case:
		hdr[1] = 127
		p := u64(plen)
		for i := 0; i < 8; i += 1 {
			hdr[9 - i] = u8(p)
			p >>= 8
		}
		n = 10
	}
	sync.lock(&c.send_mu)
	defer sync.unlock(&c.send_mu)
	if !send_all(c.sock, hdr[:n]) do return false
	return send_all(c.sock, payload)
}

ws_send_text :: proc(c: ^Conn, msg: string) -> bool {
	return ws_send(c, .Text, transmute([]byte)msg)
}

// -- Connection lifecycle ---------------------------------------------

ws_serve :: proc(sock: net.TCP_Socket) {
	c := new(Conn)
	c.sock = sock
	c.subs = make(map[string]Sub)
	c.last_pong = unix_now()

	sync.lock(&g_conns_mu)
	append(&g_conns, c)
	sync.unlock(&g_conns_mu)

	defer conn_teardown(c)

	// Reassembly state for fragmented messages.
	assembling := false
	assembled: [dynamic]byte
	assembled_op: Opcode

	for {
		// Per-message temp arena: frames and JSON parse trees die together.
		frame, ok := read_frame(sock)
		if !ok do return

		switch frame.op {
		case .Ping:
			if !ws_send(c, .Pong, frame.payload) do return
		case .Pong:
			c.last_pong = unix_now()
		case .Close:
			ws_send(c, .Close, frame.payload) // echo status code
			return
		case .Text, .Binary:
			if assembling do return // protocol error: new message mid-fragment
			if frame.fin {
				if frame.op == .Text do handle_message(c, string(frame.payload))
				free_all(context.temp_allocator)
			} else {
				assembling = true
				assembled_op = frame.op
				assembled = make([dynamic]byte)
				append(&assembled, ..frame.payload)
			}
		case .Continuation:
			if !assembling do return
			if len(assembled) + len(frame.payload) > MAX_MESSAGE {
				delete(assembled)
				return
			}
			append(&assembled, ..frame.payload)
			if frame.fin {
				assembling = false
				if assembled_op == .Text do handle_message(c, string(assembled[:]))
				delete(assembled)
				free_all(context.temp_allocator)
			}
		}
	}
}

conn_teardown :: proc(c: ^Conn) {
	sync.lock(&g_conns_mu)
	for conn, i in g_conns {
		if conn == c {
			unordered_remove(&g_conns, i)
			break
		}
	}
	sync.unlock(&g_conns_mu)

	for _, &sub in c.subs {
		mem.dynamic_arena_destroy(&sub.arena)
	}
	delete(c.subs)
	net.close(c.sock)
	free(c)
}

unix_now :: proc() -> i64 {
	return time.time_to_unix(time.now())
}

// Periodic server pings; drops connections that stopped ponging.
// Closing the socket makes the owning thread's blocked read fail,
// which triggers its own teardown.
ping_loop :: proc() {
	for {
		time.sleep(time.Second * PING_INTERVAL)
		now := unix_now()
		sync.lock(&g_conns_mu)
		for c in g_conns {
			if now - c.last_pong > PONG_DEADLINE {
				net.shutdown(c.sock, .Both)
				continue
			}
			ws_send(c, .Ping, {})
		}
		sync.unlock(&g_conns_mu)
	}
}
