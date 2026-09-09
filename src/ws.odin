package relay

// RFC 6455 server-side WebSocket: handshake, frame codec, message loop.
//
// Client frames are always masked (we unmask); server frames are never
// masked. Fragmented messages are reassembled up to MAX_MESSAGE. Every
// connection owns one reader and one joined sender; all producers enqueue
// owned frames without doing network I/O under the connection registry lock.

import "core:net"
import "core:fmt"
import "core:mem"
import "core:strings"
import "core:sync"
import "core:time"
import "core:thread"
import "core:unicode/utf8"
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
	subs:      map[string]Sub, // protected by g_conns_mu while registered
	allocator: mem.Allocator, // owns queued bytes, independent of producer scratch
	sender:    ^thread.Thread,
	send_mu:   sync.Mutex, // protects queue, stopping, closing and last_pong
	send_ready: sync.Cond,
	outbound:  [MAX_OUTBOUND_FRAMES][]byte,
	out_head:  int,
	out_count: int,
	out_bytes: int, // includes the frame currently owned by the sender
	stopping:  bool,
	closing:   bool,
	last_pong: i64, // unix seconds; any valid inbound frame proves liveness
}

g_conns: [dynamic]^Conn
g_conns_mu: sync.Mutex

MAX_SUBS_PER_CONN :: 32
MAX_FILTERS_PER_REQ :: 10
MAX_LIMIT :: 1000
PING_INTERVAL :: 30 // seconds
PONG_DEADLINE :: 95 // drop if no pong for this long
// Accept one complete byte-budgeted historical REQ without depending on
// sender scheduling, with headroom for control frames and live replies.
MAX_OUTBOUND_BYTES :: MAX_QUERY_BYTES + 2 * MAX_MESSAGE
MAX_OUTBOUND_FRAMES :: MAX_FILTERS_PER_REQ * MAX_LIMIT + 64
MAX_SERVER_MESSAGE :: MAX_RECORD + QUERY_ROW_OVERHEAD // EVENT envelope around a legal stored record
MAX_MESSAGE_FRAGMENTS :: 1024 // bounds even a stream of empty continuations
WS_SEND_TIMEOUT :: 10 * time.Second

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
	payload: []byte, // unmasked, owned by the current frame's scratch arena
}

ws_valid_prefix :: proc(hdr: [2]byte) -> bool {
	if hdr[0] & 0x70 != 0 || hdr[1] & 0x80 == 0 do return false
	op := Opcode(hdr[0] & 0x0f)
	switch op {
	case .Continuation, .Text, .Binary:
		return true
	case .Close, .Ping, .Pong:
		return hdr[0] & 0x80 != 0 && hdr[1] & 0x7f <= 125
	case:
		return false
	}
}

// The decoder rejects nonminimal lengths and the forbidden 64-bit sign bit
// before any payload allocation. ext contains only the extended length bytes.
ws_decode_header :: proc(hdr: [2]byte, ext: []byte) -> (Frame, u64, bool) {
	if !ws_valid_prefix(hdr) do return {}, 0, false
	marker := hdr[1] & 0x7f
	plen := u64(marker)
	if marker == 126 || marker == 127 {
		n := 2 if marker == 126 else 8
		if len(ext) != n do return {}, 0, false
		if marker == 127 && ext[0] & 0x80 != 0 do return {}, 0, false
		plen = 0
		for b in ext do plen = plen << 8 | u64(b)
		if marker == 126 && plen < 126 do return {}, 0, false
		if marker == 127 && plen < 65536 do return {}, 0, false
	} else if len(ext) != 0 {
		return {}, 0, false
	}
	if plen > MAX_MESSAGE do return {}, 0, false
	return Frame{fin = hdr[0] & 0x80 != 0, op = Opcode(hdr[0] & 0x0f)}, plen, true
}

ws_valid_close :: proc(payload: []byte) -> bool {
	if len(payload) == 0 do return true
	if len(payload) == 1 || len(payload) > 125 do return false
	code := u16(payload[0]) << 8 | u16(payload[1])
	if !(code >= 1000 && code <= 1014 && code != 1004 && code != 1005 && code != 1006) &&
	   !(code >= 3000 && code <= 4999) {
		return false
	}
	return utf8.valid_string(string(payload[2:]))
}

read_frame :: proc(sock: net.TCP_Socket) -> (Frame, bool) {
	hdr: [2]byte
	if !recv_exact(sock, hdr[:]) || !ws_valid_prefix(hdr) do return {}, false
	ext: [8]byte
	ext_len := 0
	switch hdr[1] & 0x7f {
	case 126: ext_len = 2
	case 127: ext_len = 8
	}
	if !recv_exact(sock, ext[:ext_len]) do return {}, false
	frame, plen, valid := ws_decode_header(hdr, ext[:ext_len])
	if !valid do return {}, false
	mask: [4]byte
	if !recv_exact(sock, mask[:]) do return {}, false
	payload, alloc_err := make([]byte, int(plen), context.temp_allocator)
	if alloc_err != nil do return {}, false
	frame.payload = payload
	if !recv_exact(sock, frame.payload) do return {}, false
	for &b, i in frame.payload do b ~= mask[i % 4]
	if frame.op == .Close && !ws_valid_close(frame.payload) do return {}, false
	return frame, true
}

// Queue helpers require send_mu, except during initialization or after join.
ws_queue_pop :: proc(c: ^Conn) -> []byte {
	assert(c.out_count > 0)
	frame := c.outbound[c.out_head]
	c.outbound[c.out_head] = nil
	c.out_head = (c.out_head + 1) % MAX_OUTBOUND_FRAMES
	c.out_count -= 1
	return frame // byte budget remains charged until the sender frees it
}

ws_queue_discard :: proc(c: ^Conn) {
	for c.out_count > 0 {
		frame := ws_queue_pop(c)
		c.out_bytes -= len(frame)
		delete(frame, c.allocator)
	}
}

ws_stop_locked :: proc(c: ^Conn) {
	c.stopping = true
	sync.cond_signal(&c.send_ready)
}

// Returns queue acceptance, NOT delivery. Safe while g_conns_mu is held:
// only copies into a bounded owned queue, never waits for socket progress.
// Saturation stops this client rather than silently dropping Nostr messages.
ws_send :: proc(c: ^Conn, op: Opcode, payload: []byte) -> bool {
	sync.lock(&c.send_mu)
	defer sync.unlock(&c.send_mu)
	if c.stopping || c.closing do return false
	switch op {
	case .Text, .Binary:
		if len(payload) > MAX_SERVER_MESSAGE {
			ws_stop_locked(c)
			return false
		}
	case .Close, .Ping, .Pong:
		if len(payload) > 125 do return false
		if op == .Close && !ws_valid_close(payload) do return false
	case .Continuation:
		return false // server sends complete frames only
	case:
		return false
	}
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
	// Close takes priority over unsent data. Only the one in-flight frame
	// can precede it, so close flushing has a bounded two-frame deadline.
	if op == .Close do ws_queue_discard(c)
	size := n + plen
	if c.out_count == MAX_OUTBOUND_FRAMES || size > MAX_OUTBOUND_BYTES - c.out_bytes {
		ws_stop_locked(c)
		return false
	}
	owned, alloc_err := make([]byte, size, c.allocator)
	if alloc_err != nil {
		ws_stop_locked(c)
		return false
	}
	copy(owned[:n], hdr[:n])
	copy(owned[n:], payload)
	c.outbound[(c.out_head + c.out_count) % MAX_OUTBOUND_FRAMES] = owned
	c.out_count += 1
	c.out_bytes += size
	if op == .Close do c.closing = true
	sync.cond_signal(&c.send_ready)
	return true
}

// The sole socket writer after upgrade; never acquires g_conns_mu. Shutdown
// wakes the owning reader, but only the reader closes/frees the connection.
ws_sender :: proc(c: ^Conn) {
	defer net.shutdown(c.sock, .Both)
	for {
		sync.lock(&c.send_mu)
		for c.out_count == 0 && !c.stopping do sync.cond_wait(&c.send_ready, &c.send_mu)
		if c.stopping {
			ws_queue_discard(c)
			sync.unlock(&c.send_mu)
			return
		}
		frame := ws_queue_pop(c)
		sync.unlock(&c.send_mu)
		is_close := frame[0] & 0x0f == u8(Opcode.Close)
		ok := send_all(c.sock, frame)
		size := len(frame)
		delete(frame, c.allocator)
		sync.lock(&c.send_mu)
		c.out_bytes -= size
		if !ok || is_close do ws_stop_locked(c)
		sync.unlock(&c.send_mu)
	}
}

ws_send_text :: proc(c: ^Conn, msg: string) -> bool {
	return ws_send(c, .Text, transmute([]byte)msg)
}

// -- Connection lifecycle ---------------------------------------------

WS_Assembly :: struct {
	data: [dynamic]byte,
	op: Opcode,
	active: bool,
	fragments: int,
}

ws_assembly_reset :: proc(state: ^WS_Assembly) {
	delete(state.data)
	state^ = {}
}

// Controls leave reassembly untouched. Completed fragmented payloads borrow
// state.data until ws_assembly_reset; unfragmented payloads borrow frame scratch.
ws_assemble :: proc(state: ^WS_Assembly, frame: Frame) -> (Frame, bool, bool) {
	switch frame.op {
	case .Close, .Ping, .Pong:
		return frame, true, true
	case .Text, .Binary:
		if state.active do return {}, false, false
		if frame.fin do return frame, true, len(frame.payload) <= MAX_MESSAGE
		state.active = true
		state.op = frame.op
	case .Continuation:
		if !state.active do return {}, false, false
	case:
		return {}, false, false
	}
	if state.fragments >= MAX_MESSAGE_FRAGMENTS || len(frame.payload) > MAX_MESSAGE - len(state.data) {
		return {}, false, false
	}
	state.fragments += 1
	needed := len(state.data) + len(frame.payload)
	if needed > cap(state.data) {
		if reserve(&state.data, min(MAX_MESSAGE, max(needed, max(256, 2 * cap(state.data))))) != nil {
			return {}, false, false
		}
	}
	append(&state.data, ..frame.payload)
	if !frame.fin do return {}, false, true
	state.active = false
	return Frame{fin = true, op = state.op, payload = state.data[:]}, true, true
}

// Function scope ensures scratch is reclaimed on EVERY path: empty frames,
// controls, fragments, malformed frames and short socket reads as well as JSON.
ws_read_step :: proc(c: ^Conn, state: ^WS_Assembly) -> (keep_reading, flush_close: bool) {
	defer free_all(context.temp_allocator)
	frame, ok := read_frame(c.sock)
	if !ok do return false, false
	sync.lock(&c.send_mu)
	c.last_pong = unix_now()
	stopping := c.stopping
	sync.unlock(&c.send_mu)
	if stopping do return false, false
	message, ready, valid := ws_assemble(state, frame)
	if !valid do return false, false
	if !ready do return true, false
	switch message.op {
	case .Ping:
		return ws_send(c, .Pong, message.payload), false
	case .Pong:
		return true, false
	case .Close:
		return false, ws_send(c, .Close, message.payload)
	case .Text, .Binary:
		defer ws_assembly_reset(state)
		if message.op == .Text {
			if !utf8.valid_string(string(message.payload)) do return false, false
			handle_message(c, string(message.payload))
		}
		return true, false
	case .Continuation:
		return false, false // ws_assemble must resolve to the original data opcode
	case:
		return false, false
	}
}

ws_serve :: proc(sock: net.TCP_Socket) {
	c := new(Conn)
	c.sock = sock
	c.allocator = context.allocator
	c.subs = make(map[string]Sub)
	c.last_pong = unix_now()
	c.sender = thread.create_and_start_with_poly_data(c, ws_sender)
	if c.sender == nil {
		delete(c.subs)
		net.close(sock)
		free(c)
		return
	}
	sync.lock(&g_conns_mu)
	append(&g_conns, c)
	sync.unlock(&g_conns_mu)
	flush_close := false
	defer { conn_teardown(c, flush_close) }
	state: WS_Assembly
	defer ws_assembly_reset(&state)
	free_all(context.temp_allocator) // handshake scratch is no longer borrowed
	for {
		keep_reading, flush := ws_read_step(c, &state)
		if !keep_reading {
			flush_close = flush
			return
		}
	}
}

conn_teardown :: proc(c: ^Conn, flush_close: bool) {
	// Removing under the registry lock waits out every broadcaster/pinger;
	// afterward no producer except the already-finished reader can touch c.
	sync.lock(&g_conns_mu)
	for conn, i in g_conns {
		if conn == c {
			unordered_remove(&g_conns, i)
			break
		}
	}
	sync.unlock(&g_conns_mu)
	if !flush_close {
		sync.lock(&c.send_mu)
		ws_stop_locked(c)
		sync.unlock(&c.send_mu)
		net.shutdown(c.sock, .Both) // interrupt any in-flight send before joining
	}
	// Graceful close waits without either mutex held; sender exits after Close
	// or its bounded write fails. destroy joins the non-detached sender.
	thread.destroy(c.sender)
	ws_queue_discard(c)
	for _, &sub in c.subs do mem.dynamic_arena_destroy(&sub.arena)
	delete(c.subs)
	net.close(c.sock)
	free(c)
}

unix_now :: proc() -> i64 {
	return time.time_to_unix(time.now())
}

// Pings and stale-client cancellation are queue-only under g_conns_mu.
// The sender performs shutdown, waking the reader for joined teardown.
ping_loop :: proc() {
	for {
		time.sleep(time.Second * PING_INTERVAL)
		now := unix_now()
		sync.lock(&g_conns_mu)
		for c in g_conns {
			sync.lock(&c.send_mu)
			if now - c.last_pong > PONG_DEADLINE && !c.closing do ws_stop_locked(c)
			sync.unlock(&c.send_mu)
			ws_send(c, .Ping, {})
		}
		sync.unlock(&g_conns_mu)
	}
}
