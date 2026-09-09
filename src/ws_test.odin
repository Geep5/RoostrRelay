package relay

import "core:mem"
import "core:net"
import "core:testing"
import "core:thread"
import "core:time"

when ODIN_TEST {
	@(test)
	ws_control_validation :: proc(t: ^testing.T) {
		for op in 0..<16 {
			for final in 0..<2 {
				for size in ([?]u8{0, 125, 126, 127}) {
					hdr := [2]byte{u8(final << 7) | u8(op), 0x80 | size}
					data := op == 0 || op == 1 || op == 2
					control := op == 8 || op == 9 || op == 10
					expected := data || (control && final == 1 && size <= 125)
					testing.expect_value(t, ws_valid_prefix(hdr), expected)
				}
			}
		}
		for rsv in ([?]byte{0x10, 0x20, 0x40}) {
			testing.expect(t, !ws_valid_prefix({0x81 | rsv, 0x80}))
		}
		testing.expect(t, !ws_valid_prefix({0x81, 0x00}), "Client masking is mandatory")
		testing.expect(t, ws_valid_close({}))
		testing.expect(t, !ws_valid_close([]byte{0x03}))
		for code in ([?]u16{1000, 1001, 1002, 1003, 1007, 1008, 1009, 1010, 1011, 1012, 1013, 1014, 3000, 4999}) {
			payload := [2]byte{byte(code >> 8), byte(code)}
			testing.expect(t, ws_valid_close(payload[:]))
		}
		for code in ([?]u16{0, 999, 1004, 1005, 1006, 1015, 1016, 2999, 5000, 65535}) {
			payload := [2]byte{byte(code >> 8), byte(code)}
			testing.expect(t, !ws_valid_close(payload[:]))
		}
		testing.expect(t, !ws_valid_close([]byte{0x03, 0xe8, 0xff}), "Close reason must be UTF-8")
		testing.expect(t, ws_valid_close([]byte{0x03, 0xe8, 0xe2, 0x82, 0xac}))
	}

	@(test)
	ws_canonical_lengths :: proc(t: ^testing.T) {
		Case :: struct { marker: byte, ext: []byte, size: u64, valid: bool }
		cases := [?]Case{
			{125, {}, 125, true},
			{126, []byte{0, 125}, 0, false},
			{126, []byte{0, 126}, 126, true},
			{126, []byte{255, 255}, 65535, true},
			{127, []byte{0, 0, 0, 0, 0, 0, 255, 255}, 0, false},
			{127, []byte{0, 0, 0, 0, 0, 1, 0, 0}, 65536, true},
			{127, []byte{0, 0, 0, 0, 0, 16, 0, 0}, MAX_MESSAGE, true},
			{127, []byte{0, 0, 0, 0, 0, 16, 0, 1}, 0, false},
			{127, []byte{128, 0, 0, 0, 0, 1, 0, 0}, 0, false},
			{126, []byte{0}, 0, false},
			{127, []byte{0, 0}, 0, false},
			{1, []byte{0}, 0, false},
		}
		for c in cases {
			frame, size, ok := ws_decode_header({0x81, 0x80 | c.marker}, c.ext)
			testing.expect_value(t, ok, c.valid)
			if ok {
				testing.expect_value(t, size, c.size)
				testing.expect(t, frame.fin && frame.op == .Text)
			}
		}
	}

	@(test)
	ws_fragment_lifecycle :: proc(t: ^testing.T) {
		state: WS_Assembly
		defer ws_assembly_reset(&state)
		input := [2]byte{'a', 'b'}
		_, ready, ok := ws_assemble(&state, {op = .Text, payload = input[:]})
		testing.expect(t, ok && !ready && state.active)
		input[0] = 'x'
		testing.expectf(t, string(state.data[:]) == "ab", "Reassembly must own input bytes")
		ping, ping_ready, ping_ok := ws_assemble(&state, {fin = true, op = .Ping})
		testing.expect(t, ping_ok && ping_ready && ping.op == .Ping && state.active)
		testing.expect_value(t, state.fragments, 1)
		message, complete, valid := ws_assemble(&state, {fin = true, op = .Continuation, payload = []byte{'c'}})
		testing.expect(t, valid && complete && message.op == .Text && !state.active)
		testing.expect_value(t, string(message.payload), "abc")
		ws_assembly_reset(&state)
		testing.expect(t, raw_data(state.data) == nil && !state.active && state.fragments == 0)
		_, _, unexpected := ws_assemble(&state, {fin = true, op = .Continuation})
		testing.expect(t, !unexpected)
		ws_assemble(&state, {op = .Binary, payload = []byte{'a'}})
		_, _, nested := ws_assemble(&state, {fin = true, op = .Text})
		testing.expect(t, !nested)
		ws_assembly_reset(&state)
		// Teardown of an unfinished message must release the owned allocation.
		testing.expect(t, raw_data(state.data) == nil)
	}

	@(test)
	ws_fragment_budgets :: proc(t: ^testing.T) {
		state: WS_Assembly
		defer ws_assembly_reset(&state)
		payload := make([]byte, MAX_MESSAGE)
		defer delete(payload)
		_, ready, ok := ws_assemble(&state, {op = .Binary, payload = payload[:MAX_MESSAGE/2]})
		testing.expect(t, ok && !ready)
		message, complete, valid := ws_assemble(&state, {fin = true, op = .Continuation, payload = payload[MAX_MESSAGE/2:]})
		testing.expect(t, valid && complete && len(message.payload) == MAX_MESSAGE)
		testing.expect(t, cap(state.data) <= MAX_MESSAGE)
		ws_assembly_reset(&state)
		ws_assemble(&state, {op = .Binary, payload = payload})
		_, _, oversized := ws_assemble(&state, {fin = true, op = .Continuation, payload = []byte{0}})
		testing.expect(t, !oversized && len(state.data) == MAX_MESSAGE)
		ws_assembly_reset(&state)
		ws_assemble(&state, {op = .Binary})
		for _ in 1..<MAX_MESSAGE_FRAGMENTS {
			_, _, accepted := ws_assemble(&state, {op = .Continuation})
			testing.expect(t, accepted)
		}
		_, _, excess := ws_assemble(&state, {fin = true, op = .Continuation})
		testing.expect(t, !excess, "Empty fragments must consume the fragment budget")
		ws_assembly_reset(&state)
		ws_assemble(&state, {op = .Binary})
		for _ in 1..<MAX_MESSAGE_FRAGMENTS-1 do ws_assemble(&state, {op = .Continuation})
		_, final_ready, final_ok := ws_assemble(&state, {fin = true, op = .Continuation})
		testing.expect(t, final_ready && final_ok, "Exactly the fragment limit remains valid")
	}

	@(test)
	ws_server_message_boundary :: proc(t: ^testing.T) {
		payload := make([]byte, MAX_SERVER_MESSAGE + 1)
		defer delete(payload)
		for op in ([?]Opcode{.Text, .Binary}) {
			c := Conn{allocator = context.allocator}
			testing.expect(t, ws_send(&c, op, payload[:MAX_SERVER_MESSAGE]), "A maximum stored record plus envelope must enqueue")
			testing.expect_value(t, c.out_count, 1)
			testing.expect_value(t, c.out_bytes, MAX_SERVER_MESSAGE + 10)
			testing.expect(t, !ws_send(&c, op, payload), "One byte beyond the server message bound must fail")
			testing.expect(t, c.stopping && c.out_count == 1)
			ws_queue_discard(&c)
			testing.expect_value(t, c.out_bytes, 0)
		}
	}

	@(test)
	ws_queue_history_burst :: proc(t: ^testing.T) {
		c := Conn{allocator = context.allocator}
		defer ws_queue_discard(&c)
		// An ordinary historical REQ must enqueue completely even when the
		// sender has not been scheduled yet. Include an EOSE and a ping.
		payload := make([]byte, MAX_QUERY_BYTES / MAX_LIMIT)
		defer delete(payload)
		for _ in 0..<MAX_LIMIT do testing.expect(t, ws_send(&c, .Text, payload))
		testing.expect(t, ws_send_text(&c, "[\"EOSE\",\"history\"]"))
		testing.expect(t, ws_send(&c, .Ping, {}))
		testing.expect(t, !c.stopping && c.out_count == MAX_LIMIT + 2)
	}

	@(test)
	ws_queue_byte_budget :: proc(t: ^testing.T) {
		c := Conn{allocator = context.allocator}
		defer ws_queue_discard(&c)
		payload := make([]byte, MAX_MESSAGE)
		defer delete(payload)
		full_frames := MAX_OUTBOUND_BYTES / (MAX_MESSAGE + 10)
		for _ in 0..<full_frames do testing.expect(t, ws_send(&c, .Binary, payload))
		in_flight := ws_queue_pop(&c)
		defer delete(in_flight, c.allocator)
		// Fill the remaining wire-byte budget, including every header and
		// the popped/in-flight frame, independently of the configured cap.
		remainder := MAX_OUTBOUND_BYTES - full_frames * (MAX_MESSAGE + 10)
		testing.expect(t, remainder > 65545 && remainder <= MAX_MESSAGE + 10)
		testing.expect(t, ws_send(&c, .Binary, payload[:remainder-10]))
		testing.expect_value(t, c.out_bytes, MAX_OUTBOUND_BYTES)
		testing.expect(t, !ws_send(&c, .Text, {}))
		testing.expect(t, c.stopping, "Budget overflow must stop the slow client")
		testing.expect_value(t, c.out_bytes, MAX_OUTBOUND_BYTES)
		c.out_bytes -= len(in_flight)
		ws_queue_discard(&c)
		testing.expect_value(t, c.out_bytes, 0)
		testing.expect(t, !ws_send(&c, .Ping, {}), "Stopped connections cannot enqueue")
	}

	@(test)
	ws_queue_ownership_close_and_slots :: proc(t: ^testing.T) {
		c := Conn{allocator = context.allocator}
		defer ws_queue_discard(&c)
		payload := [3]byte{'a', 'b', 'c'}
		testing.expect(t, ws_send(&c, .Text, payload[:]))
		payload[0] = 'x'
		in_flight := ws_queue_pop(&c)
		defer delete(in_flight, c.allocator)
		testing.expect_value(t, string(in_flight[2:]), "abc")
		testing.expect_value(t, in_flight[0], byte(0x81))
		for _ in 0..<MAX_OUTBOUND_FRAMES do testing.expect(t, ws_send(&c, .Ping, {}))
		testing.expect(t, ws_send(&c, .Close, []byte{0x03, 0xe8}), "Close bypasses a full pending queue")
		testing.expect_value(t, c.out_count, 1)
		testing.expect_value(t, c.out_bytes, len(in_flight) + 4)
		testing.expect(t, c.closing && !ws_send(&c, .Text, payload[:]))
		close_frame := ws_queue_pop(&c)
		testing.expect_value(t, close_frame[0], byte(0x88))
		testing.expect_value(t, close_frame[3], byte(0xe8))
		c.out_bytes -= len(close_frame) + len(in_flight)
		delete(close_frame, c.allocator)

		full := Conn{allocator = context.allocator}
		defer ws_queue_discard(&full)
		for _ in 0..<MAX_OUTBOUND_FRAMES do testing.expect(t, ws_send(&full, .Pong, {}))
		testing.expect(t, !ws_send(&full, .Pong, {}) && full.stopping)
		testing.expect_value(t, full.out_bytes, 2 * MAX_OUTBOUND_FRAMES)
	}

	// Real loopback sockets, ephemeral port, no globals or sleeps. Timeout
	// options ensure a regression reports failure rather than hanging a suite.
	ws_test_pair :: proc(t: ^testing.T) -> (net.TCP_Socket, net.TCP_Socket, bool) {
		listener, err := net.listen_tcp({address = net.IP4_Address{127, 0, 0, 1}, port = 0})
		if !testing.expect(t, err == nil) do return {}, {}, false
		defer net.close(listener)
		endpoint, ep_err := net.bound_endpoint(listener)
		if !testing.expect(t, ep_err == nil) do return {}, {}, false
		client, dial_err := net.dial_tcp(endpoint)
		if !testing.expect(t, dial_err == nil) do return {}, {}, false
		server, _, accept_err := net.accept_tcp(listener)
		if !testing.expect(t, accept_err == nil) {
			net.close(client)
			return {}, {}, false
		}
		for sock in ([?]net.TCP_Socket{client, server}) {
			net.set_option(sock, .Receive_Timeout, time.Second)
			net.set_option(sock, .Send_Timeout, time.Second)
		}
		return client, server, true
	}

	ws_test_expect_scratch_empty :: proc(t: ^testing.T, arena: ^mem.Dynamic_Arena) {
		testing.expect(t, arena.current_block == nil && len(arena.used_blocks) == 0 && len(arena.unused_blocks) == 0 && len(arena.out_band_allocations) == 0)
	}

	@(test)
	ws_frame_scratch_lifecycle :: proc(t: ^testing.T) {
		client, server, pair_ok := ws_test_pair(t)
		if !pair_ok do return
		defer net.close(client)
		defer net.close(server)
		arena: mem.Dynamic_Arena
		mem.dynamic_arena_init(&arena)
		defer mem.dynamic_arena_destroy(&arena)
		context.temp_allocator = mem.dynamic_arena_allocator(&arena)
		c := Conn{sock = server, allocator = context.allocator}
		defer ws_queue_discard(&c)
		state: WS_Assembly
		defer ws_assembly_reset(&state)
		frames := [?][]byte{
			{0x89, 0x81, 1, 2, 3, 4, 'x' ~ 1}, // masked ping with payload
			{0x8a, 0x80, 0, 0, 0, 0}, // empty pong
			{0x02, 0x81, 0, 0, 0, 0, 'a'}, // fragmented binary
			{0x00, 0x80, 0, 0, 0, 0}, // empty continuation
			{0x80, 0x81, 0, 0, 0, 0, 'b'}, // final continuation
			{0x82, 0x80, 0, 0, 0, 0}, // empty complete message
		}
		for frame in frames {
			_ = make([]byte, 17, context.temp_allocator) // also exercises empty-frame cleanup
			if !testing.expect(t, send_all(client, frame)) do return
			keep, flush := ws_read_step(&c, &state)
			testing.expect(t, keep && !flush)
			ws_test_expect_scratch_empty(t, &arena)
		}
		testing.expect_value(t, c.out_count, 1)
		testing.expectf(t, c.outbound[c.out_head][2] == byte('x'), "Queued Pong outlives frame scratch")
		_ = make([]byte, 17, context.temp_allocator)
		testing.expect(t, send_all(client, []byte{0x88, 0x80, 0, 0, 0, 0}))
		close_keep, close_flush := ws_read_step(&c, &state)
		testing.expect(t, !close_keep && close_flush && c.closing)
		ws_test_expect_scratch_empty(t, &arena)
		// Rejection after payload allocation must free scratch too.
		_ = make([]byte, 17, context.temp_allocator)
		testing.expect(t, send_all(client, []byte{0x88, 0x81, 0, 0, 0, 0, 0}))
		keep, flush := ws_read_step(&c, &state)
		testing.expect(t, !keep && !flush)
		ws_test_expect_scratch_empty(t, &arena)
		// EOF halfway through a declared payload is another allocation path.
		_ = make([]byte, 17, context.temp_allocator)
		testing.expect(t, send_all(client, []byte{0x82, 0x83, 0, 0, 0, 0, 'x'}))
		net.shutdown(client, .Send)
		keep, flush = ws_read_step(&c, &state)
		testing.expect(t, !keep && !flush)
		ws_test_expect_scratch_empty(t, &arena)
	}

	@(test)
	ws_sender_flush_and_join :: proc(t: ^testing.T) {
		client, server, pair_ok := ws_test_pair(t)
		if !pair_ok do return
		defer net.close(client)
		defer net.close(server)
		c := Conn{sock = server, allocator = context.allocator}
		defer ws_queue_discard(&c)
		// Closing before sender start deterministically exercises prioritization.
		testing.expect(t, ws_send(&c, .Text, []byte{'x'}))
		testing.expect(t, ws_send(&c, .Close, []byte{0x03, 0xe8}))
		c.sender = thread.create_and_start_with_poly_data(&c, ws_sender)
		if !testing.expect(t, c.sender != nil) do return
		defer thread.destroy(c.sender)
		actual: [4]byte
		testing.expect(t, recv_exact(client, actual[:]))
		testing.expect_value(t, actual, [4]byte{0x88, 2, 0x03, 0xe8})
		thread.join(c.sender)
		testing.expect(t, c.stopping && c.out_count == 0 && c.out_bytes == 0)
		probe: [1]byte
		n, _ := net.recv_tcp(client, probe[:])
		testing.expectf(t, n == 0, "Joined sender shuts down the socket after Close")
	}

	@(test)
	ws_sender_stop_and_join :: proc(t: ^testing.T) {
		client, server, pair_ok := ws_test_pair(t)
		if !pair_ok do return
		defer net.close(client)
		defer net.close(server)
		c := Conn{sock = server, allocator = context.allocator}
		defer ws_queue_discard(&c)
		for _ in 0..<MAX_OUTBOUND_FRAMES do testing.expect(t, ws_send(&c, .Ping, {}))
		testing.expect(t, !ws_send(&c, .Ping, {}) && c.stopping)
		c.sender = thread.create_and_start_with_poly_data(&c, ws_sender)
		if !testing.expect(t, c.sender != nil) do return
		thread.destroy(c.sender)
		testing.expect(t, c.out_count == 0 && c.out_bytes == 0)
		probe: [1]byte
		n, _ := net.recv_tcp(client, probe[:])
		testing.expectf(t, n == 0, "Overflow stops the sender without emitting queued frames")
	}
}
