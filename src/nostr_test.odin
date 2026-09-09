package relay

import "core:strings"
import "core:testing"

when ODIN_TEST {

	@(test)
	json_depth_guard_bounds_nesting :: proc(t: ^testing.T) {
		deep := strings.repeat("[", 200, context.temp_allocator)
		testing.expect(t, !json_depth_ok(transmute([]u8)deep))
		balanced := strings.builder_make(context.temp_allocator)
		for i in 0..<128 do strings.write_byte(&balanced, '[')
		for i in 0..<128 do strings.write_byte(&balanced, ']')
		testing.expect(t, json_depth_ok(transmute([]u8)strings.to_string(balanced)))
		testing.expect(t, json_depth_ok(transmute([]u8)string(`["EVENT",{"tags":[["p","abc"]],"content":"hi"}]`)))
		// Brackets inside string literals and behind backslash escapes are
		// not structure.
		testing.expect(t, json_depth_ok(transmute([]u8)string(`"[[[{"`)))
		testing.expect(t, json_depth_ok(transmute([]u8)string(`["]\",\"[",""]"]`)))
		// Nesting that never balances is rejected before the parser runs.
		testing.expect(t, !json_depth_ok(transmute([]u8)string("[")))
		testing.expect(t, !json_depth_ok(transmute([]u8)string("]")))
		testing.expect(t, !json_depth_ok(transmute([]u8)string("{}]")))
		// The caller's cap is honoured.
		testing.expect(t, !json_depth_ok(transmute([]u8)string("[[[]]]"), 2))
	}

	@(test)
	event_rate_limit_window :: proc(t: ^testing.T) {
		window: i64
		count: int
		for i in 0..<MAX_EVENTS_PER_WINDOW {
			testing.expect(t, event_rate_ok(&window, &count, 1000))
		}
		testing.expect(t, !event_rate_ok(&window, &count, 1000))
		testing.expect(t, !event_rate_ok(&window, &count, 1000))
		testing.expect(t, event_rate_ok(&window, &count, 1001))
		testing.expect_value(t, count, 1)
	}
}
