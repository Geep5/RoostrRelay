package relay

// Pre-parse JSON nesting guard. core:encoding/json descends recursively,
// so a few kilobytes of '[' overflow the reader thread's stack before any
// size limit applies. This scanner bounds depth without allocating: it
// counts '{'/'[' vs '}'/']' while skipping string literals and backslash
// escapes. False when depth exceeds max_depth or nesting never balances
// (mismatched closers make depth negative; an unclosed opener leaves it
// positive). Anything it accepts still goes through the real parser.
json_depth_ok :: proc(data: []u8, max_depth := 128) -> bool {
	depth := 0
	in_string := false
	escaped := false
	for b in data {
		if in_string {
			if escaped {
				escaped = false
			} else if b == '\\' {
				escaped = true
			} else if b == '"' {
				in_string = false
			}
			continue
		}
		switch b {
		case '"':
			in_string = true
		case '{', '[':
			depth += 1
			if depth > max_depth do return false
		case '}', ']':
			depth -= 1
			if depth < 0 do return false
		}
	}
	return depth == 0
}
