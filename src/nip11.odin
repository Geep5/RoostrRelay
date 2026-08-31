package relay

// NIP-11 relay information document, served on GET / with
// Accept: application/nostr+json. Fields come from env so the same
// binary works anywhere.

import "core:fmt"
import "core:os"
import "core:strings"

nip11_doc :: proc() -> []byte {
	name := os.get_env("RELAY_NAME", context.temp_allocator)
	if name == "" do name = "RoostrRelay"
	desc := os.get_env("RELAY_DESCRIPTION", context.temp_allocator)
	if desc == "" do desc = "A Nostr relay in Odin backing Roostr sync."
	pubkey := os.get_env("RELAY_PUBKEY", context.temp_allocator)
	contact := os.get_env("RELAY_CONTACT", context.temp_allocator)

	sb := strings.builder_make(context.temp_allocator)
	strings.write_string(&sb, `{"name":`)
	canon_escape(&sb, name)
	strings.write_string(&sb, `,"description":`)
	canon_escape(&sb, desc)
	if pubkey != "" {
		strings.write_string(&sb, `,"pubkey":`)
		canon_escape(&sb, pubkey)
	}
	if contact != "" {
		strings.write_string(&sb, `,"contact":`)
		canon_escape(&sb, contact)
	}
	fmt.sbprintf(&sb,
		`,"supported_nips":[1,9,11],"software":"https://github.com/Geep5/RoostrRelay","version":"0.1.0",`+
		`"limitation":{{"max_message_length":%d,"max_subscriptions":%d,"max_filters":%d,"max_limit":%d,`+
		`"auth_required":false,"payment_required":false,"restricted_writes":%v}}}}`,
		MAX_MESSAGE, MAX_SUBS_PER_CONN, MAX_FILTERS_PER_REQ, MAX_LIMIT, len(g_allowed) > 0)
	return transmute([]byte)strings.to_string(sb)
}
