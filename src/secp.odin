package relay

// libsecp256k1 binding - exactly the verification surface, nothing else.
// BIP-340 schnorr verify over the 32-byte event id, x-only pubkey.
//
// macOS: brew's libsecp256k1 (built with schnorrsig).
// Linux image: built statically in the Dockerfile builder stage.

import "core:c"
import "core:encoding/hex"
import "core:fmt"
import "core:os"

foreign import secp "system:secp256k1"

// SECP256K1_FLAGS_TYPE_CONTEXT | SECP256K1_FLAGS_BIT_CONTEXT_VERIFY.
// (VERIFY is a deprecated alias for NONE in current releases, but this
// value is accepted by every version that has schnorrsig at all.)
SECP256K1_CONTEXT_VERIFY :: 0x0101

foreign secp {
	secp256k1_context_create :: proc "c" (flags: c.uint) -> rawptr ---
	secp256k1_context_destroy :: proc "c" (ctx: rawptr) ---
	secp256k1_xonly_pubkey_parse :: proc "c" (ctx: rawptr, pubkey: ^[64]u8, input32: ^u8) -> c.int ---
	secp256k1_schnorrsig_verify :: proc "c" (ctx: rawptr, sig64: ^u8, msg: ^u8, msglen: c.size_t, pubkey: ^[64]u8) -> c.int ---
}

g_secp_ctx: rawptr

verify_init :: proc() {
	g_secp_ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY)
	if g_secp_ctx == nil {
		fmt.eprintln("[relay] secp256k1 context creation failed")
		os.exit(1)
	}
}

// id/pubkey/sig are lowercase hex (64/64/128 chars, pre-validated).
verify_sig :: proc(id: string, pubkey: string, sig: string) -> bool {
	id_b, iok := hex.decode(transmute([]byte)id, context.temp_allocator)
	pk_b, pok := hex.decode(transmute([]byte)pubkey, context.temp_allocator)
	sg_b, sok := hex.decode(transmute([]byte)sig, context.temp_allocator)
	if !iok || !pok || !sok do return false
	if len(id_b) != 32 || len(pk_b) != 32 || len(sg_b) != 64 do return false

	parsed: [64]u8
	if secp256k1_xonly_pubkey_parse(g_secp_ctx, &parsed, &pk_b[0]) != 1 do return false
	return secp256k1_schnorrsig_verify(g_secp_ctx, &sg_b[0], &id_b[0], 32, &parsed) == 1
}
