package relay

// Nostr hex adapter for the pure-Odin BIP-340 verifier. All inputs are
// public; schnorr_verify is variable-time and must not be used for signing.
// Default builds have no libsecp256k1 dependency. During the production
// soak, VERIFY_DUAL compares both implementations and fails closed on any
// disagreement. The C context is initialized once before worker threads.

import "core:c"
import "core:os"
import "core:encoding/hex"
import "core:fmt"

VERIFY_DUAL :: #config(VERIFY_DUAL, false)

when VERIFY_DUAL {
	foreign import secp "system:secp256k1"
	foreign secp {
		secp256k1_context_create :: proc "c" (flags: c.uint) -> rawptr ---
		secp256k1_context_destroy :: proc "c" (ctx: rawptr) ---
		secp256k1_xonly_pubkey_parse :: proc "c" (ctx: rawptr, pubkey: ^[64]u8, input32: ^u8) -> c.int ---
		secp256k1_schnorrsig_verify :: proc "c" (ctx: rawptr, sig64: ^u8, msg: ^u8, msglen: c.size_t, pubkey: ^[64]u8) -> c.int ---
	}
	g_secp_ctx: rawptr
}

verify_init :: proc() {
	when VERIFY_DUAL {
		g_secp_ctx = secp256k1_context_create(0x0101)
		if g_secp_ctx == nil {
			fmt.eprintln("[relay] secp256k1 reference context creation failed")
			os.exit(1)
		}
		fmt.println("[relay] verifier: pure Odin + libsecp256k1 differential soak (fail closed)")
	} else {
		fmt.println("[relay] verifier: pure Odin BIP-340")
	}
}

@(private = "file")
verify_decode_hex :: proc(src: string, dst: []u8) -> bool {
	if len(src) != 2 * len(dst) do return false
	for i in 0..<len(dst) {
		value, ok := hex.decode_sequence(src[2*i:2*i+2])
		if !ok do return false
		dst[i] = value
	}
	return true
}

verify_sig :: proc(id: string, pubkey: string, sig: string) -> bool {
	message: [32]u8
	key: [32]u8
	signature: [64]u8
	if !verify_decode_hex(id, message[:]) ||
	   !verify_decode_hex(pubkey, key[:]) ||
	   !verify_decode_hex(sig, signature[:]) {
		return false
	}

	valid := schnorr_verify(message[:], key[:], signature[:])
	when VERIFY_DUAL {
		parsed: [64]u8
		reference := secp256k1_xonly_pubkey_parse(g_secp_ctx, &parsed, &key[0]) == 1 &&
			secp256k1_schnorrsig_verify(g_secp_ctx, &signature[0], &message[0], len(message), &parsed) == 1
		if valid != reference {
			fmt.eprintfln("[relay] VERIFIER DISAGREEMENT event=%s pure=%v reference=%v; rejecting", id, valid, reference)
			return false
		}
	}
	return valid
}
