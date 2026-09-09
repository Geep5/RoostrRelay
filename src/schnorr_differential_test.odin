package relay

import "core:c"
import "core:fmt"
import "core:testing"
import "core:time"

// No foreign import or signing entry point exists in a production build or
// ordinary pure test build. The C signer is only a deterministic test oracle.
when ODIN_TEST && #config(VERIFY_DIFFERENTIAL, false) {
	foreign import schnorr_test_secp "system:secp256k1"

	foreign schnorr_test_secp {
		@(link_name="secp256k1_context_create")
		schnorr_test_c_create :: proc "c" (flags: c.uint) -> rawptr ---
		@(link_name="secp256k1_context_destroy")
		schnorr_test_c_destroy :: proc "c" (ctx: rawptr) ---
		@(link_name="secp256k1_keypair_create")
		schnorr_test_c_keypair :: proc "c" (ctx: rawptr, keypair: ^[96]u8, secret: ^u8) -> c.int ---
		@(link_name="secp256k1_keypair_xonly_pub")
		schnorr_test_c_public :: proc "c" (ctx: rawptr, pubkey: ^[64]u8, parity: ^c.int, keypair: ^[96]u8) -> c.int ---
		@(link_name="secp256k1_xonly_pubkey_serialize")
		schnorr_test_c_serialize :: proc "c" (ctx: rawptr, output: ^u8, pubkey: ^[64]u8) -> c.int ---
		@(link_name="secp256k1_xonly_pubkey_parse")
		schnorr_test_c_parse :: proc "c" (ctx: rawptr, pubkey: ^[64]u8, input: ^u8) -> c.int ---
		@(link_name="secp256k1_schnorrsig_sign_custom")
		schnorr_test_c_sign :: proc "c" (ctx: rawptr, signature: ^u8, message: ^u8, message_len: c.size_t, keypair: ^[96]u8, extraparams: rawptr) -> c.int ---
		@(link_name="secp256k1_schnorrsig_verify")
		schnorr_test_c_verify :: proc "c" (ctx: rawptr, signature: ^u8, message: ^u8, message_len: c.size_t, pubkey: ^[64]u8) -> c.int ---
	}

	Schnorr_Differential_Stats :: struct {
		checks, accepted, rejected: int,
		pure_time, c_time: time.Duration,
	}

	// Xorshift64, fixed nonzero seed. These bytes are deliberately public test
	// data, NOT cryptographically secure randomness or production secret keys.
	schnorr_test_fill :: proc(state: ^u64, output: []u8) {
		for &b in output {
			state^ ~= state^ << 13
			state^ ~= state^ >> 7
			state^ ~= state^ << 17
			b = u8(state^ >> 56)
		}
	}

	schnorr_test_c_accepts :: proc(ctx: rawptr, message, pubkey, signature: []u8) -> bool {
		if len(pubkey) != 32 || len(signature) != 64 do return false
		parsed: [64]u8
		if schnorr_test_c_parse(ctx, &parsed, &pubkey[0]) != 1 do return false
		message_ptr: ^u8
		if len(message) > 0 do message_ptr = &message[0]
		return schnorr_test_c_verify(ctx, &signature[0], message_ptr, c.size_t(len(message)), &parsed) == 1
	}

	schnorr_test_compare :: proc(t: ^testing.T, ctx: rawptr, stats: ^Schnorr_Differential_Stats, message, pubkey, signature: []u8, expected: bool, corpus: string, index: int) {
		start := time.now()
		pure := schnorr_verify(message, pubkey, signature)
		stats.pure_time += time.since(start)
		start = time.now()
		oracle := schnorr_test_c_accepts(ctx, message, pubkey, signature)
		stats.c_time += time.since(start)
		testing.expectf(t, pure == oracle && oracle == expected, "%s case %d: pure=%v C=%v expected=%v", corpus, index, pure, oracle, expected)
		stats.checks += 1
		if oracle {
			stats.accepted += 1
		} else {
			stats.rejected += 1
		}
	}

	@(test)
	schnorr_differential :: proc(t: ^testing.T) {
		ctx := schnorr_test_c_create(1) // SECP256K1_CONTEXT_NONE
		if !testing.expect(t, ctx != nil) do return
		defer schnorr_test_c_destroy(ctx)
		stats: Schnorr_Differential_Stats
		start := time.now()
		vectors := schnorr_test_vectors(t)
		for &v, i in vectors {
			schnorr_test_compare(t, ctx, &stats, v.message[:v.message_len], v.pubkey[:], v.signature[:], v.valid, "official", i)
		}

		state: u64 = 0x3405ec0256a11ce1
		lengths := [?]int{0, 1, 17, 31, 32, 33, 55, 56, 63, 64, 65, 100, 127, 128, 129, 255}
		for i in 0..<1000 {
			secret: [32]u8
			schnorr_test_fill(&state, secret[:])
			secret[0] &= 0x7f // canonical scalar below n
			secret[31] |= 1 // nonzero
			if i < 2 {
				secret = {}
				secret[31] = u8(i+1)
			} else if i < 4 {
				if !schnorr_test_decode(t, "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140", secret[:]) do return
				secret[31] -= u8(i-2) // n-1 and n-2
			}
			keypair: [96]u8
			parsed: [64]u8
			pubkey: [32]u8
			signature: [64]u8
			if !testing.expect(t, schnorr_test_c_keypair(ctx, &keypair, &secret[0]) == 1) do return
			if !testing.expect(t, schnorr_test_c_public(ctx, &parsed, nil, &keypair) == 1) do return
			if !testing.expect(t, schnorr_test_c_serialize(ctx, &pubkey[0], &parsed) == 1) do return
			message: [256]u8
			schnorr_test_fill(&state, message[:])
			message_len := lengths[i % len(lengths)]
			message_ptr: ^u8
			if message_len > 0 do message_ptr = &message[0]
			// NULL extraparams selects the standard BIP-340 nonce with zero aux.
			if !testing.expect(t, schnorr_test_c_sign(ctx, &signature[0], message_ptr, c.size_t(message_len), &keypair, nil) == 1) do return
			schnorr_test_compare(t, ctx, &stats, message[:message_len], pubkey[:], signature[:], true, "signed", i)

			changed_message := message
			changed_message_len := message_len
			if message_len == 0 {
				changed_message_len = 1
			} else {
				changed_message[i % message_len] ~= 1
			}
			schnorr_test_compare(t, ctx, &stats, changed_message[:changed_message_len], pubkey[:], signature[:], false, "message bit", i)
			changed_key := pubkey
			changed_key[i % 32] ~= u8(1 << uint(i % 8))
			schnorr_test_compare(t, ctx, &stats, message[:message_len], changed_key[:], signature[:], false, "key bit", i)
			for offset in ([?]int{0, 32}) {
				changed_sig := signature
				changed_sig[offset + i % 32] ~= u8(1 << uint(i % 8))
				schnorr_test_compare(t, ctx, &stats, message[:message_len], pubkey[:], changed_sig[:], false, "signature bit", 2*i + offset/32)
			}

			// Independent uniformly distributed invalid triples, not just edits
			// of valid signatures; exercises key lift failures and curve equations.
			schnorr_test_fill(&state, message[:])
			schnorr_test_fill(&state, pubkey[:])
			schnorr_test_fill(&state, signature[:])
			schnorr_test_compare(t, ctx, &stats, message[:message_len], pubkey[:], signature[:], false, "random triple", i)
		}
		testing.expect_value(t, stats.checks, 6019)
		testing.expect_value(t, stats.accepted, 1009)
		testing.expect_value(t, stats.rejected, 5010)
		fmt.printfln("BIP-340 differential: seed=0x3405ec0256a11ce1; 19 official, 1000 signed, 4000 mutations, 1000 random triples")
		fmt.printfln("BIP-340 differential: %d checks, %d accepted, %d rejected; pure=%.3f ms, C=%.3f ms, total=%.3f ms (verification timings include clock overhead)", stats.checks, stats.accepted, stats.rejected, time.duration_milliseconds(stats.pure_time), time.duration_milliseconds(stats.c_time), time.duration_milliseconds(time.since(start)))
	}
}
