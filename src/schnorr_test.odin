package relay

	import "core:encoding/csv"
	import "core:encoding/hex"
	import "core:fmt"
	import "core:testing"
	import "core:time"

when ODIN_TEST {

	// Official BIP-340 vectors by Pieter Wuille, Jonas Nick, and Tim Ruffing.
	// Source: https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv
	// BIP-340 License-Code: BSD-2-Clause OR MIT OR CC0-1.0; used under CC0-1.0.
	// https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
	// Fixture SHA256: 34c9d1d9c3a88d524bc80778540dc43f8306ec249a7485293063c376db851c2d
	SCHNORR_TEST_CSV :: #load("../testdata/bip340.csv", string)

	Schnorr_Test_Vector :: struct {
		message: [100]u8,
		message_len: int,
		pubkey: [32]u8,
		signature: [64]u8,
		valid: bool,
	}

	schnorr_test_decode :: proc(t: ^testing.T, text: string, dst: []u8) -> bool {
		if !testing.expect_value(t, len(text), 2 * len(dst)) do return false
		for &value, i in dst {
			decoded, ok := hex.decode_sequence(text[2*i:2*i+2])
			if !testing.expectf(t, ok, "Invalid fixture hex at byte %d", i) do return false
			value = decoded
		}
		return true
	}

	schnorr_test_vectors :: proc(t: ^testing.T) -> [19]Schnorr_Test_Vector {
		vectors: [19]Schnorr_Test_Vector
		r: csv.Reader
		r.reuse_record = true
		r.reuse_record_buffer = true
		csv.reader_init_with_string(&r, SCHNORR_TEST_CSV)
		defer csv.reader_destroy(&r)
		header, err := csv.read(&r)
		if !testing.expect(t, err == nil && len(header) == 8, "Invalid BIP-340 CSV header") do return vectors
		count := 0
		for row, _, row_err in csv.iterator_next(&r) {
			if !testing.expect(t, row_err == nil && len(row) == 8) do return vectors
			if !testing.expect(t, count < len(vectors), "Unexpected extra BIP-340 vector") do return vectors
			v := &vectors[count]
			if !testing.expect(t, len(row[4]) % 2 == 0 && len(row[4])/2 <= len(v.message)) do return vectors
			v.message_len = len(row[4])/2
			if !schnorr_test_decode(t, row[2], v.pubkey[:]) do return vectors
			if !schnorr_test_decode(t, row[4], v.message[:v.message_len]) do return vectors
			if !schnorr_test_decode(t, row[5], v.signature[:]) do return vectors
			if !testing.expect(t, row[6] == "TRUE" || row[6] == "FALSE") do return vectors
			v.valid = row[6] == "TRUE"
			count += 1
		}
		testing.expect(t, csv.is_io_error(csv.iterator_last_error(r), .EOF), "BIP-340 CSV must end without a parse error")
		testing.expect_value(t, count, len(vectors))
		return vectors
	}

	@(test)
	schnorr_official_vectors :: proc(t: ^testing.T) {
		vectors := schnorr_test_vectors(t)
		start := time.now()
		accepted := 0
		for &v, i in vectors {
			got := schnorr_verify(v.message[:v.message_len], v.pubkey[:], v.signature[:])
			testing.expectf(t, got == v.valid, "BIP-340 vector %d: expected %v, got %v", i, v.valid, got)
			if got do accepted += 1
		}
		// Includes odd R, non-curve keys/R, infinity (vectors 9 and 10), r=p,
		// s=n, pubkey>p, and message lengths 0, 1, 17, 32, and 100.
		testing.expect_value(t, accepted, 9)
		fmt.printfln("BIP-340 official: %d vectors, %d accepted, %d rejected, %.3f ms", len(vectors), accepted, len(vectors)-accepted, time.duration_milliseconds(time.since(start)))
	}

	@(test)
	schnorr_sizes_and_mutations :: proc(t: ^testing.T) {
		vectors := schnorr_test_vectors(t)
		checks := 0
		for &v, vector_index in vectors {
			if !v.valid do continue
			message := v.message[:v.message_len]
			pk_extra: [33]u8
			sig_extra: [65]u8
			copy(pk_extra[:], v.pubkey[:])
			copy(sig_extra[:], v.signature[:])
			for size in ([?]int{0, 1, 31, 33}) {
				testing.expectf(t, !schnorr_verify(message, pk_extra[:size], v.signature[:]), "Vector %d accepted key length %d", vector_index, size)
				checks += 1
			}
			for size in ([?]int{0, 1, 32, 63, 65}) {
				testing.expectf(t, !schnorr_verify(message, v.pubkey[:], sig_extra[:size]), "Vector %d accepted signature length %d", vector_index, size)
				checks += 1
			}
			for i in 0..<len(v.signature) {
				altered := v.signature
				altered[i] ~= 1
				testing.expectf(t, !schnorr_verify(message, v.pubkey[:], altered[:]), "Vector %d accepted altered signature byte %d", vector_index, i)
				checks += 1
			}
			for i in 0..<len(v.pubkey) {
				altered := v.pubkey
				altered[i] ~= 1
				testing.expectf(t, !schnorr_verify(message, altered[:], v.signature[:]), "Vector %d accepted altered key byte %d", vector_index, i)
				checks += 1
			}
			for i in 0..<v.message_len {
				altered := v.message
				altered[i] ~= 1
				testing.expectf(t, !schnorr_verify(altered[:v.message_len], v.pubkey[:], v.signature[:]), "Vector %d accepted altered message byte %d", vector_index, i)
				checks += 1
			}
			extended: [101]u8
			copy(extended[:], message)
			testing.expect(t, !schnorr_verify(extended[:v.message_len+1], v.pubkey[:], v.signature[:]))
			checks += 1
			if v.message_len > 0 {
				testing.expect(t, !schnorr_verify(message[:len(message)-1], v.pubkey[:], v.signature[:]))
				checks += 1
			}
		}
		fmt.printfln("BIP-340 sizes/mutations: %d rejection checks", checks)
	}

	@(test)
	schnorr_encoding_boundaries :: proc(t: ^testing.T) {
		vectors := schnorr_test_vectors(t)
		v := vectors[0]
		// Below p/n these fail the equation, not range validation.
		boundaries := [?]string{
			"0000000000000000000000000000000000000000000000000000000000000000",
			"0000000000000000000000000000000000000000000000000000000000000001",
			"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2E",
			"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",
			"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30",
			"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140",
			"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
			"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364142",
			"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
		}
		for value, i in boundaries {
			bytes: [32]u8
			if !schnorr_test_decode(t, value, bytes[:]) do return
			testing.expectf(t, !schnorr_verify(v.message[:v.message_len], bytes[:], v.signature[:]), "Accepted key boundary %d", i)
			for offset in ([?]int{0, 32}) {
				altered := v.signature
				copy(altered[offset:offset+32], bytes[:])
				testing.expectf(t, !schnorr_verify(v.message[:v.message_len], v.pubkey[:], altered[:]), "Accepted signature boundary %d at %d", i, offset)
			}
		}
	}

	// Independent Python oracle, p=2**256-2**32-977: columns are
	// a,b,(a+b)%p,(a-b)%p,(a*b)%p,pow(a,p-2,p). All pairs from
	// [0,1,2,2**32-1,2**32,2**64-1,2**64,2**128-1,2**128,
	// 2**192-1,2**192,p-2,p-1], plus 128 pairs from Random(340).randrange(p).
	@(test)
	schnorr_field_oracle :: proc(t: ^testing.T) {
		r: csv.Reader
		r.reuse_record = true
		r.reuse_record_buffer = true
		csv.reader_init_with_string(&r, #load("../testdata/schnorr-field.csv", string))
		defer csv.reader_destroy(&r)
		header, err := csv.read(&r)
		if !testing.expect(t, err == nil && len(header) == 6) do return
		count := 0
		inverse_exponent := SCHNORR_P
		inverse_exponent[0] -= 2
		for row, index in csv.iterator_next(&r) {
			if !testing.expect(t, len(row) == 6) do return
			values: [6]Schnorr_U256
			for field, i in row {
				bytes: [32]u8
				if !schnorr_test_decode(t, field, bytes[:]) do return
				values[i] = schnorr_u256_from_bytes(bytes[:])
			}
			testing.expectf(t, schnorr_fe_add(values[0], values[1]) == values[2], "Field addition oracle row %d", index)
			testing.expectf(t, schnorr_fe_sub(values[0], values[1]) == values[3], "Field subtraction oracle row %d", index)
			testing.expectf(t, schnorr_fe_mul(values[0], values[1]) == values[4], "Field multiplication oracle row %d", index)
			testing.expectf(t, schnorr_fe_pow(values[0], inverse_exponent) == values[5], "Field inverse oracle row %d", index)
			count += 1
		}
		testing.expect(t, csv.is_io_error(csv.iterator_last_error(r), .EOF))
		testing.expect_value(t, count, 297)
		fmt.printfln("BIP-340 field oracle: %d rows, %d independent arithmetic checks", count, count*4)
	}

	@(test)
	schnorr_point_infinity :: proc(t: ^testing.T) {
		zero := Schnorr_U256{}
		infinity := Schnorr_Point{}
		negative_g := SCHNORR_G
		negative_g.y = schnorr_fe_sub(zero, negative_g.y)
		testing.expect(t, schnorr_point_add(SCHNORR_G, negative_g).z == zero)
		testing.expect(t, schnorr_point_add(negative_g, SCHNORR_G).z == zero)
		testing.expect(t, schnorr_point_double(infinity).z == zero)
		testing.expect_value(t, schnorr_point_add(infinity, SCHNORR_G), SCHNORR_G)
		testing.expect_value(t, schnorr_point_add(SCHNORR_G, infinity), SCHNORR_G)
		a := schnorr_point_add(SCHNORR_G, SCHNORR_G)
		b := schnorr_point_double(SCHNORR_G)
		testing.expect(t, a.z != zero && b.z != zero)
		az2 := schnorr_fe_mul(a.z, a.z)
		bz2 := schnorr_fe_mul(b.z, b.z)
		testing.expect(t, schnorr_fe_mul(a.x, bz2) == schnorr_fe_mul(b.x, az2))
		testing.expect(t, schnorr_fe_mul(a.y, schnorr_fe_mul(bz2, b.z)) == schnorr_fe_mul(b.y, schnorr_fe_mul(az2, a.z)))
		testing.expect(t, schnorr_double_scalar(zero, zero, SCHNORR_G).z == zero)
		testing.expect(t, schnorr_double_scalar(SCHNORR_N, zero, SCHNORR_G).z == zero)
		testing.expect(t, schnorr_double_scalar(Schnorr_U256{1, 0, 0, 0}, Schnorr_U256{1, 0, 0, 0}, SCHNORR_G).z == zero)
		_, ok := schnorr_lift_x(SCHNORR_P)
		testing.expect(t, !ok)
	}

	@(test)
	schnorr_hex_wrapper :: proc(t: ^testing.T) {
		// Only this test touches the optional global C context; other tests use
		// schnorr_verify or their own local C context.
		when VERIFY_DUAL do verify_init()
		defer {
			when VERIFY_DUAL {
				secp256k1_context_destroy(g_secp_ctx)
				g_secp_ctx = nil
			}
		}
		id :: "0000000000000000000000000000000000000000000000000000000000000000"
		pk :: "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9"
		sig :: "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0"
		testing.expect(t, verify_sig(id, pk, sig))
		for invalid in ([?]string{"", "0", id[:63], id + "00", "g000000000000000000000000000000000000000000000000000000000000000", " 000000000000000000000000000000000000000000000000000000000000000"}) {
			testing.expect(t, !verify_sig(invalid, pk, sig))
			testing.expect(t, !verify_sig(id, invalid, sig))
		}
		for invalid in ([?]string{"", "0", sig[:127], sig + "00", "z907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0", " 907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0"}) {
			testing.expect(t, !verify_sig(id, pk, invalid))
		}
		testing.expect(t, !verify_sig("1000000000000000000000000000000000000000000000000000000000000000", pk, sig))
	}
}
