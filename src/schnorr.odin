package relay

import "core:crypto/sha2"

// BIP-340 verification only. ALL arithmetic here is variable-time and operates
// exclusively on public data. Never reuse these helpers for signing or secrets.
// Specification: https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
// Group formulas: https://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html
// Field reduction uses 2^256 = 2^32 + 977 (mod p); bounds are documented below.
// No allocator, mutable global state, or foreign cryptographic code is used.

@(private)
Schnorr_U256 :: [4]u64 // Little-endian limbs; encoded bytes are big-endian.

@(private)
SCHNORR_P :: Schnorr_U256{0xfffffffefffffc2f, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff}
@(private)
SCHNORR_N :: Schnorr_U256{0xbfd25e8cd0364141, 0xbaaedce6af48a03b, 0xfffffffffffffffe, 0xffffffffffffffff}
@(private)
SCHNORR_C :: u64(0x1000003d1)
@(private)
SCHNORR_SQRT_EXP :: Schnorr_U256{0xffffffffbfffff0c, 0xffffffffffffffff, 0xffffffffffffffff, 0x3fffffffffffffff}
@(private)
SCHNORR_INVERSE_EXP :: Schnorr_U256{0xfffffffefffffc2d, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff}

@(private)
Schnorr_Point :: struct {
	x, y, z: Schnorr_U256,
}

// Jacobian coordinates: affine x = X/Z^2, y = Y/Z^3. Z=0 is infinity,
// regardless of X,Y; all coordinates of finite points are canonical modulo p.
@(private)
SCHNORR_G :: Schnorr_Point{
	x = {0x59f2815b16f81798, 0x029bfcdb2dce28d9, 0x55a06295ce870b07, 0x79be667ef9dcbbac},
	y = {0x9c47d08ffb10d4b8, 0xfd17b448a6855419, 0x5da4fbfc0e1108a8, 0x483ada7726a3c465},
	z = {1, 0, 0, 0},
}

// SHA256("BIP0340/challenge"). Read-only storage avoids hashing the tag or
// allocating a concatenation buffer on each verification.
@(private, rodata)
SCHNORR_CHALLENGE_TAG := [32]u8{
	0x7b, 0xb5, 0x2d, 0x7a, 0x9f, 0xef, 0x58, 0x32,
	0x3e, 0xb1, 0xbf, 0x7a, 0x40, 0x7d, 0xb3, 0x82,
	0xd2, 0xf3, 0xf2, 0xd8, 0x1b, 0xb1, 0x22, 0x4f,
	0x49, 0xfe, 0x51, 0x8f, 0x6d, 0x48, 0xd3, 0x7c,
}

@(private)
schnorr_u256_from_bytes :: proc(data: []u8) -> (value: Schnorr_U256) {
	assert(len(data) == 32)
	for i in 0..<32 {
		value[3 - i / 8] = (value[3 - i / 8] << 8) | u64(data[i])
	}
	return
}

@(private)
schnorr_u256_ge :: proc(a, b: Schnorr_U256) -> bool {
	for i := 3; i >= 0; i -= 1 {
		if a[i] != b[i] do return a[i] > b[i]
	}
	return true
}

// Raw subtraction modulo 2^256, with the true unsigned borrow separately.
// Adding 2^64 before each subtraction keeps the u128 intermediate nonnegative.
@(private)
schnorr_u256_sub :: proc(a, b: Schnorr_U256) -> (value: Schnorr_U256, borrow: u64) {
	for i in 0..<4 {
		t := (u128(1) << 64) + u128(a[i]) - u128(b[i]) - u128(borrow)
		value[i] = u64(t)
		borrow = 1 - u64(t >> 64)
	}
	return
}

// Reduce low + high*2^256, with low < 2^256 and high <= C.
// First fold adds at most C^2. Its carry is at most one; if that carry occurs,
// the wrapped low is < C^2. Thus the second fold cannot overflow 256 bits.
// The final value is < 2^256 < 2p, so exactly one conditional subtraction suffices.
@(private)
schnorr_fe_reduce :: proc(low: Schnorr_U256, high: u64) -> Schnorr_U256 {
	value := low
	carry := high
	for _ in 0..<2 {
		t := u128(value[0]) + u128(carry) * u128(SCHNORR_C)
		value[0] = u64(t)
		carry = u64(t >> 64)
		for i in 1..<4 {
			t = u128(value[i]) + u128(carry)
			value[i] = u64(t)
			carry = u64(t >> 64)
		}
	}
	if schnorr_u256_ge(value, SCHNORR_P) {
		value, _ = schnorr_u256_sub(value, SCHNORR_P)
	}
	return value
}

// All field operations require canonical operands in [0,p) and return [0,p).
@(private)
schnorr_fe_add :: proc(a, b: Schnorr_U256) -> Schnorr_U256 {
	value: Schnorr_U256
	carry: u64
	for i in 0..<4 {
		t := u128(a[i]) + u128(b[i]) + u128(carry)
		value[i] = u64(t)
		carry = u64(t >> 64)
	}
	return schnorr_fe_reduce(value, carry)
}

@(private)
schnorr_fe_sub :: proc(a, b: Schnorr_U256) -> Schnorr_U256 {
	value, borrow := schnorr_u256_sub(a, b)
	if borrow != 0 {
		// Wrapped a-b plus p, discarding the final carry, is a-b+p in [0,p).
		carry: u64
		p := SCHNORR_P
		for i in 0..<4 {
			t := u128(value[i]) + u128(p[i]) + u128(carry)
			value[i] = u64(t)
			carry = u64(t >> 64)
		}
	}
	return value
}

@(private)
schnorr_fe_mul :: proc(a, b: Schnorr_U256) -> Schnorr_U256 {
	product: [8]u64
	for i in 0..<4 {
		carry: u64
		for j in 0..<4 {
			// With B=2^64, the maximum is (B-1)^2+2(B-1)=B^2-1.
			// No u128 overflow; the next row's top limb is still zero.
			t := u128(a[i]) * u128(b[j]) + u128(product[i+j]) + u128(carry)
			product[i+j] = u64(t)
			carry = u64(t >> 64)
		}
		product[i+4] = carry
	}

	// Fold the high four limbs once. Each accumulator is <= B*(C+1)-1,
	// so u128 suffices and the final carry is <= C, as fe_reduce requires.
	low: Schnorr_U256
	carry: u64
	for i in 0..<4 {
		t := u128(product[i+4]) * u128(SCHNORR_C) + u128(product[i]) + u128(carry)
		low[i] = u64(t)
		carry = u64(t >> 64)
	}
	return schnorr_fe_reduce(low, carry)
}

@(private)
schnorr_fe_square :: proc(a: Schnorr_U256) -> Schnorr_U256 {
	return schnorr_fe_mul(a, a)
}

@(private)
schnorr_fe_double :: proc(a: Schnorr_U256) -> Schnorr_U256 {
	return schnorr_fe_add(a, a)
}

// Binary exponentiation. Exponents and branches are public. The inverse uses
// Fermat's theorem (a^(p-2)); callers must reject zero before requesting inversion.
@(private)
schnorr_fe_pow :: proc(a, exponent: Schnorr_U256) -> Schnorr_U256 {
	value := Schnorr_U256{1, 0, 0, 0}
	for bit := 255; bit >= 0; bit -= 1 {
		value = schnorr_fe_square(value)
		if ((exponent[bit / 64] >> uint(bit % 64)) & 1) != 0 {
			value = schnorr_fe_mul(value, a)
		}
	}
	return value
}

@(private)
schnorr_lift_x :: proc(x: Schnorr_U256) -> (Schnorr_Point, bool) {
	if schnorr_u256_ge(x, SCHNORR_P) do return {}, false
	c := schnorr_fe_add(schnorr_fe_mul(schnorr_fe_square(x), x), {7, 0, 0, 0})
	y := schnorr_fe_pow(c, SCHNORR_SQRT_EXP)
	if schnorr_fe_square(y) != c do return {}, false
	if (y[0] & 1) != 0 do y = schnorr_fe_sub({}, y)
	return Schnorr_Point{x = x, y = y, z = {1, 0, 0, 0}}, true
}

// EFD dbl-2009-l (Lange, 2009), a=0, 2M+5S.
@(private)
schnorr_point_double :: proc(p: Schnorr_Point) -> Schnorr_Point {
	if p.z == (Schnorr_U256{}) || p.y == (Schnorr_U256{}) do return {}
	a := schnorr_fe_square(p.x)
	b := schnorr_fe_square(p.y)
	c := schnorr_fe_square(b)
	d := schnorr_fe_double(schnorr_fe_sub(schnorr_fe_sub(schnorr_fe_square(schnorr_fe_add(p.x, b)), a), c))
	e := schnorr_fe_add(schnorr_fe_double(a), a)
	f := schnorr_fe_square(e)
	x := schnorr_fe_sub(f, schnorr_fe_double(d))
	c8 := schnorr_fe_double(schnorr_fe_double(schnorr_fe_double(c)))
	y := schnorr_fe_sub(schnorr_fe_mul(e, schnorr_fe_sub(d, x)), c8)
	z := schnorr_fe_double(schnorr_fe_mul(p.y, p.z))
	return Schnorr_Point{x = x, y = y, z = z}
}

// EFD add-2007-bl (Bernstein-Lange, 2007), 11M+5S.
// The published formula is incomplete: handle infinity, equal points and
// opposite points explicitly, using coordinates scaled to the same denominator.
@(private)
schnorr_point_add :: proc(p, q: Schnorr_Point) -> Schnorr_Point {
	if p.z == (Schnorr_U256{}) do return q
	if q.z == (Schnorr_U256{}) do return p
	z1z1 := schnorr_fe_square(p.z)
	z2z2 := schnorr_fe_square(q.z)
	u1 := schnorr_fe_mul(p.x, z2z2)
	u2 := schnorr_fe_mul(q.x, z1z1)
	s1 := schnorr_fe_mul(p.y, schnorr_fe_mul(q.z, z2z2))
	s2 := schnorr_fe_mul(q.y, schnorr_fe_mul(p.z, z1z1))
	if u1 == u2 {
		if s1 == s2 do return schnorr_point_double(p)
		return {}
	}
	h := schnorr_fe_sub(u2, u1)
	i := schnorr_fe_square(schnorr_fe_double(h))
	j := schnorr_fe_mul(h, i)
	r := schnorr_fe_double(schnorr_fe_sub(s2, s1))
	v := schnorr_fe_mul(u1, i)
	x := schnorr_fe_sub(schnorr_fe_sub(schnorr_fe_square(r), j), schnorr_fe_double(v))
	y := schnorr_fe_sub(schnorr_fe_mul(r, schnorr_fe_sub(v, x)), schnorr_fe_double(schnorr_fe_mul(s1, j)))
	z := schnorr_fe_mul(schnorr_fe_sub(schnorr_fe_sub(schnorr_fe_square(schnorr_fe_add(p.z, q.z)), z1z1), z2z2), h)
	return Schnorr_Point{x = x, y = y, z = z}
}

// Joint binary multiplication (Shamir's trick): 256 doublings, at most 256
// additions, and a four-entry stack table. This computes s*G-e*P directly,
// including zero scalars and the G-P=infinity case, without scalar negation.
@(private)
schnorr_double_scalar :: proc(s, e: Schnorr_U256, p: Schnorr_Point) -> Schnorr_Point {
	negative_p := p
	negative_p.y = schnorr_fe_sub({}, p.y)
	table := [4]Schnorr_Point{{}, SCHNORR_G, negative_p, schnorr_point_add(SCHNORR_G, negative_p)}
	result: Schnorr_Point
	for bit := 255; bit >= 0; bit -= 1 {
		result = schnorr_point_double(result)
		s_bit := (s[bit / 64] >> uint(bit % 64)) & 1
		e_bit := (e[bit / 64] >> uint(bit % 64)) & 1
		index := int(s_bit | (e_bit << 1))
		if index != 0 do result = schnorr_point_add(result, table[index])
	}
	return result
}

// Verify arbitrary message bytes against an exactly 32-byte x-only public key
// and exactly 64-byte signature. No prehashing or hex decoding is performed.
// Stack-only and reentrant. This is NOT a constant-time signing primitive.
schnorr_verify :: proc(message, pubkey, signature: []u8) -> bool {
	if len(pubkey) != 32 || len(signature) != 64 do return false
	// SHA256's 64-bit bit count must include tag||tag||r||pk (128 bytes).
	if u64(len(message)) > (u64(1) << 61) - 1 - 128 do return false

	r := schnorr_u256_from_bytes(signature[:32])
	s := schnorr_u256_from_bytes(signature[32:])
	if schnorr_u256_ge(r, SCHNORR_P) || schnorr_u256_ge(s, SCHNORR_N) do return false
	p, ok := schnorr_lift_x(schnorr_u256_from_bytes(pubkey))
	if !ok do return false

	hash: sha2.Context_256
	digest: [32]u8
	sha2.init_256(&hash)
	sha2.update(&hash, SCHNORR_CHALLENGE_TAG[:])
	sha2.update(&hash, SCHNORR_CHALLENGE_TAG[:])
	sha2.update(&hash, signature[:32])
	sha2.update(&hash, pubkey)
	sha2.update(&hash, message)
	sha2.final(&hash, digest[:])
	e := schnorr_u256_from_bytes(digest[:])
	// n > 2^255, hence a 256-bit hash needs at most one subtraction.
	if schnorr_u256_ge(e, SCHNORR_N) do e, _ = schnorr_u256_sub(e, SCHNORR_N)

	result := schnorr_double_scalar(s, e, p)
	if result.z == (Schnorr_U256{}) do return false
	// Compare projective X first, saving the inversion on an invalid equation.
	z2 := schnorr_fe_square(result.z)
	if result.x != schnorr_fe_mul(r, z2) do return false
	zi := schnorr_fe_pow(result.z, SCHNORR_INVERSE_EXP)
	y := schnorr_fe_mul(result.y, schnorr_fe_mul(schnorr_fe_square(zi), zi))
	return (y[0] & 1) == 0
}
