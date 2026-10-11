package relay

import "base:runtime"
import "core:crypto/sha2"
import "core:encoding/base64"
import "core:encoding/hex"
import "core:fmt"
import "core:net"
import "core:os"
import "core:strings"
import "core:strconv"
import "core:sync"
import "core:testing"
import "core:thread"

when ODIN_TEST {
	// -- Test-only BIP-340 signer (variable time, deterministic nonce) ------

	blossom_test_u256_bytes :: proc(v: Schnorr_U256) -> (out: [32]u8) {
		for i in 0..<32 do out[i] = u8(v[3 - i / 8] >> uint(8 * (7 - i % 8)))
		return
	}

	blossom_test_addmod_n :: proc(a, b: Schnorr_U256) -> Schnorr_U256 {
		r: Schnorr_U256
		carry: u64
		for i in 0..<4 {
			s := a[i] + b[i]
			c1 := u64(s < a[i])
			s2 := s + carry
			c2 := u64(s2 < s)
			r[i] = s2
			carry = c1 | c2
		}
		if carry != 0 || schnorr_u256_ge(r, SCHNORR_N) do r, _ = schnorr_u256_sub(r, SCHNORR_N)
		return r
	}

	blossom_test_mulmod_n :: proc(a, b: Schnorr_U256) -> Schnorr_U256 {
		r: Schnorr_U256
		for bit := 255; bit >= 0; bit -= 1 {
			r = blossom_test_addmod_n(r, r)
			if (b[bit / 64] >> uint(bit % 64)) & 1 == 1 do r = blossom_test_addmod_n(r, a)
		}
		return r
	}

	blossom_test_affine :: proc(p: Schnorr_Point) -> (x, y: Schnorr_U256) {
		zi := schnorr_fe_pow(p.z, SCHNORR_INVERSE_EXP)
		zi2 := schnorr_fe_square(zi)
		return schnorr_fe_mul(p.x, zi2), schnorr_fe_mul(p.y, schnorr_fe_mul(zi2, zi))
	}

	blossom_test_negate_n :: proc(v: Schnorr_U256) -> Schnorr_U256 {
		r, _ := schnorr_u256_sub(SCHNORR_N, v)
		return r
	}

	blossom_test_pubkey :: proc(secret: Schnorr_U256) -> string {
		px, _ := blossom_test_affine(schnorr_double_scalar(secret, {}, SCHNORR_G))
		b := blossom_test_u256_bytes(px)
		return string(hex.encode(b[:], context.temp_allocator))
	}

	blossom_test_sign :: proc(secret: Schnorr_U256, msg: []u8) -> string {
		d := secret
		px, py := blossom_test_affine(schnorr_double_scalar(d, {}, SCHNORR_G))
		if py[0] & 1 == 1 do d = blossom_test_negate_n(d)
		db := blossom_test_u256_bytes(d)
		nonce: [32]u8
		{
			ctx: sha2.Context_256
			sha2.init_256(&ctx)
			sha2.update(&ctx, db[:])
			sha2.update(&ctx, msg)
			sha2.final(&ctx, nonce[:])
		}
		k := schnorr_u256_from_bytes(nonce[:])
		if schnorr_u256_ge(k, SCHNORR_N) do k, _ = schnorr_u256_sub(k, SCHNORR_N)
		rx, ry := blossom_test_affine(schnorr_double_scalar(k, {}, SCHNORR_G))
		if ry[0] & 1 == 1 do k = blossom_test_negate_n(k)
		rb := blossom_test_u256_bytes(rx)
		pb := blossom_test_u256_bytes(px)
		digest: [32]u8
		{
			ctx: sha2.Context_256
			sha2.init_256(&ctx)
			sha2.update(&ctx, SCHNORR_CHALLENGE_TAG[:])
			sha2.update(&ctx, SCHNORR_CHALLENGE_TAG[:])
			sha2.update(&ctx, rb[:])
			sha2.update(&ctx, pb[:])
			sha2.update(&ctx, msg)
			sha2.final(&ctx, digest[:])
		}
		e := schnorr_u256_from_bytes(digest[:])
		if schnorr_u256_ge(e, SCHNORR_N) do e, _ = schnorr_u256_sub(e, SCHNORR_N)
		s := blossom_test_addmod_n(k, blossom_test_mulmod_n(e, d))
		sb := blossom_test_u256_bytes(s)
		sig: [64]u8
		copy(sig[:32], rb[:])
		copy(sig[32:], sb[:])
		return string(hex.encode(sig[:], context.temp_allocator))
	}

	Blossom_Test_Auth :: struct {
		secret:     Schnorr_U256,
		kind:       i64,
		verb:       string,
		x:          string,
		created_at: i64,
		expiration: i64,
		corrupt:    bool,
	}

	blossom_test_auth :: proc(a: Blossom_Test_Auth) -> string {
		now := unix_now()
		tags := make([dynamic][]string, context.temp_allocator)
		append(&tags, []string{"t", a.verb})
		if a.x != "" do append(&tags, []string{"x", a.x})
		exp := a.expiration != 0 ? a.expiration : now + 600
		append(&tags, []string{"expiration", fmt.tprintf("%d", exp)})
		ev := Event{
			pubkey = blossom_test_pubkey(a.secret),
			created_at = a.created_at != 0 ? a.created_at : now,
			kind = a.kind != 0 ? a.kind : BLOB_AUTH_KIND,
			tags = tags[:],
			content = a.verb,
		}
		ev.tags_json = canon_tags(ev.tags)
		ev.id = compute_event_id(&ev)
		idb, _ := hex.decode(transmute([]u8)ev.id, context.temp_allocator)
		ev.sig = blossom_test_sign(a.secret, idb)
		if a.corrupt {
			b := transmute([]u8)strings.clone(ev.sig, context.temp_allocator)
			b[127] = b[127] == '0' ? '1' : '0'
			ev.sig = string(b)
		}
		js := event_json(&ev)
		return fmt.tprintf("Nostr %s", base64.encode(transmute([]u8)js, allocator = context.temp_allocator))
	}

	// -- Loopback server ----------------------------------------------------

	Blossom_Test_Server :: struct {
		listener: net.TCP_Socket,
		endpoint: net.Endpoint,
		stop:     bool,
		thread:   ^thread.Thread,
	}

	blossom_test_serve :: proc(s: ^Blossom_Test_Server) {
		for !sync.atomic_load(&s.stop) {
			client, _, err := net.accept_tcp(s.listener)
			if err != nil do continue
			if sync.atomic_load(&s.stop) {
				net.close(client)
				break
			}
			thread.run_with_poly_data(client, handle_connection)
		}
	}

	Blossom_Test_Response :: struct {
		status:  int,
		headers: string, // raw head, lowercased
		body:    string,
	}

	blossom_test_request :: proc(s: ^Blossom_Test_Server, method, path: string, headers: []string, body: []u8 = nil, content_length := -1) -> (r: Blossom_Test_Response) {
		sock, err := net.dial_tcp(s.endpoint)
		if err != nil do return
		defer net.close(sock)
		sb := strings.builder_make(context.temp_allocator)
		fmt.sbprintf(&sb, "%s %s HTTP/1.1\r\nHost: blossom.test\r\n", method, path)
		for h in headers do fmt.sbprintf(&sb, "%s\r\n", h)
		cl := content_length >= 0 ? content_length : len(body)
		if method == "PUT" || content_length >= 0 do fmt.sbprintf(&sb, "Content-Length: %d\r\n", cl)
		strings.write_string(&sb, "\r\n")
		if _, serr := net.send_tcp(sock, transmute([]u8)strings.to_string(sb)); serr != nil do return
		if len(body) > 0 {
			if _, serr := net.send_tcp(sock, body); serr != nil do return
		}
		net.shutdown(sock, .Send)
		out := make([dynamic]u8, context.temp_allocator)
		buf: [64 << 10]u8
		for {
			n, rerr := net.recv_tcp(sock, buf[:])
			if rerr != nil || n <= 0 do break
			append(&out, ..buf[:n])
		}
		raw := string(out[:])
		end := strings.index(raw, "\r\n\r\n")
		if end < 0 || len(raw) < 12 do return
		r.headers = strings.to_lower(raw[:end], context.temp_allocator)
		r.body = raw[end+4:]
		r.status, _ = strconv.parse_int(raw[9:12])
		return
	}

	blossom_test_sha :: proc(data: []u8) -> string {
		d: [32]u8
		ctx: sha2.Context_256
		sha2.init_256(&ctx)
		sha2.update(&ctx, data)
		sha2.final(&ctx, d[:])
		return string(hex.encode(d[:], context.temp_allocator))
	}

	blossom_test_free_all :: proc() {
		for k, m in g_blobs {
			delete(k)
			blob_free_meta(m)
		}
		delete(g_blobs)
		delete(g_blob_dir)
		g_blobs = nil
		g_blob_dir = ""
	}

	@(test)
	blossom_end_to_end :: proc(t: ^testing.T) {
		// Server threads allocate with the heap allocator; share it so frees match.
		context.allocator = runtime.heap_allocator()
		sync.lock(&store_test_mu) // g_allowed is shared with the store tests
		defer sync.unlock(&store_test_mu)

		alice := Schnorr_U256{0x1111, 0x2222, 0x3333, 0x0444}
		bob := Schnorr_U256{0x5555, 0x6666, 0x7777, 0x0888}
		mallory := Schnorr_U256{0x9999, 0xaaaa, 0xbbbb, 0x0ccc}
		alice_pk := blossom_test_pubkey(alice)
		bob_pk := blossom_test_pubkey(bob)
		// The signer agrees with the relay's verifier.
		{
			msg: [32]u8 = 7
			sig := blossom_test_sign(alice, msg[:])
			testing.expect(t, verify_sig(string(hex.encode(msg[:], context.temp_allocator)), alice_pk, sig))
		}

		saved_allowed := g_allowed
		g_allowed = make(map[string]bool)
		g_allowed[alice_pk] = true
		g_allowed[bob_pk] = true
		defer {
			delete(g_allowed)
			g_allowed = saved_allowed
		}

		dir := fmt.tprintf("%s/roostr-blossom-test-%d", os.get_env("TMPDIR", context.temp_allocator), unix_now())
		_ = os.make_directory_all(dir)
		defer os.remove_all(dir)
		db := fmt.tprintf("%s/relay.db", dir)
		blob_open(db)
		defer blossom_test_free_all()

		srv: Blossom_Test_Server
		lerr: net.Network_Error
		srv.listener, lerr = net.listen_tcp({address = net.IP4_Address{127, 0, 0, 1}, port = 0})
		if !testing.expect(t, lerr == nil) do return
		srv.endpoint, _ = net.bound_endpoint(srv.listener)
		srv.thread = thread.create_and_start_with_poly_data(&srv, blossom_test_serve)
		defer {
			sync.atomic_store(&srv.stop, true)
			if wake, err := net.dial_tcp(srv.endpoint); err == nil do net.close(wake)
			thread.join(srv.thread)
			thread.destroy(srv.thread)
			net.close(srv.listener)
		}

		blob := make([]u8, 1 << 20 + 12345) // several BLOB_IO_CHUNKs
		defer delete(blob)
		for &b, i in blob do b = u8(i * 31 + i / 251)
		sha := blossom_test_sha(blob)
		up := blossom_test_auth({secret = alice, verb = "upload", x = sha})

		// CORS preflight.
		r := blossom_test_request(&srv, "OPTIONS", "/upload", nil)
		testing.expect_value(t, r.status, 204)
		testing.expect(t, strings.contains(r.headers, "access-control-allow-methods: get, head, put, delete, options"))
		testing.expect(t, strings.contains(r.headers, "authorization"))

		// Auth failures, all before the body is stored.
		future := blossom_test_auth({secret = alice, verb = "upload", x = sha, created_at = unix_now() + 3600})
		expired := blossom_test_auth({secret = alice, verb = "upload", x = sha, expiration = unix_now() - 1})
		wrong_verb := blossom_test_auth({secret = alice, verb = "delete", x = sha})
		wrong_kind := blossom_test_auth({secret = alice, verb = "upload", x = sha, kind = 1})
		bad_sig := blossom_test_auth({secret = alice, verb = "upload", x = sha, corrupt = true})
		cases := [?]struct{ auth: string, status: int }{
			{"", 401}, {"Bearer abc", 401}, {"Nostr !!!", 401},
			{future, 401}, {expired, 401}, {wrong_verb, 401}, {wrong_kind, 401}, {bad_sig, 401},
			{blossom_test_auth({secret = mallory, verb = "upload", x = sha}), 403},
		}
		for c in cases {
			hs := c.auth == "" ? nil : []string{fmt.tprintf("Authorization: %s", c.auth)}
			r = blossom_test_request(&srv, "PUT", "/upload", hs, blob[:1000])
			testing.expectf(t, r.status == c.status, "auth %q: got %d", c.auth, r.status)
		}

		// x tag for different bytes: rejected after hashing.
		other := blossom_test_auth({secret = alice, verb = "upload", x = strings.repeat("ab", 32, context.temp_allocator)})
		r = blossom_test_request(&srv, "PUT", "/upload", {fmt.tprintf("Authorization: %s", other)}, blob)
		testing.expect_value(t, r.status, 401)
		// X-SHA-256 header disagreeing with the body.
		lie := strings.repeat("cd", 32, context.temp_allocator)
		lie_auth := blossom_test_auth({secret = alice, verb = "upload", x = lie})
		r = blossom_test_request(&srv, "PUT", "/upload", {fmt.tprintf("Authorization: %s", lie_auth), fmt.tprintf("X-SHA-256: %s", lie)}, blob)
		testing.expect_value(t, r.status, 409)
		// Header naming a hash the auth event does not cover.
		r = blossom_test_request(&srv, "PUT", "/upload", {fmt.tprintf("Authorization: %s", up), fmt.tprintf("X-SHA-256: %s", lie)}, blob)
		testing.expect_value(t, r.status, 401)
		// Size limit, rejected from the header alone.
		r = blossom_test_request(&srv, "PUT", "/upload", {fmt.tprintf("Authorization: %s", up)}, nil, int(BLOB_MAX_SIZE) + 1)
		testing.expect_value(t, r.status, 413)
		// BUD-06 preflight.
		r = blossom_test_request(&srv, "HEAD", "/upload", {fmt.tprintf("Authorization: %s", up), fmt.tprintf("X-SHA-256: %s", sha), fmt.tprintf("X-Content-Length: %d", len(blob))})
		testing.expect_value(t, r.status, 200)
		testing.expect(t, !os.exists(blob_path(sha)))
		entries, _ := os.read_all_directory_by_path(g_blob_dir, context.temp_allocator)
		testing.expect_value(t, len(entries), 0) // no temp files left behind

		// Upload.
		r = blossom_test_request(&srv, "PUT", "/upload", {fmt.tprintf("Authorization: %s", up), fmt.tprintf("X-SHA-256: %s", sha), "Content-Type: application/octet-stream"}, blob)
		testing.expect_value(t, r.status, 200)
		testing.expect(t, strings.contains(r.body, fmt.tprintf(`"url":"http://blossom.test/%s"`, sha)), r.body)
		testing.expect(t, strings.contains(r.body, fmt.tprintf(`"size":%d`, len(blob))), r.body)

		// Download, HEAD, ranges.
		r = blossom_test_request(&srv, "GET", fmt.tprintf("/%s", sha), nil)
		testing.expect_value(t, r.status, 200)
		testing.expect(t, r.body == string(blob), "downloaded bytes differ")
		testing.expect(t, strings.contains(r.headers, "accept-ranges: bytes"))
		r = blossom_test_request(&srv, "HEAD", fmt.tprintf("/%s.png", sha), nil)
		testing.expect(t, r.status == 200 && r.body == "")
		testing.expect(t, strings.contains(r.headers, fmt.tprintf("content-length: %d", len(blob))))
		testing.expect(t, strings.contains(r.headers, "content-type: image/png"))
		r = blossom_test_request(&srv, "GET", fmt.tprintf("/%s", sha), {"Range: bytes=300000-300009"})
		testing.expect_value(t, r.status, 206)
		testing.expect(t, r.body == string(blob[300000:300010]))
		testing.expect(t, strings.contains(r.headers, fmt.tprintf("content-range: bytes 300000-300009/%d", len(blob))))
		r = blossom_test_request(&srv, "GET", fmt.tprintf("/%s", sha), {"Range: bytes=-5"})
		testing.expect(t, r.status == 206 && r.body == string(blob[len(blob)-5:]))
		r = blossom_test_request(&srv, "GET", fmt.tprintf("/%s", sha), {fmt.tprintf("Range: bytes=%d-", len(blob) - 3)})
		testing.expect(t, r.status == 206 && r.body == string(blob[len(blob)-3:]))
		r = blossom_test_request(&srv, "GET", fmt.tprintf("/%s", sha), {fmt.tprintf("Range: bytes=%d-", len(blob))})
		testing.expect_value(t, r.status, 416)
		r = blossom_test_request(&srv, "GET", fmt.tprintf("/%s", strings.repeat("0", 64, context.temp_allocator)), nil)
		testing.expect_value(t, r.status, 404)

		// Bob re-uploads the same bytes: a second claim, same blob.
		r = blossom_test_request(&srv, "PUT", "/upload", {fmt.tprintf("Authorization: %s", blossom_test_auth({secret = bob, verb = "upload", x = sha}))}, blob)
		testing.expect_value(t, r.status, 200)

		// Listing: own uploads only.
		r = blossom_test_request(&srv, "GET", fmt.tprintf("/list/%s", alice_pk), {fmt.tprintf("Authorization: %s", blossom_test_auth({secret = alice, verb = "list"}))})
		testing.expect(t, r.status == 200 && strings.contains(r.body, sha), r.body)
		r = blossom_test_request(&srv, "GET", fmt.tprintf("/list/%s", alice_pk), {fmt.tprintf("Authorization: %s", blossom_test_auth({secret = bob, verb = "list"}))})
		testing.expect_value(t, r.status, 403)
		r = blossom_test_request(&srv, "GET", fmt.tprintf("/list/%s", alice_pk), nil)
		testing.expect_value(t, r.status, 401)

		// Claims survive a restart.
		blossom_test_free_all()
		blob_open(db)
		testing.expect(t, sha in g_blobs && len(g_blobs[sha].owners) == 2)

		// Deletion: only uploaders; the bytes go with the last claim.
		r = blossom_test_request(&srv, "DELETE", fmt.tprintf("/%s", sha), {fmt.tprintf("Authorization: %s", blossom_test_auth({secret = mallory, verb = "delete", x = sha}))})
		testing.expect_value(t, r.status, 403)
		r = blossom_test_request(&srv, "DELETE", fmt.tprintf("/%s", sha), {fmt.tprintf("Authorization: %s", blossom_test_auth({secret = alice, verb = "delete", x = lie}))})
		testing.expect_value(t, r.status, 401)
		r = blossom_test_request(&srv, "DELETE", fmt.tprintf("/%s", sha), {fmt.tprintf("Authorization: %s", blossom_test_auth({secret = alice, verb = "delete", x = sha}))})
		testing.expect_value(t, r.status, 200)
		r = blossom_test_request(&srv, "GET", fmt.tprintf("/%s", sha), nil)
		testing.expect_value(t, r.status, 200)
		r = blossom_test_request(&srv, "DELETE", fmt.tprintf("/%s", sha), {fmt.tprintf("Authorization: %s", blossom_test_auth({secret = alice, verb = "delete", x = sha}))})
		testing.expect_value(t, r.status, 403)
		r = blossom_test_request(&srv, "DELETE", fmt.tprintf("/%s", sha), {fmt.tprintf("Authorization: %s", blossom_test_auth({secret = bob, verb = "delete", x = sha}))})
		testing.expect_value(t, r.status, 200)
		r = blossom_test_request(&srv, "GET", fmt.tprintf("/%s", sha), nil)
		testing.expect_value(t, r.status, 404)
		testing.expect(t, !os.exists(blob_path(sha)) && !os.exists(blob_meta_path(sha)))

		// NIP-11 advertises Blossom; the relay paths still answer.
		r = blossom_test_request(&srv, "GET", "/", {"Accept: application/nostr+json"})
		testing.expect(t, r.status == 200 && strings.contains(r.body, `"blossom":{"buds":[1,2,6,11]`), r.body)
		r = blossom_test_request(&srv, "GET", "/health", nil)
		testing.expect(t, r.status == 200 && r.body == "ok")
	}
}
