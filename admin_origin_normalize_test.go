// Copyright 2015 Matthew Holt and The Caddy Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package caddy

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// mustParseOrigins normalizes each configured origin for test setup,
// failing the test if any entry is rejected.
func mustParseOrigins(t *testing.T, origins ...string) []originTuple {
	t.Helper()
	tuples := make([]originTuple, 0, len(origins))
	for _, o := range origins {
		tuple, err := parseOrigin(o)
		if err != nil {
			t.Fatalf("parseOrigin(%q) = error %v, want valid tuple", o, err)
		}
		tuples = append(tuples, tuple)
	}
	return tuples
}

// TestParseOrigin locks in the canonical form that configured origins and
// Origin header values are normalized to, and the malformed inputs that
// must be rejected (fail closed) rather than loosely interpreted.
func TestParseOrigin(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		for i, tc := range []struct {
			input  string
			expect originTuple
		}{
			// DNS names: case-insensitive, trailing root dot ignored
			{input: "example.com", expect: originTuple{host: "example.com"}},
			{input: "Example.COM", expect: originTuple{host: "example.com"}},
			{input: "example.com.", expect: originTuple{host: "example.com"}},
			{input: "LOCALHOST.:2019", expect: originTuple{host: "localhost", port: "2019"}},
			// ports: canonicalized (no leading zeros)
			{input: "example.com:8080", expect: originTuple{host: "example.com", port: "8080"}},
			{input: "example.com:080", expect: originTuple{host: "example.com", port: "80"}},
			// schemes: lowercased; default ports elided only when the scheme is known
			{input: "http://example.com", expect: originTuple{scheme: "http", host: "example.com"}},
			{input: "http://example.com:80", expect: originTuple{scheme: "http", host: "example.com"}},
			{input: "https://example.com:443", expect: originTuple{scheme: "https", host: "example.com"}},
			{input: "ws://example.com:80", expect: originTuple{scheme: "ws", host: "example.com"}},
			{input: "wss://example.com:443", expect: originTuple{scheme: "wss", host: "example.com"}},
			{input: "HTTP://Example.COM:80", expect: originTuple{scheme: "http", host: "example.com"}},
			// non-default ports are always preserved
			{input: "http://example.com:8080", expect: originTuple{scheme: "http", host: "example.com", port: "8080"}},
			{input: "https://example.com:80", expect: originTuple{scheme: "https", host: "example.com", port: "80"}},
			{input: "http://example.com:443", expect: originTuple{scheme: "http", host: "example.com", port: "443"}},
			// IPv4
			{input: "127.0.0.1:2019", expect: originTuple{host: "127.0.0.1", port: "2019"}},
			{input: "http://127.0.0.1", expect: originTuple{scheme: "http", host: "127.0.0.1"}},
			// bracketed IPv6, rendered in canonical form
			{input: "[::1]:2019", expect: originTuple{host: "::1", port: "2019"}},
			{input: "http://[::1]:2019", expect: originTuple{scheme: "http", host: "::1", port: "2019"}},
			{input: "http://[0:0:0:0:0:0:0:1]:2019", expect: originTuple{scheme: "http", host: "::1", port: "2019"}},
			{input: "[::ffff:127.0.0.1]:2019", expect: originTuple{host: "127.0.0.1", port: "2019"}},
		} {
			actual, err := parseOrigin(tc.input)
			if err != nil {
				t.Errorf("Test %d: parseOrigin(%q) = error %v, want %+v", i, tc.input, err, tc.expect)
				continue
			}
			if actual != tc.expect {
				t.Errorf("Test %d: parseOrigin(%q) = %+v, want %+v", i, tc.input, actual, tc.expect)
			}
		}
	})

	t.Run("invalid", func(t *testing.T) {
		for i, input := range []string{
			// empty values
			"",
			"http://",
			"http://:2019",
			":2019",
			// userinfo is never legitimate in an origin or Host
			"http://user@example.com",
			"http://user:pass@example.com:2019",
			"user@example.com:2019",
			"example.com:2019@evil.com",
			// ports: empty, non-numeric, out of range, duplicated
			"example.com:",
			"[::1]:",
			"example.com:abc",
			"example.com:99999",
			"example.com:80:90",
			"[::1]:80:90",
			// IPv6 must be bracketed; zones are ambiguous and rejected
			"::1",
			"::1:2019",
			"[::1",
			"http://[fe80::1%eth0]:2019",
			"[fe80::1%25eth0]:2019",
			// paths, query strings, fragments are rejected, not stripped
			"http://example.com/",
			"http://example.com/path",
			"http://example.com?x=1",
			"http://example.com#frag",
			"example.com/path",
			// whitespace and control characters
			"http://exa mple.com",
			"http://example.com ",
			" http://example.com",
			"http://example.com\t",
			"http://exa\rmple.com",
			"http://exa\nmple.com",
			// percent-encoding in the host is ambiguous
			"http://ex%61mple.com",
			// malformed DNS names
			"example.com..",
			".",
			// scheme-relative and schemeless URLs are not origins
			"//example.com:2019",
		} {
			if actual, err := parseOrigin(input); err == nil {
				t.Errorf("Test %d: parseOrigin(%q) = %+v, want error", i, input, actual)
			}
		}
	})
}

// TestParseRefererOrigin locks in how a Referer header (a full URL, unlike
// a serialized Origin) is reduced to an origin tuple: path, query, and
// fragment are expected and ignored, but userinfo, non-absolute URLs, and
// malformed hosts are rejected.
func TestParseRefererOrigin(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		for i, tc := range []struct {
			input  string
			expect originTuple
		}{
			{input: "http://localhost:2019", expect: originTuple{scheme: "http", host: "localhost", port: "2019"}},
			{input: "http://localhost:2019/config/", expect: originTuple{scheme: "http", host: "localhost", port: "2019"}},
			{input: "http://localhost:2019/path?q=1#frag", expect: originTuple{scheme: "http", host: "localhost", port: "2019"}},
			{input: "https://EXAMPLE.com.", expect: originTuple{scheme: "https", host: "example.com"}},
			{input: "http://[::1]:2019/admin", expect: originTuple{scheme: "http", host: "::1", port: "2019"}},
		} {
			actual, err := parseRefererOrigin(tc.input)
			if err != nil {
				t.Errorf("Test %d: parseRefererOrigin(%q) = error %v, want %+v", i, tc.input, err, tc.expect)
				continue
			}
			if actual != tc.expect {
				t.Errorf("Test %d: parseRefererOrigin(%q) = %+v, want %+v", i, tc.input, actual, tc.expect)
			}
		}
	})

	t.Run("invalid", func(t *testing.T) {
		for i, input := range []string{
			"",
			"localhost:2019", // not an absolute URL
			"/config/",
			"http://user@localhost:2019/",
			"http://localhost:2019:80/",
			"http://exa mple.com/",
			"http://[fe80::1%eth0]:2019/",
		} {
			if actual, err := parseRefererOrigin(input); err == nil {
				t.Errorf("Test %d: parseRefererOrigin(%q) = %+v, want error", i, input, actual)
			}
		}
	})
}

// TestAdminHandlerCheckHost locks in the DNS rebinding mitigation: the
// request Host is normalized with the same rules as configured origins,
// and host-header injection attempts are rejected.
func TestAdminHandlerCheckHost(t *testing.T) {
	h := adminHandler{allowedOrigins: mustParseOrigins(t,
		"localhost:2019",
		"http://example.com:8080",
		"[::1]:2019",
	)}

	for i, tc := range []struct {
		host    string
		wantErr bool
	}{
		// exact and equivalent spellings
		{host: "localhost:2019", wantErr: false},
		{host: "LOCALHOST:2019", wantErr: false},
		{host: "localhost.:2019", wantErr: false},
		{host: "localhost:02019", wantErr: false},
		{host: "[::1]:2019", wantErr: false},
		{host: "[0:0:0:0:0:0:0:1]:2019", wantErr: false},
		// scheme-ful configured origins still constrain the Host check
		{host: "example.com:8080", wantErr: false},
		{host: "example.com:80", wantErr: true},
		// different host or port
		{host: "evil.com", wantErr: true},
		{host: "evil.com:2019", wantErr: true},
		{host: "127.0.0.1:2019", wantErr: true},
		{host: "localhost", wantErr: true},
		{host: "localhost:2020", wantErr: true},
		{host: "", wantErr: true},
		// host header injection attempts
		{host: "localhost:2019:80", wantErr: true},
		{host: "localhost:abc", wantErr: true},
		{host: "localhost:99999", wantErr: true},
		{host: "user@localhost:2019", wantErr: true},
		{host: "localhost:2019@evil.com", wantErr: true},
		{host: "localhost:2019/path", wantErr: true},
		{host: "localhost:2019?x=1", wantErr: true},
		{host: "localhost:2019#frag", wantErr: true},
		{host: "http://localhost:2019", wantErr: true},
		{host: "::1:2019", wantErr: true},
		{host: "[fe80::1%eth0]:2019", wantErr: true},
		{host: "localhost:2019 ", wantErr: true},
		{host: "local\thost:2019", wantErr: true},
		{host: "localhost.:2019.", wantErr: true},
	} {
		r := httptest.NewRequest(http.MethodGet, "http://placeholder/config/", nil)
		r.Host = tc.host
		err := h.checkHost(r)
		if tc.wantErr && err == nil {
			t.Errorf("Test %d: checkHost(%q) = nil, want error", i, tc.host)
		}
		if !tc.wantErr && err != nil {
			t.Errorf("Test %d: checkHost(%q) = %v, want nil", i, tc.host, err)
		}
	}
}

// TestAdminHandlerOriginAllowed locks in tuple comparison semantics,
// including scheme wildcards for host-only entries and default-port
// elision for scheme-ful entries.
func TestAdminHandlerOriginAllowed(t *testing.T) {
	for i, tc := range []struct {
		allowed string
		origin  string
		expect  bool
	}{
		// host-only configured origins match any scheme
		{allowed: "example.com", origin: "http://example.com", expect: true},
		{allowed: "example.com", origin: "https://example.com", expect: true},
		{allowed: "example.com", origin: "http://example.com:8080", expect: false},
		// default ports are equivalent when the scheme is known
		{allowed: "http://example.com", origin: "http://example.com:80", expect: true},
		{allowed: "http://example.com:80", origin: "http://example.com", expect: true},
		{allowed: "https://example.com", origin: "https://example.com:443", expect: true},
		// scheme and non-default ports must match exactly
		{allowed: "http://example.com", origin: "https://example.com", expect: false},
		{allowed: "http://example.com", origin: "http://example.com:443", expect: false},
		{allowed: "http://example.com:8080", origin: "http://example.com", expect: false},
		// host normalization applies on both sides
		{allowed: "localhost:2019", origin: "http://LOCALHOST.:2019", expect: true},
		{allowed: "[::1]:2019", origin: "http://[0:0:0:0:0:0:0:1]:2019", expect: true},
		// no prefix/suffix matching
		{allowed: "example.com", origin: "http://evil.example.com", expect: false},
		{allowed: "example.com", origin: "http://example.com.evil.org", expect: false},
	} {
		allowed, err := parseOrigin(tc.allowed)
		if err != nil {
			t.Fatalf("Test %d: parseOrigin(%q) = error %v", i, tc.allowed, err)
		}
		origin, err := parseOrigin(tc.origin)
		if err != nil {
			t.Fatalf("Test %d: parseOrigin(%q) = error %v", i, tc.origin, err)
		}
		h := adminHandler{allowedOrigins: []originTuple{allowed}}
		if actual := h.originAllowed(origin); actual != tc.expect {
			t.Errorf("Test %d: originAllowed(%q) with allowed %q = %v, want %v",
				i, tc.origin, tc.allowed, actual, tc.expect)
		}
	}
}

// TestAdminHandlerCheckOrigin locks in how the Origin and Referer headers
// are resolved to an origin: the Origin header is authoritative, malformed
// Origins fail closed (no Referer fallback), and the Referer is only
// consulted when no usable Origin header is present.
func TestAdminHandlerCheckOrigin(t *testing.T) {
	newHandler := func(t *testing.T) adminHandler {
		return adminHandler{allowedOrigins: mustParseOrigins(t, "localhost:2019")}
	}

	t.Run("valid origin is echoed back", func(t *testing.T) {
		h := newHandler(t)
		r := httptest.NewRequest(http.MethodGet, "http://localhost:2019/config/", nil)
		r.Header.Set("Origin", "http://localhost:2019")
		origin, err := h.checkOrigin(r)
		if err != nil {
			t.Fatalf("checkOrigin() = %v, want nil", err)
		}
		if origin != "http://localhost:2019" {
			t.Errorf("checkOrigin() = %q, want the original Origin header value", origin)
		}
	})

	t.Run("origin not in allow-list", func(t *testing.T) {
		h := newHandler(t)
		r := httptest.NewRequest(http.MethodGet, "http://localhost:2019/config/", nil)
		r.Header.Set("Origin", "http://evil.com")
		if _, err := h.checkOrigin(r); err == nil {
			t.Error("checkOrigin() = nil, want error")
		}
	})

	t.Run("origin null is rejected", func(t *testing.T) {
		h := newHandler(t)
		r := httptest.NewRequest(http.MethodGet, "http://localhost:2019/config/", nil)
		r.Header.Set("Origin", "null")
		if _, err := h.checkOrigin(r); err == nil {
			t.Error("checkOrigin() with Origin 'null' = nil, want error")
		}
	})

	t.Run("malformed origin fails closed without referer fallback", func(t *testing.T) {
		h := newHandler(t)
		r := httptest.NewRequest(http.MethodGet, "http://localhost:2019/config/", nil)
		// the Referer alone would be acceptable; the bogus Origin must
		// not be allowed to fall back to it
		r.Header.Set("Origin", "http://localhost:2019:80")
		r.Header.Set("Referer", "http://localhost:2019/config/")
		if _, err := h.checkOrigin(r); err == nil {
			t.Error("checkOrigin() with malformed Origin and valid Referer = nil, want error")
		}
	})

	t.Run("origin with path is rejected", func(t *testing.T) {
		h := newHandler(t)
		r := httptest.NewRequest(http.MethodGet, "http://localhost:2019/config/", nil)
		r.Header.Set("Origin", "http://localhost:2019/path")
		if _, err := h.checkOrigin(r); err == nil {
			t.Error("checkOrigin() with Origin containing a path = nil, want error")
		}
	})

	t.Run("schemeless origin is rejected", func(t *testing.T) {
		h := newHandler(t)
		r := httptest.NewRequest(http.MethodGet, "http://localhost:2019/config/", nil)
		// a serialized origin always has a scheme (RFC 6454); even though
		// this host:port would match the allow-list as a config entry, it
		// is not a legitimate Origin header value
		r.Header.Set("Origin", "localhost:2019")
		if _, err := h.checkOrigin(r); err == nil {
			t.Error("checkOrigin() with schemeless Origin = nil, want error")
		}
	})

	t.Run("duplicate origin headers are rejected", func(t *testing.T) {
		h := newHandler(t)
		r := httptest.NewRequest(http.MethodGet, "http://localhost:2019/config/", nil)
		r.Header["Origin"] = []string{"http://localhost:2019", "http://evil.com"}
		if _, err := h.checkOrigin(r); err == nil {
			t.Error("checkOrigin() with duplicate Origin headers = nil, want error")
		}
	})

	t.Run("referer fallback when origin missing", func(t *testing.T) {
		h := newHandler(t)
		r := httptest.NewRequest(http.MethodGet, "http://localhost:2019/config/", nil)
		r.Header.Set("Referer", "http://localhost:2019/config/?x=1#frag")
		origin, err := h.checkOrigin(r)
		if err != nil {
			t.Fatalf("checkOrigin() = %v, want nil", err)
		}
		if origin != "http://localhost:2019" {
			t.Errorf("checkOrigin() = %q, want canonical origin %q", origin, "http://localhost:2019")
		}
	})

	t.Run("referer with userinfo is rejected", func(t *testing.T) {
		h := newHandler(t)
		r := httptest.NewRequest(http.MethodGet, "http://localhost:2019/config/", nil)
		r.Header.Set("Referer", "http://user@localhost:2019/config/")
		if _, err := h.checkOrigin(r); err == nil {
			t.Error("checkOrigin() with userinfo Referer = nil, want error")
		}
	})

	t.Run("missing origin and referer is rejected", func(t *testing.T) {
		h := newHandler(t)
		r := httptest.NewRequest(http.MethodGet, "http://localhost:2019/config/", nil)
		if _, err := h.checkOrigin(r); err == nil {
			t.Error("checkOrigin() without Origin or Referer = nil, want error")
		}
	})
}

// newTestAdminHandler returns an adminHandler with a route that always
// succeeds, so tests can observe whether the security checks let a
// request through to the mux.
func newTestAdminHandler(allowed []originTuple, enforceHost, enforceOrigin bool) adminHandler {
	h := adminHandler{
		mux:            http.NewServeMux(),
		enforceHost:    enforceHost,
		enforceOrigin:  enforceOrigin,
		allowedOrigins: allowed,
	}
	h.mux.Handle("/ok", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	return h
}

// TestAdminHandlerServeHTTPBrowserMitigations locks in the browser-context
// mitigations that run before Host/Origin checks.
func TestAdminHandlerServeHTTPBrowserMitigations(t *testing.T) {
	allowed := mustParseOrigins(t, "localhost:2019")

	t.Run("websocket upgrade is rejected", func(t *testing.T) {
		h := newTestAdminHandler(allowed, true, false)
		r := httptest.NewRequest(http.MethodGet, "http://localhost:2019/ok", nil)
		r.Header.Set("Upgrade", "websocket")
		rr := httptest.NewRecorder()
		h.serveHTTP(rr, r)
		if rr.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
		}
	})

	t.Run("no-cors fetch mode is rejected", func(t *testing.T) {
		h := newTestAdminHandler(allowed, true, false)
		r := httptest.NewRequest(http.MethodGet, "http://localhost:2019/ok", nil)
		r.Header.Set("Sec-Fetch-Mode", "no-cors")
		rr := httptest.NewRecorder()
		h.serveHTTP(rr, r)
		if rr.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
		}
	})

	t.Run("null origin is rejected", func(t *testing.T) {
		h := newTestAdminHandler(allowed, true, false)
		r := httptest.NewRequest(http.MethodGet, "http://localhost:2019/ok", nil)
		r.Header.Set("Origin", "null")
		rr := httptest.NewRecorder()
		h.serveHTTP(rr, r)
		if rr.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
		}
	})
}

// TestAdminHandlerServeHTTPEnforceOrigin locks in the compatibility
// boundary of the enforce_origin switch: when enabled, a request without
// a valid Origin is rejected even if its Host is allowed; when disabled,
// the Origin check only runs if Origin or Sec-Fetch-Mode headers exist.
func TestAdminHandlerServeHTTPEnforceOrigin(t *testing.T) {
	allowed := mustParseOrigins(t, "localhost:2019")

	for i, tc := range []struct {
		name          string
		enforceOrigin bool
		origin        string // empty means: do not set the header
		secFetchMode  string // empty means: do not set the header
		expectStatus  int
		expectCORS    bool
	}{
		{name: "enforce on, no origin", enforceOrigin: true, expectStatus: http.StatusForbidden},
		{name: "enforce on, valid origin", enforceOrigin: true, origin: "http://localhost:2019", expectStatus: http.StatusOK, expectCORS: true},
		{name: "enforce on, invalid origin", enforceOrigin: true, origin: "http://evil.com", expectStatus: http.StatusForbidden},
		{name: "enforce off, no origin headers", enforceOrigin: false, expectStatus: http.StatusOK},
		{name: "enforce off, valid origin", enforceOrigin: false, origin: "http://localhost:2019", expectStatus: http.StatusOK, expectCORS: true},
		{name: "enforce off, invalid origin", enforceOrigin: false, origin: "http://evil.com", expectStatus: http.StatusForbidden},
		{name: "enforce off, sec-fetch-mode triggers check", enforceOrigin: false, secFetchMode: "cors", expectStatus: http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newTestAdminHandler(allowed, true, tc.enforceOrigin)
			r := httptest.NewRequest(http.MethodGet, "http://localhost:2019/ok", nil)
			if tc.origin != "" {
				r.Header.Set("Origin", tc.origin)
			}
			if tc.secFetchMode != "" {
				r.Header.Set("Sec-Fetch-Mode", tc.secFetchMode)
			}
			rr := httptest.NewRecorder()
			h.serveHTTP(rr, r)
			if rr.Code != tc.expectStatus {
				t.Errorf("Test %d: status = %d, want %d", i, rr.Code, tc.expectStatus)
			}
			if gotCORS := rr.Header().Get("Access-Control-Allow-Origin") != ""; gotCORS != tc.expectCORS {
				t.Errorf("Test %d: Access-Control-Allow-Origin set = %v, want %v", i, gotCORS, tc.expectCORS)
			}
		})
	}
}

// TestAdminHandlerServeHTTPIgnoresForwardedHeaders ensures that
// client-controlled proxy headers are never consulted as a source of
// trust: only the actual Host header matters.
func TestAdminHandlerServeHTTPIgnoresForwardedHeaders(t *testing.T) {
	allowed := mustParseOrigins(t, "localhost:2019")

	t.Run("forged forwarded host does not unblock a bad host", func(t *testing.T) {
		h := newTestAdminHandler(allowed, true, false)
		r := httptest.NewRequest(http.MethodGet, "http://localhost:2019/ok", nil)
		r.Host = "evil.com"
		r.Header.Set("X-Forwarded-Host", "localhost:2019")
		r.Header.Set("X-Forwarded-For", "127.0.0.1")
		rr := httptest.NewRecorder()
		h.serveHTTP(rr, r)
		if rr.Code != http.StatusForbidden {
			t.Errorf("status = %d, want %d", rr.Code, http.StatusForbidden)
		}
	})

	t.Run("forged forwarded host does not block a good host", func(t *testing.T) {
		h := newTestAdminHandler(allowed, true, false)
		r := httptest.NewRequest(http.MethodGet, "http://localhost:2019/ok", nil)
		r.Header.Set("X-Forwarded-Host", "evil.com")
		rr := httptest.NewRecorder()
		h.serveHTTP(rr, r)
		if rr.Code != http.StatusOK {
			t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
		}
	})
}

// TestAdminHandlerUnixSocketSkipsHostCheck locks in the unix-socket
// boundary: no default origins are configured and the Host check is
// disabled, so any Host value reaches the mux (see the long comment in
// allowedOrigins for the rationale).
func TestAdminHandlerUnixSocketSkipsHostCheck(t *testing.T) {
	for _, network := range []struct{ network, host string }{
		{network: "unix", host: "/tmp/caddy-test-admin.sock"},
		{network: "fd", host: "3"},
	} {
		t.Run(network.network, func(t *testing.T) {
			addr := NetworkAddress{Network: network.network, Host: network.host}
			admin := &AdminConfig{}
			handler, err := admin.newAdminHandler(addr, false, Context{})
			if err != nil {
				t.Fatalf("newAdminHandler() = %v, want nil", err)
			}
			if handler.enforceHost {
				t.Error("enforceHost = true, want false for unix/fd admin addresses")
			}
			if len(handler.allowedOrigins) != 0 {
				t.Errorf("allowedOrigins = %v, want empty for unix/fd admin addresses", handler.allowedOrigins)
			}

			// a request with an arbitrary Host and no Origin must not be
			// blocked by Host/Origin checks; the mux has no route for "/",
			// so reaching it proves the checks were skipped
			r := httptest.NewRequest(http.MethodGet, "http://anything.invalid/", nil)
			rr := httptest.NewRecorder()
			handler.serveHTTP(rr, r)
			if rr.Code == http.StatusForbidden || rr.Code == http.StatusBadRequest {
				t.Errorf("status = %d, want the request to reach the mux (e.g. 404)", rr.Code)
			}
		})
	}
}

// TestAllowedOriginsDefaults locks in the default policy when Origins is
// not configured: loopback listeners allow the standard loopback
// spellings on the listen port; unix/fd listeners allow nothing (host
// checks are disabled for them instead).
func TestAllowedOriginsDefaults(t *testing.T) {
	for i, tc := range []struct {
		name    string
		addr    NetworkAddress
		origins []string
		expect  []string
	}{
		{
			name:   "loopback listener gets loopback defaults",
			addr:   NetworkAddress{Network: "tcp", Host: "localhost", StartPort: 2019, EndPort: 2019},
			expect: []string{"localhost:2019", "[::1]:2019", "127.0.0.1:2019"},
		},
		{
			name:   "loopback IP listener gets loopback defaults",
			addr:   NetworkAddress{Network: "tcp", Host: "127.0.0.1", StartPort: 2019, EndPort: 2019},
			expect: []string{"localhost:2019", "[::1]:2019", "127.0.0.1:2019"},
		},
		{
			name:   "non-loopback listener gets its own address",
			addr:   NetworkAddress{Network: "tcp", Host: "192.0.2.1", StartPort: 2019, EndPort: 2019},
			expect: []string{"192.0.2.1:2019"},
		},
		{
			name:   "unix listener gets no defaults",
			addr:   NetworkAddress{Network: "unix", Host: "/tmp/caddy.sock"},
			expect: nil,
		},
		{
			name:   "fd listener gets no defaults",
			addr:   NetworkAddress{Network: "fd", Host: "3"},
			expect: nil,
		},
		{
			name:    "explicitly empty origins allow nothing",
			addr:    NetworkAddress{Network: "tcp", Host: "localhost", StartPort: 2019, EndPort: 2019},
			origins: []string{},
			expect:  nil,
		},
		{
			name:    "malformed configured origins are dropped",
			addr:    NetworkAddress{Network: "tcp", Host: "localhost", StartPort: 2019, EndPort: 2019},
			origins: []string{"http://user@example.com", "example.com:99999", "http://example.com/path", "example.com:2019"},
			expect:  []string{"example.com:2019"},
		},
		{
			name:    "duplicate configured origins are coalesced",
			addr:    NetworkAddress{Network: "tcp", Host: "localhost", StartPort: 2019, EndPort: 2019},
			origins: []string{"Example.com:2019", "example.COM.:2019", "http://example.com:2019"},
			expect:  []string{"example.com:2019", "http://example.com:2019"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			admin := AdminConfig{Origins: tc.origins}
			got := admin.allowedOrigins(tc.addr)

			gotSet := make(map[string]struct{})
			for _, tuple := range got {
				gotSet[tuple.String()] = struct{}{}
			}
			if len(gotSet) != len(tc.expect) {
				t.Errorf("Test %d: allowedOrigins() = %v, want %v", i, gotSet, tc.expect)
				return
			}
			for _, expect := range tc.expect {
				if _, ok := gotSet[expect]; !ok {
					t.Errorf("Test %d: allowedOrigins() = %v, missing %q", i, gotSet, expect)
				}
			}
		})
	}
}

// TestAdminOriginConfigConcurrentAccess exercises the origin configuration
// under concurrent request handling, the way a config reload overlaps with
// in-flight requests: the handler's allowed origins are computed once and
// only read afterwards, while a reload computes a fresh slice. Run with
// -race to be meaningful.
func TestAdminOriginConfigConcurrentAccess(t *testing.T) {
	admin := &AdminConfig{Origins: []string{"localhost:2019", "http://example.com:8080"}}
	addr := NetworkAddress{Network: "tcp", Host: "localhost", StartPort: 2019, EndPort: 2019}

	handler := newTestAdminHandler(admin.allowedOrigins(addr), true, true)

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		// concurrent readers: requests flowing through the security checks
		wg.Go(func() {
			for j := 0; j < 50; j++ {
				r := httptest.NewRequest(http.MethodGet, "http://localhost:2019/ok", nil)
				r.Header.Set("Origin", "http://localhost:2019")
				rr := httptest.NewRecorder()
				handler.serveHTTP(rr, r)
				if rr.Code != http.StatusOK {
					t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
					return
				}
			}
		})
		// concurrent reloads: recomputing the allowed origins must not
		// disturb the slice the handler is reading
		wg.Go(func() {
			for j := 0; j < 50; j++ {
				_ = admin.allowedOrigins(addr)
			}
		})
	}
	wg.Wait()
}
