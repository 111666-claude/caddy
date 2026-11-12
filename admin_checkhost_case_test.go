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
	"net/http/httptest"
	"testing"
)

// TestAdminHandlerCheckHostCaseInsensitive is the regression test for the
// Host allow-list comparison being case-sensitive. Per RFC 3986 §3.2.2,
// host names are case-insensitive, and url.Parse does not normalize host
// case, so the comparison must fold case. This mirrors the fix applied to
// originAllowed, where an allowed 'http://Example.com:8080' rejected a
// client Host of 'example.com:8080'.
//
// Host and configured origins are now both normalized to originTuples
// before comparison; these cases lock in that the normalization preserves
// the case-insensitive behavior.
func TestAdminHandlerCheckHostCaseInsensitive(t *testing.T) {
	cases := []struct {
		name    string
		allowed string
		host    string
		wantErr bool
	}{
		{
			name:    "allow-list uppercase, request Host lowercase",
			allowed: "http://Example.com:2019",
			host:    "example.com:2019",
			wantErr: false,
		},
		{
			name:    "allow-list lowercase, request Host uppercase",
			allowed: "http://example.com:2019",
			host:    "EXAMPLE.com:2019",
			wantErr: false,
		},
		{
			name:    "default localhost entry, request Host uppercase",
			allowed: "http://localhost:2019",
			host:    "LOCALHOST:2019",
			wantErr: false,
		},
		{
			name:    "different host is still rejected",
			allowed: "http://example.com:2019",
			host:    "evil.example.org:2019",
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			allowed, err := parseOrigin(tc.allowed)
			if err != nil {
				t.Fatalf("invalid allowed origin %q: %v", tc.allowed, err)
			}
			h := adminHandler{allowedOrigins: []originTuple{allowed}}
			r := httptest.NewRequest("GET", "http://"+tc.host+"/config/", nil)
			err = h.checkHost(r)
			if tc.wantErr && err == nil {
				t.Errorf("checkHost(%q) with allowed %v = nil, want error", tc.host, tc.allowed)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("checkHost(%q) with allowed %v = %v, want nil", tc.host, tc.allowed, err)
			}
		})
	}
}
