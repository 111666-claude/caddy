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
	"testing"
)

// TestAdminHandlerOriginAllowed_CaseInsensitiveHost is the regression
// test for the host allow-list comparison being case-sensitive. Per
// RFC 3986 §3.2.2, host names are case-insensitive.
//
// Origins are now normalized to originTuples before comparison; these
// cases lock in that the normalization preserves the case-insensitive
// behavior.
func TestAdminHandlerOriginAllowed_CaseInsensitiveHost(t *testing.T) {
	cases := []struct {
		name    string
		allowed string
		origin  string
	}{
		{
			name:    "allow-list uppercase, origin lowercase",
			allowed: "http://Example.com:8080",
			origin:  "http://example.com:8080",
		},
		{
			name:    "allow-list lowercase, origin uppercase",
			allowed: "http://example.com:8080",
			origin:  "http://EXAMPLE.com:8080",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			allowed, err := parseOrigin(tc.allowed)
			if err != nil {
				t.Fatalf("invalid allowed origin %q: %v", tc.allowed, err)
			}
			origin, err := parseOrigin(tc.origin)
			if err != nil {
				t.Fatalf("invalid origin %q: %v", tc.origin, err)
			}
			h := adminHandler{allowedOrigins: []originTuple{allowed}}
			if !h.originAllowed(origin) {
				t.Errorf("originAllowed(%v) with allowed %v = false, want true", tc.origin, tc.allowed)
			}
		})
	}
}
