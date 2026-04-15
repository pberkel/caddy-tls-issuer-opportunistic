// Copyright 2026 Pieter Berkel
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

package opportunistic

import (
	"context"
	"fmt"
	"testing"
)

func TestDNSPrecondition_Met(t *testing.T) {
	tests := []struct {
		name           string
		overrideDomain string
		names          []string
		lookupCNAME    func(context.Context, string) (string, error)
		want           bool
	}{
		{
			name: "empty name list",
			want: false,
		},
		{
			name:  "wildcard qualifies without override domain",
			names: []string{"*.example.com"},
			want:  true,
		},
		{
			name:  "IPv4 address does not qualify",
			names: []string{"1.2.3.4"},
			want:  false,
		},
		{
			name:  "IPv6 address does not qualify",
			names: []string{"2001:db8::1"},
			want:  false,
		},
		{
			name:  "no override domain fails closed",
			names: []string{"www.example.com"},
			want:  false,
		},
		{
			name:           "apex domain qualifies when CNAME delegation present",
			overrideDomain: "acme.example.net",
			names:          []string{"example.com"},
			lookupCNAME: func(_ context.Context, host string) (string, error) {
				if host == "_acme-challenge.example.com" {
					return "acme.example.net.", nil
				}
				return "", fmt.Errorf("unexpected host: %s", host)
			},
			want: true,
		},
		{
			name:           "apex domain does not qualify without matching CNAME",
			overrideDomain: "acme.example.net",
			names:          []string{"example.com"},
			lookupCNAME: func(_ context.Context, _ string) (string, error) {
				return "", fmt.Errorf("NXDOMAIN")
			},
			want: false,
		},
		{
			name:           "challenge name equals override domain (fast path, no lookup)",
			overrideDomain: "_acme-challenge.example.com",
			names:          []string{"www.example.com"},
			want:           true,
		},
		{
			name:           "challenge name equals override domain with trailing dot",
			overrideDomain: "_acme-challenge.example.com.",
			names:          []string{"www.example.com"},
			want:           true,
		},
		{
			name:           "CNAME resolves to override domain",
			overrideDomain: "acme.example.net",
			names:          []string{"www.example.com"},
			lookupCNAME: func(_ context.Context, _ string) (string, error) {
				return "acme.example.net.", nil
			},
			want: true,
		},
		{
			name:           "CNAME resolves to override domain with trailing dot in override",
			overrideDomain: "acme.example.net.",
			names:          []string{"www.example.com"},
			lookupCNAME: func(_ context.Context, _ string) (string, error) {
				return "acme.example.net.", nil
			},
			want: true,
		},
		{
			name:           "CNAME resolves to different domain",
			overrideDomain: "acme.example.net",
			names:          []string{"www.example.com"},
			lookupCNAME: func(_ context.Context, _ string) (string, error) {
				return "other.example.org.", nil
			},
			want: false,
		},
		{
			name:           "CNAME lookup error fails closed",
			overrideDomain: "acme.example.net",
			names:          []string{"www.example.com"},
			lookupCNAME: func(_ context.Context, _ string) (string, error) {
				return "", fmt.Errorf("lookup timeout")
			},
			want: false,
		},
		{
			name:           "all names must qualify — one IP disqualifies",
			overrideDomain: "_acme-challenge.example.com",
			names:          []string{"www.example.com", "1.2.3.4"},
			want:           false,
		},
		{
			name:  "all names must qualify — one no-override disqualifies",
			names: []string{"*.example.com", "www.example.com"},
			want:  false,
		},
		{
			name:           "multi-level subdomain: challenge at parent of first dot",
			overrideDomain: "acme.example.net",
			names:          []string{"api.v2.example.com"},
			lookupCNAME: func(_ context.Context, host string) (string, error) {
				if host == "_acme-challenge.v2.example.com" {
					return "acme.example.net.", nil
				}
				return "", fmt.Errorf("unexpected host: %s", host)
			},
			want: true,
		},
		{
			name:           "public suffix apex does not qualify without matching CNAME",
			overrideDomain: "acme.example.net",
			names:          []string{"example.co.uk"},
			lookupCNAME: func(_ context.Context, _ string) (string, error) {
				return "", fmt.Errorf("NXDOMAIN")
			},
			want: false,
		},
		{
			name:           "subdomain of public suffix uses correct challenge name",
			overrideDomain: "acme.example.net",
			names:          []string{"www.example.co.uk"},
			lookupCNAME: func(_ context.Context, host string) (string, error) {
				if host == "_acme-challenge.example.co.uk" {
					return "acme.example.net.", nil
				}
				return "", fmt.Errorf("unexpected host: %s", host)
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &DNSPrecondition{
				OverrideDomain: tt.overrideDomain,
				lookupCNAME:    tt.lookupCNAME,
			}
			if got := c.Met(context.Background(), tt.names); got != tt.want {
				t.Errorf("Met() = %v, want %v", got, tt.want)
			}
		})
	}
}
