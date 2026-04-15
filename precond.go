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
	"net"
	"net/netip"
	"strings"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/net/publicsuffix"
)

// DNSPrecondition determines whether DNS-01 prerequisites are met for a set
// of domain names. It is used by OpportunisticIssuer to select which inner
// issuer to use and to decide whether to transform a hostname to wildcard form.
//
// When OverrideDomain is set (automatically populated from the primary
// ACMEIssuer's dns_challenge_override_domain, or set explicitly), the check
// performs a live DNS lookup: it verifies that _acme-challenge.<base> either
// IS OverrideDomain or has a CNAME record pointing to it. This confirms that
// the DNS-01 challenge delegation is in place before committing to wildcard
// issuance.
//
// When OverrideDomain is empty, non-wildcard non-IP names are assumed to
// qualify (lightweight, no network I/O).
type DNSPrecondition struct {
	// OverrideDomain is the domain that _acme-challenge.<base> must equal or
	// CNAME to for DNS-01 prerequisites to be considered met. This should match
	// the dns_challenge_override_domain configured on the primary issuer.
	//
	// If empty, it is automatically populated from the primary ACMEIssuer
	// during provisioning. Set it explicitly only when the primary issuer is
	// not a standard ACMEIssuer.
	OverrideDomain string `json:"override_domain,omitempty"`

	// Custom DNS resolvers to use for CNAME lookups, e.g. ["8.8.8.8:53"].
	// Port defaults to 53 if omitted. If empty, the system resolver is used.
	Resolvers []string `json:"resolvers,omitempty"`

	// When true, per-request DNS precondition evaluation details are logged at
	// info level regardless of the global Caddy log level. When false (the
	// default), the same details are only emitted when Caddy's global log level
	// is set to debug.
	Debug bool `json:"debug,omitempty"`

	logger      *zap.Logger
	lookupCNAME func(ctx context.Context, host string) (string, error) // overridden in tests
}

// debugCheck returns a zap.CheckedEntry for a debug-level message. When the
// Debug flag is enabled the entry is checked at info level so it is always
// emitted regardless of the global Caddy log level. When Debug is false the
// entry is only emitted when Caddy's global log level includes debug.
func (c *DNSPrecondition) debugCheck(msg string) *zapcore.CheckedEntry {
	if c.logger == nil {
		return nil
	}
	if c.Debug {
		return c.logger.Check(zapcore.InfoLevel, msg)
	}
	return c.logger.Check(zapcore.DebugLevel, msg)
}

// Met returns true only if every name in names satisfies the DNS-01
// prerequisites. A single disqualifying name causes the method to return false.
// An empty name list returns false: there are no names to issue a certificate
// for, so routing to the DNS issuer would be pointless.
func (c *DNSPrecondition) Met(ctx context.Context, names []string) bool {
	if len(names) == 0 {
		return false
	}
	for _, name := range names {
		if !c.nameQualifies(ctx, name) {
			if ce := c.debugCheck("name does not meet DNS-01 prerequisites"); ce != nil {
				ce.Write(zap.String("name", name))
			}
			return false
		}
	}
	return true
}

func (c *DNSPrecondition) nameQualifies(ctx context.Context, name string) bool {
	// Wildcards require DNS-01 — unconditionally qualifying avoids an
	// unnecessary fallback that would fail anyway.
	if strings.HasPrefix(name, "*.") {
		return true
	}

	// IP addresses have no DNS zone; DNS-01 cannot validate them.
	if _, err := netip.ParseAddr(name); err == nil {
		return false
	}

	// Verify that the ACME challenge subdomain for this name is either equal
	// to the override domain or CNAMEd to it. Without an override domain we
	// have no way to confirm DNS-01 will work, so we fail closed and let the
	// fallback issuer handle it.
	if c.OverrideDomain == "" {
		return false
	}
	return c.checkCNAMEDelegation(ctx, name)
}

// checkCNAMEDelegation checks that the ACME challenge subdomain for name is
// equal to, or has a CNAME chain leading to, OverrideDomain.
//
// For subdomains the challenge name is derived from the wildcard that would
// cover the name (e.g. "www.example.com" → "_acme-challenge.example.com").
// For apex domains the challenge name is "_acme-challenge.<apex>" directly,
// since DNS-01 can validate apex domains without a wildcard certificate.
//
// The check fails closed: any lookup error (NXDOMAIN, timeout, network error)
// returns false so that a broken delegation falls back to HTTP-01 rather than
// attempting a DNS-01 challenge that is guaranteed to fail.
func (c *DNSPrecondition) checkCNAMEDelegation(ctx context.Context, name string) bool {
	registered, err := publicsuffix.EffectiveTLDPlusOne(name)
	if err != nil {
		// Unknown or invalid domain — cannot determine challenge name.
		return false
	}

	// Determine the challenge name:
	//   apex "example.com"         → "_acme-challenge.example.com"
	//   sub  "www.example.com"     → "_acme-challenge.example.com"
	//   deep "api.v2.example.com"  → "_acme-challenge.v2.example.com"
	var challengeName string
	if name == registered {
		challengeName = "_acme-challenge." + name
	} else {
		dot := strings.Index(name, ".")
		challengeName = "_acme-challenge." + name[dot+1:]
	}

	overrideDomain := strings.TrimSuffix(c.OverrideDomain, ".")

	// Fast path: challenge name IS the override domain — no lookup needed.
	if strings.TrimSuffix(challengeName, ".") == overrideDomain {
		return true
	}

	// Follow the CNAME chain and check if the final target is the override domain.
	cname, err := c.resolveCNAME(ctx, challengeName)
	if err != nil {
		if ce := c.debugCheck("CNAME lookup failed; DNS-01 prereqs not met"); ce != nil {
			ce.Write(
				zap.String("challenge_name", challengeName),
				zap.String("override_domain", overrideDomain),
				zap.Error(err))
		}
		return false
	}

	result := strings.TrimSuffix(cname, ".")
	if ce := c.debugCheck("CNAME lookup result"); ce != nil {
		ce.Write(
			zap.String("challenge_name", challengeName),
			zap.String("cname", result),
			zap.String("override_domain", overrideDomain),
			zap.Bool("match", result == overrideDomain))
	}
	return result == overrideDomain
}

// resolveCNAME looks up the CNAME for host. When custom resolvers are
// configured, each is tried in order and the first successful result is
// returned. Falls back to the system resolver when no custom resolvers are
// configured.
func (c *DNSPrecondition) resolveCNAME(ctx context.Context, host string) (string, error) {
	if c.lookupCNAME != nil {
		return c.lookupCNAME(ctx, host)
	}
	if len(c.Resolvers) == 0 {
		return net.DefaultResolver.LookupCNAME(ctx, host)
	}
	var lastErr error
	for _, addr := range c.Resolvers {
		if _, _, err := net.SplitHostPort(addr); err != nil {
			// No port specified — default to 53.
			addr = net.JoinHostPort(addr, "53")
		}
		r := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "udp", addr)
			},
		}
		cname, err := r.LookupCNAME(ctx, host)
		if err == nil {
			return cname, nil
		}
		lastErr = err
	}
	return "", lastErr
}
