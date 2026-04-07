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

// Package opportunistic provides a TLS certificate issuer that uses DNS-01
// challenges (and issues wildcard certificates) when prerequisites are met,
// falling back to HTTP-01 or TLS-ALPN-01 for specific certificates otherwise.
// Subject transformation is handled automatically by the issuer itself.

package opportunistic

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/mholt/acmez/v3/acme"
	"go.uber.org/zap"
	"golang.org/x/net/publicsuffix"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
)

func init() {
	caddy.RegisterModule(OpportunisticIssuer{})
}

// OpportunisticIssuer is a TLS certificate issuer (module ID:
// tls.issuance.opportunistic) that selects between two inner issuers at
// issuance time based on whether DNS-01 prerequisites are met. When
// prerequisites are met it issues wildcard certificates via the primary issuer;
// otherwise it falls back to the secondary issuer (typically HTTP-01 or
// TLS-ALPN-01). Subject transformation is registered automatically via
// SetConfig so no separate subject_transformer directive is required.
//
// EXPERIMENTAL: Subject to change.
type OpportunisticIssuer struct {
	// The issuer to use when DNS-01 challenge prerequisites are met.
	// Any tls.issuance module is accepted. The primary issuer must be capable
	// of issuing wildcard certificates (e.g. an ACME issuer with a DNS
	// challenge provider, or an internal CA), because when prerequisites are
	// met this issuer will receive wildcard subject names.
	PrimaryRaw json.RawMessage `json:"primary,omitempty" caddy:"namespace=tls.issuance inline_key=module"`

	// The issuer to use when DNS-01 prerequisites are not met.
	// Any tls.issuance module is accepted. Typically an ACME issuer relying
	// on HTTP-01 or TLS-ALPN-01 challenges, which cannot validate wildcards.
	FallbackRaw json.RawMessage `json:"fallback,omitempty" caddy:"namespace=tls.issuance inline_key=module"`

	// Configuration for the DNS-01 prerequisite checker that determines which
	// issuer is selected at runtime.
	Precondition DNSPrecondition `json:"precondition"`

	primary  certmagic.Issuer
	fallback certmagic.Issuer
	logger   *zap.Logger
	cache    *issuerCache
}

// issuerCache records the issuer selected during PreCheck, keyed by the
// sorted, comma-joined name list. This ensures Issue always uses the same
// issuer that PreCheck prepared challenge infrastructure for, even if the
// DNS state changes between the two calls.
//
// Entries are bounded by issuerCacheMaxSize and expire after issuerCacheTTL
// to prevent unbounded growth under high on-demand TLS load.
type issuerCache struct {
	mu      sync.Mutex
	entries map[string]issuerCacheEntry
}

type issuerCacheEntry struct {
	issuer    certmagic.Issuer
	expiresAt time.Time
}

const (
	issuerCacheTTL     = 5 * time.Minute
	issuerCacheMaxSize = 256
)

// CaddyModule returns the Caddy module information.
func (OpportunisticIssuer) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "tls.issuance.opportunistic",
		New: func() caddy.Module { return new(OpportunisticIssuer) },
	}
}

// Provision sets up the issuer, loading and provisioning both inner issuers.
func (iss *OpportunisticIssuer) Provision(ctx caddy.Context) error {
	iss.logger = ctx.Logger()
	iss.Precondition.logger = iss.logger.Named("prereq_checker")
	iss.cache = &issuerCache{entries: make(map[string]issuerCacheEntry)}

	if iss.PrimaryRaw != nil {
		val, err := ctx.LoadModule(iss, "PrimaryRaw")
		if err != nil {
			return fmt.Errorf("loading primary issuer module: %v", err)
		}
		iss.primary = val.(certmagic.Issuer)
	}

	if iss.FallbackRaw != nil {
		val, err := ctx.LoadModule(iss, "FallbackRaw")
		if err != nil {
			return fmt.Errorf("loading fallback issuer module: %v", err)
		}
		iss.fallback = val.(certmagic.Issuer)
	}

	if iss.primary == nil {
		return fmt.Errorf("primary issuer is required")
	}
	if iss.fallback == nil {
		return fmt.Errorf("fallback issuer is required")
	}

	// Auto-populate the prereq checker's override domain from the primary
	// ACMEIssuer if not set explicitly. This avoids requiring the user to
	// configure dns_challenge_override_domain in two places.
	if iss.Precondition.OverrideDomain == "" {
		if acmeIssuer, ok := iss.primary.(*caddytls.ACMEIssuer); ok {
			if acmeIssuer.Challenges != nil && acmeIssuer.Challenges.DNS != nil {
				iss.Precondition.OverrideDomain = acmeIssuer.Challenges.DNS.OverrideDomain
			}
		}
	}

	iss.logger.Info("opportunistic issuer ready")

	return nil
}

// SetConfig implements caddytls.ConfigSetter. It auto-registers the issuer as
// the certmagic SubjectTransformer (if none was explicitly configured) so that
// on-demand TLS wildcard-transforms subjects using the same prereq logic that
// selects challenges at issuance time — without requiring a separate
// subject_transformer directive. Both inner issuers also receive the config.
func (iss *OpportunisticIssuer) SetConfig(cfg *certmagic.Config) {
	if cfg.SubjectTransformer == nil {
		cfg.SubjectTransformer = iss.transformSubject
	}
	if cs, ok := iss.primary.(caddytls.ConfigSetter); ok {
		cs.SetConfig(cfg)
	}
	if cs, ok := iss.fallback.(caddytls.ConfigSetter); ok {
		cs.SetConfig(cfg)
	}
}

// transformSubject is the certmagic.Config.SubjectTransformer callback.
// It converts a hostname to wildcard form only when DNS-01 prerequisites
// are met, keeping subject transformation consistent with issuer selection.
func (iss *OpportunisticIssuer) transformSubject(ctx context.Context, domain string) string {
	if !iss.Precondition.Met(ctx, []string{domain}) {
		return domain
	}
	return toWildcard(domain)
}

// toWildcard converts domain to its one-level wildcard form using the Public
// Suffix List. Returns domain unchanged if it is already the registered apex
// or if the PSL lookup fails.
func toWildcard(domain string) string {
	registered, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		return domain
	}
	if domain == registered {
		return domain
	}
	dot := strings.Index(domain, ".")
	return "*" + domain[dot:]
}

// PreCheck implements certmagic.PreChecker. It runs the DNS prereq check,
// caches the selected issuer for use by Issue, then delegates to that
// issuer's PreCheck if it implements the interface.
//
// Caching is necessary because PreCheck and Issue run as separate calls and
// the prereq check result must be consistent between them — particularly once
// network-based checks (NS record probing) are added.
func (iss *OpportunisticIssuer) PreCheck(ctx context.Context, names []string, interactive bool) error {
	issuer := iss.selectAndCache(ctx, names)
	if pc, ok := issuer.(certmagic.PreChecker); ok {
		return pc.PreCheck(ctx, names, interactive)
	}
	return nil
}

// Issue obtains a certificate. It reuses the issuer selected during PreCheck
// for the same name set; if no cached entry exists (e.g. PreCheck was not
// called) it falls back to a fresh selection.
func (iss *OpportunisticIssuer) Issue(ctx context.Context, csr *x509.CertificateRequest) (*certmagic.IssuedCertificate, error) {
	key := namesKey(csr.DNSNames)
	iss.cache.mu.Lock()
	entry, ok := iss.cache.entries[key]
	if ok {
		if time.Now().After(entry.expiresAt) {
			ok = false
		}
		delete(iss.cache.entries, key)
	}
	iss.cache.mu.Unlock()

	var issuer certmagic.Issuer
	if ok {
		issuer = entry.issuer
	} else {
		// PreCheck was not called, used different names, or entry expired;
		// select fresh.
		issuer = iss.selectIssuer(ctx, csr.DNSNames)
	}

	return issuer.Issue(ctx, csr)
}

// IssuerKey returns the issuer key for certificate storage namespacing.
// Uses the primary issuer's key so that certificates obtained via DNS-01 and
// HTTP-01 are stored under the same key and can be reused across restarts.
func (iss *OpportunisticIssuer) IssuerKey() string {
	return iss.primary.IssuerKey()
}

// GetRenewalInfo implements certmagic.RenewalInfoGetter by delegating to
// whichever inner issuer supports ARI. Primary is tried first (consistent
// with IssuerKey); fallback is tried if primary does not support ARI.
func (iss *OpportunisticIssuer) GetRenewalInfo(ctx context.Context, cert certmagic.Certificate) (acme.RenewalInfo, error) {
	if rig, ok := iss.primary.(certmagic.RenewalInfoGetter); ok {
		return rig.GetRenewalInfo(ctx, cert)
	}
	if rig, ok := iss.fallback.(certmagic.RenewalInfoGetter); ok {
		return rig.GetRenewalInfo(ctx, cert)
	}
	return acme.RenewalInfo{}, fmt.Errorf("neither primary nor fallback issuer supports ARI")
}

// Revoke implements certmagic.Revoker by delegating to whichever inner issuer
// supports revocation. Primary is tried first; fallback is tried if primary
// does not support revocation.
func (iss *OpportunisticIssuer) Revoke(ctx context.Context, cert certmagic.CertificateResource, reason int) error {
	if r, ok := iss.primary.(certmagic.Revoker); ok {
		return r.Revoke(ctx, cert, reason)
	}
	if r, ok := iss.fallback.(certmagic.Revoker); ok {
		return r.Revoke(ctx, cert, reason)
	}
	return fmt.Errorf("neither primary nor fallback issuer supports revocation")
}

// selectAndCache runs the prereq check, caches the result under the name key,
// and returns the selected issuer.
func (iss *OpportunisticIssuer) selectAndCache(ctx context.Context, names []string) certmagic.Issuer {
	issuer := iss.selectIssuer(ctx, names)
	key := namesKey(names)
	now := time.Now()
	iss.cache.mu.Lock()
	// Sweep expired entries.
	for k, e := range iss.cache.entries {
		if now.After(e.expiresAt) {
			delete(iss.cache.entries, k)
		}
	}
	// If still at capacity, evict the soonest-expiring entry.
	if len(iss.cache.entries) >= issuerCacheMaxSize {
		var oldest string
		var oldestExp time.Time
		for k, e := range iss.cache.entries {
			if oldest == "" || e.expiresAt.Before(oldestExp) {
				oldest, oldestExp = k, e.expiresAt
			}
		}
		delete(iss.cache.entries, oldest)
	}
	iss.cache.entries[key] = issuerCacheEntry{issuer: issuer, expiresAt: now.Add(issuerCacheTTL)}
	iss.cache.mu.Unlock()
	return issuer
}

// selectIssuer runs the prereq check and returns the appropriate inner issuer.
func (iss *OpportunisticIssuer) selectIssuer(ctx context.Context, names []string) certmagic.Issuer {
	if iss.Precondition.Met(ctx, names) {
		iss.logger.Debug("DNS-01 prerequisites met; using primary issuer",
			zap.Strings("names", names))
		return iss.primary
	}
	iss.logger.Debug("DNS-01 prerequisites not met; using fallback issuer",
		zap.Strings("names", names))
	return iss.fallback
}

// namesKey returns a stable cache key for a slice of domain names.
func namesKey(names []string) string {
	sorted := make([]string, len(names))
	copy(sorted, names)
	sort.Strings(sorted)
	return strings.Join(sorted, ",")
}

// Interface guards
var (
	_ caddy.Module                = (*OpportunisticIssuer)(nil)
	_ caddy.Provisioner           = (*OpportunisticIssuer)(nil)
	_ certmagic.Issuer            = (*OpportunisticIssuer)(nil)
	_ certmagic.PreChecker        = (*OpportunisticIssuer)(nil)
	_ certmagic.Revoker           = (*OpportunisticIssuer)(nil)
	_ certmagic.RenewalInfoGetter = (*OpportunisticIssuer)(nil)
	_ caddytls.ConfigSetter       = (*OpportunisticIssuer)(nil)
)
