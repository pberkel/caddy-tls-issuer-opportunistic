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
	"crypto/x509"
	"fmt"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"
)

// stubIssuer is a minimal certmagic.Issuer for testing.
type stubIssuer struct {
	key     string
	issueFn func(context.Context, *x509.CertificateRequest) (*certmagic.IssuedCertificate, error)
}

func (s *stubIssuer) Issue(ctx context.Context, csr *x509.CertificateRequest) (*certmagic.IssuedCertificate, error) {
	if s.issueFn != nil {
		return s.issueFn(ctx, csr)
	}
	return &certmagic.IssuedCertificate{}, nil
}

func (s *stubIssuer) IssuerKey() string { return s.key }

// configSetterIssuer is a stubIssuer that also records SetConfig calls.
type configSetterIssuer struct {
	stubIssuer
	cfg *certmagic.Config
}

func (s *configSetterIssuer) SetConfig(cfg *certmagic.Config) { s.cfg = cfg }

// newTestIssuer builds an OpportunisticIssuer with the given inner issuers and
// precondition, bypassing Provision so tests need no Caddy context.
func newTestIssuer(primary, fallback certmagic.Issuer, precond DNSPrecondition) *OpportunisticIssuer {
	logger := zap.NewNop()
	precond.logger = logger.Named("prereq_checker")
	return &OpportunisticIssuer{
		primary:      primary,
		fallback:     fallback,
		Precondition: precond,
		logger:       logger,
		cache:        &issuerCache{entries: make(map[string]issuerCacheEntry)},
	}
}

// fastPathPrecond returns a DNSPrecondition that qualifies "www.example.com"
// via the fast path (no DNS lookup) by setting the override domain to the
// expected challenge name.
func fastPathPrecond() DNSPrecondition {
	return DNSPrecondition{OverrideDomain: "_acme-challenge.example.com"}
}

// --- toWildcard ---

func TestToWildcard(t *testing.T) {
	tests := []struct {
		domain string
		want   string
	}{
		{"www.example.com", "*.example.com"},
		{"api.v2.example.com", "*.v2.example.com"},
		{"www.example.co.uk", "*.example.co.uk"},
		// Apex: unchanged.
		{"example.com", "example.com"},
		{"example.co.uk", "example.co.uk"},
		// Already a wildcard: idempotent.
		{"*.example.com", "*.example.com"},
	}
	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			if got := toWildcard(tt.domain); got != tt.want {
				t.Errorf("toWildcard(%q) = %q, want %q", tt.domain, got, tt.want)
			}
		})
	}
}

// --- namesKey ---

func TestNamesKey(t *testing.T) {
	t.Run("single name", func(t *testing.T) {
		if got := namesKey([]string{"example.com"}); got != "example.com" {
			t.Errorf("got %q", got)
		}
	})

	t.Run("sorted regardless of input order", func(t *testing.T) {
		a := namesKey([]string{"b.example.com", "a.example.com"})
		b := namesKey([]string{"a.example.com", "b.example.com"})
		if a != b {
			t.Errorf("namesKey not stable: %q vs %q", a, b)
		}
	})

	t.Run("different sets produce different keys", func(t *testing.T) {
		a := namesKey([]string{"a.example.com"})
		b := namesKey([]string{"b.example.com"})
		if a == b {
			t.Errorf("different name sets produced identical key %q", a)
		}
	})
}

// --- SetConfig ---

func TestSetConfig_SetsTransformerWhenNil(t *testing.T) {
	iss := newTestIssuer(&stubIssuer{}, &stubIssuer{}, fastPathPrecond())
	cfg := &certmagic.Config{}

	iss.SetConfig(cfg)

	if cfg.SubjectTransformer == nil {
		t.Fatal("SubjectTransformer should be set when cfg has none")
	}
}

func TestSetConfig_DoesNotOverwriteExistingTransformer(t *testing.T) {
	iss := newTestIssuer(&stubIssuer{}, &stubIssuer{}, fastPathPrecond())
	sentinel := func(_ context.Context, d string) string { return d }
	cfg := &certmagic.Config{SubjectTransformer: sentinel}

	iss.SetConfig(cfg)

	// Compare function pointers via a call — sentinel always returns the input.
	if cfg.SubjectTransformer(context.Background(), "x") != "x" {
		t.Fatal("SubjectTransformer was overwritten")
	}
	// Verify sentinel (not iss.transformSubject) is installed by checking that a
	// qualifiable name is NOT wildcarded (sentinel is identity, transformSubject
	// would wildcard it).
	got := cfg.SubjectTransformer(context.Background(), "www.example.com")
	if got != "www.example.com" {
		t.Errorf("expected sentinel identity transform, got %q", got)
	}
}

func TestSetConfig_PropagatestoInnerIssuers(t *testing.T) {
	primary := &configSetterIssuer{}
	fallback := &configSetterIssuer{}
	iss := newTestIssuer(primary, fallback, fastPathPrecond())
	cfg := &certmagic.Config{}

	iss.SetConfig(cfg)

	if primary.cfg != cfg {
		t.Error("primary SetConfig was not called with the config")
	}
	if fallback.cfg != cfg {
		t.Error("fallback SetConfig was not called with the config")
	}
}

// --- issuerCache ---

func TestIssuerCache_StoreAndRetrieve(t *testing.T) {
	primary := &stubIssuer{key: "primary"}
	fallback := &stubIssuer{key: "fallback"}
	iss := newTestIssuer(primary, fallback, fastPathPrecond())

	iss.selectAndCache(context.Background(), []string{"www.example.com"})

	iss.cache.mu.Lock()
	entry, ok := iss.cache.entries[namesKey([]string{"www.example.com"})]
	iss.cache.mu.Unlock()

	if !ok {
		t.Fatal("entry not found in cache after selectAndCache")
	}
	if entry.issuer != primary {
		t.Errorf("cached issuer = %v, want primary", entry.issuer)
	}
	if entry.expiresAt.IsZero() {
		t.Error("expiresAt not set")
	}
}

func TestIssuerCache_ExpiredEntryTreatedAsMiss(t *testing.T) {
	var issueCalls []string
	primary := &stubIssuer{key: "primary", issueFn: func(_ context.Context, csr *x509.CertificateRequest) (*certmagic.IssuedCertificate, error) {
		issueCalls = append(issueCalls, "primary")
		return &certmagic.IssuedCertificate{}, nil
	}}
	fallback := &stubIssuer{key: "fallback", issueFn: func(_ context.Context, csr *x509.CertificateRequest) (*certmagic.IssuedCertificate, error) {
		issueCalls = append(issueCalls, "fallback")
		return &certmagic.IssuedCertificate{}, nil
	}}
	// Precondition that never qualifies so selectIssuer returns fallback.
	iss := newTestIssuer(primary, fallback, DNSPrecondition{})

	// Insert an already-expired entry for primary.
	key := namesKey([]string{"www.example.com"})
	iss.cache.mu.Lock()
	iss.cache.entries[key] = issuerCacheEntry{
		issuer:    primary,
		expiresAt: time.Now().Add(-time.Second),
	}
	iss.cache.mu.Unlock()

	_, _ = iss.Issue(context.Background(), &x509.CertificateRequest{DNSNames: []string{"www.example.com"}})

	if len(issueCalls) != 1 || issueCalls[0] != "fallback" {
		t.Errorf("expected fallback after expired cache entry, got %v", issueCalls)
	}
}

func TestIssuerCache_MaxSizeEvictsOldest(t *testing.T) {
	primary := &stubIssuer{key: "primary"}
	fallback := &stubIssuer{key: "fallback"}
	// Precondition never qualifies so all entries use fallback — we only care
	// about eviction, not which issuer is selected.
	iss := newTestIssuer(primary, fallback, DNSPrecondition{})

	// Fill cache to capacity with entries that have future expiry.
	now := time.Now()
	iss.cache.mu.Lock()
	for i := range issuerCacheMaxSize {
		key := fmt.Sprintf("host%d.example.com", i)
		iss.cache.entries[key] = issuerCacheEntry{
			issuer:    fallback,
			expiresAt: now.Add(time.Duration(i+1) * time.Minute),
		}
	}
	iss.cache.mu.Unlock()

	// Inserting one more entry should evict the oldest (host0, expiresAt +1m).
	iss.selectAndCache(context.Background(), []string{"new.example.com"})

	iss.cache.mu.Lock()
	_, oldest := iss.cache.entries["host0.example.com"]
	size := len(iss.cache.entries)
	iss.cache.mu.Unlock()

	if oldest {
		t.Error("oldest entry (host0) should have been evicted")
	}
	if size != issuerCacheMaxSize {
		t.Errorf("cache size = %d, want %d", size, issuerCacheMaxSize)
	}
}

func TestIssuerCache_SweepsExpiredOnWrite(t *testing.T) {
	primary := &stubIssuer{key: "primary"}
	fallback := &stubIssuer{key: "fallback"}
	iss := newTestIssuer(primary, fallback, DNSPrecondition{})

	// Populate with expired entries (below max size so eviction logic isn't hit).
	iss.cache.mu.Lock()
	for i := range 10 {
		key := fmt.Sprintf("expired%d.example.com", i)
		iss.cache.entries[key] = issuerCacheEntry{
			issuer:    fallback,
			expiresAt: time.Now().Add(-time.Second),
		}
	}
	iss.cache.mu.Unlock()

	iss.selectAndCache(context.Background(), []string{"new.example.com"})

	iss.cache.mu.Lock()
	size := len(iss.cache.entries)
	iss.cache.mu.Unlock()

	// Expired entries should have been swept; only the new entry remains.
	if size != 1 {
		t.Errorf("cache size after sweep = %d, want 1", size)
	}
}

// --- PreCheck / Issue consistency ---

func TestPreCheckIssueConsistency_UsesCachedIssuer(t *testing.T) {
	var issueCalls []string
	primary := &stubIssuer{key: "primary", issueFn: func(_ context.Context, _ *x509.CertificateRequest) (*certmagic.IssuedCertificate, error) {
		issueCalls = append(issueCalls, "primary")
		return &certmagic.IssuedCertificate{}, nil
	}}
	fallback := &stubIssuer{key: "fallback", issueFn: func(_ context.Context, _ *x509.CertificateRequest) (*certmagic.IssuedCertificate, error) {
		issueCalls = append(issueCalls, "fallback")
		return &certmagic.IssuedCertificate{}, nil
	}}
	// Precond qualifies via fast path so primary is selected during PreCheck.
	iss := newTestIssuer(primary, fallback, fastPathPrecond())

	names := []string{"www.example.com"}
	if err := iss.PreCheck(context.Background(), names, false); err != nil {
		t.Fatalf("PreCheck: %v", err)
	}

	// Change precondition so a fresh selectIssuer would return fallback.
	iss.Precondition = DNSPrecondition{}

	_, _ = iss.Issue(context.Background(), &x509.CertificateRequest{DNSNames: names})

	if len(issueCalls) != 1 || issueCalls[0] != "primary" {
		t.Errorf("expected primary from cache, got %v", issueCalls)
	}
}

func TestIssueWithoutPreCheck_SelectsFresh(t *testing.T) {
	var issueCalls []string
	primary := &stubIssuer{key: "primary", issueFn: func(_ context.Context, _ *x509.CertificateRequest) (*certmagic.IssuedCertificate, error) {
		issueCalls = append(issueCalls, "primary")
		return &certmagic.IssuedCertificate{}, nil
	}}
	fallback := &stubIssuer{key: "fallback", issueFn: func(_ context.Context, _ *x509.CertificateRequest) (*certmagic.IssuedCertificate, error) {
		issueCalls = append(issueCalls, "fallback")
		return &certmagic.IssuedCertificate{}, nil
	}}
	// Precond does not qualify, so fallback should be selected.
	iss := newTestIssuer(primary, fallback, DNSPrecondition{})

	_, _ = iss.Issue(context.Background(), &x509.CertificateRequest{DNSNames: []string{"www.example.com"}})

	if len(issueCalls) != 1 || issueCalls[0] != "fallback" {
		t.Errorf("expected fallback for fresh selection, got %v", issueCalls)
	}
}

func TestIssue_ConsumesCache(t *testing.T) {
	primary := &stubIssuer{key: "primary"}
	fallback := &stubIssuer{key: "fallback"}
	iss := newTestIssuer(primary, fallback, fastPathPrecond())

	names := []string{"www.example.com"}
	_ = iss.PreCheck(context.Background(), names, false)

	// First Issue consumes the cache entry.
	_, _ = iss.Issue(context.Background(), &x509.CertificateRequest{DNSNames: names})

	// Cache should be empty after Issue.
	iss.cache.mu.Lock()
	_, ok := iss.cache.entries[namesKey(names)]
	iss.cache.mu.Unlock()

	if ok {
		t.Error("cache entry should be consumed after Issue")
	}
}
