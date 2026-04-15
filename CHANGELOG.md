# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.2] - 2026-04-14

### Changed
- Apex domains (e.g. `example.com`) now use the primary (DNS-01) issuer when `_acme-challenge.<apex>` CNAMEs to the override domain, instead of always routing to the fallback issuer. A specific (non-wildcard) certificate is issued for the apex name directly.

---

## [1.0.1] - 2026-04-13

### Added
- `debug` configuration option. When `true`, DNS prerequisite evaluation details (per-name qualification, CNAME lookup results, lookup failures, and primary/fallback issuer selection) are emitted at info level regardless of the global Caddy log level. When `false` (the default), the same details are only emitted when Caddy's global log level is set to debug.

---

## [1.0.0] - 2026-04-10

### Added

- `tls.issuance.opportunistic` Caddy issuer module that selects between a primary (DNS-01) and fallback (HTTP-01 / TLS-ALPN-01) issuer at runtime based on DNS prerequisites.
- DNS prerequisite check: verifies that `_acme-challenge.<base>` equals or CNAMEs to the configured `dns_challenge_override_domain` before committing to wildcard issuance.
- Automatic subject transformation — hostnames are promoted to wildcard form (e.g. `www.example.com` → `*.example.com`) when prerequisites are met, with no separate `subject_transformer` directive required.
- Fail-closed behaviour: any DNS lookup error, missing override domain, or IP address routes to the fallback issuer.
- `PreCheck`/`Issue` consistency cache: issuer selection made during `PreCheck` is preserved for the subsequent `Issue` call, bounded by a 5-minute TTL and a maximum of 256 entries.
- ARI support (`GetRenewalInfo`) delegating to the primary issuer, with fallback to the secondary issuer if primary does not support ARI (RFC 8739).
- Revocation support (`Revoke`) delegating to the primary issuer, with fallback to the secondary issuer if primary does not support revocation.
- Caddyfile support via `issuer opportunistic { primary ... fallback ... resolvers ... }`.
- Auto-population of `override_domain` from the primary `ACMEIssuer`'s `dns_challenge_override_domain`, avoiding duplicate configuration.
- Custom DNS resolver support via the `resolvers` directive.
- Unit tests covering prerequisite checks, subject transformation, cache eviction, and `PreCheck`/`Issue` consistency.
- CHANGELOG, README, and Apache 2.0 LICENSE.
