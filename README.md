# caddy-issuer-opportunistic

A [Caddy](https://caddyserver.com) TLS issuer module (`tls.issuance.opportunistic`) that opportunistically issues wildcard certificates via DNS-01 challenge when DNS prerequisites are met, and falls back to a secondary issuer (typically HTTP-01 or TLS-ALPN-01) otherwise.

Designed for on-demand TLS deployments where some hostnames have DNS-01 delegation configured and others do not.

> **Experimental:** The configuration interface may change before a stable release.

## How it works

When Caddy needs a certificate for a hostname, the opportunistic issuer:

1. Checks whether `_acme-challenge.<base>` is equal to, or has a CNAME record pointing to, the configured `dns_challenge_override_domain`.
2. If the check passes, the hostname is transformed to its wildcard form (e.g. `www.example.com` → `*.example.com`) and the certificate is issued by the **primary** issuer using DNS-01.
3. If the check fails — including on any DNS lookup error — the original hostname is kept and the certificate is issued by the **fallback** issuer using HTTP-01 or TLS-ALPN-01.

Subject transformation is registered automatically; no separate `subject_transformer` directive is required.

The DNS prerequisite check is fail-closed: any error (NXDOMAIN, timeout, network failure, missing override domain) routes to the fallback issuer.

## Prerequisites

- Caddy built with this module (see [Installation](#installation))
- On-demand TLS enabled (`on_demand` in Caddyfile or `on_demand: true` in JSON)
- A DNS provider module for the primary issuer (e.g. a libdns provider)
- DNS delegation in place: `_acme-challenge.<base>` CNAMEd to the override domain for any hostname that should receive a wildcard certificate

## Installation

Build Caddy with this module using [`xcaddy`](https://github.com/caddyserver/xcaddy):

```sh
xcaddy build \
  --with github.com/pberkel/caddy-issuer-opportunistic \
  --with github.com/libdns/<your-dns-provider>
```

## Configuration

### Caddyfile

```caddyfile
{
    on_demand_tls {
        ask https://auth.example.internal/check
    }

    tls {
        issuer opportunistic {
            primary acme {
                dir https://acme-v02.api.letsencrypt.org/directory
                dns <provider> {
                    # provider-specific credentials
                }
                dns_challenge_override_domain acme.example.net
            }
            fallback acme {
                dir https://acme-v02.api.letsencrypt.org/directory
            }
            resolvers 8.8.8.8 1.1.1.1
        }
    }
}

*.example.com {
    tls {
        on_demand
    }
    reverse_proxy localhost:8080
}
```

The `dns_challenge_override_domain` on the primary issuer is automatically read; there is no need to repeat it in the `opportunistic` block.

#### Subdirectives

| Subdirective | Required | Description |
|---|---|---|
| `primary <module> { ... }` | Yes | Issuer used when DNS prerequisites are met. Must support wildcard certificates (DNS-01). |
| `fallback <module> { ... }` | Yes | Issuer used when DNS prerequisites are not met. Typically an ACME issuer using HTTP-01 or TLS-ALPN-01. |
| `resolvers <addr> ...` | No | Custom DNS resolvers for CNAME lookups (e.g. `8.8.8.8`). Port defaults to 53. Uses the system resolver if omitted. |

### JSON

```json
{
  "apps": {
    "tls": {
      "automation": {
        "on_demand": {
          "ask": "https://auth.example.internal/check"
        },
        "policies": [
          {
            "on_demand": true,
            "issuers": [
              {
                "module": "opportunistic",
                "primary": {
                  "module": "acme",
                  "ca": "https://acme-v02.api.letsencrypt.org/directory",
                  "challenges": {
                    "dns": {
                      "provider": {
                        "name": "<provider>"
                      },
                      "override_domain": "acme.example.net"
                    }
                  }
                },
                "fallback": {
                  "module": "acme",
                  "ca": "https://acme-v02.api.letsencrypt.org/directory"
                },
                "precondition": {
                  "resolvers": ["8.8.8.8", "1.1.1.1"]
                }
              }
            ]
          }
        ]
      }
    }
  }
}
```

## DNS setup

For each base domain that should receive wildcard certificates, add a CNAME record delegating the ACME challenge subdomain to your DNS provider's override domain:

```
_acme-challenge.example.com.  IN  CNAME  acme.example.net.
```

Hostnames whose base domain does not have this delegation will automatically use the fallback issuer and receive a specific (non-wildcard) certificate.

## Behaviour reference

| Hostname | DNS delegation present | Certificate issued | Issuer |
|---|---|---|---|
| `www.example.com` | Yes | `*.example.com` | Primary (DNS-01) |
| `api.v2.example.com` | Yes (`_acme-challenge.v2.example.com`) | `*.v2.example.com` | Primary (DNS-01) |
| `www.example.com` | No | `www.example.com` | Fallback (HTTP-01) |
| `example.com` (apex) | — | `example.com` | Fallback (HTTP-01) |
| `*.example.com` | — | `*.example.com` | Primary (DNS-01) |
| IP address | — | — | Fallback |

## License

Apache 2.0 — see [LICENSE](LICENSE).
