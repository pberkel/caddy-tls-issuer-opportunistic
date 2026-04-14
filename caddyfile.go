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
	"strconv"

	"github.com/caddyserver/certmagic"

	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

// UnmarshalCaddyfile populates OpportunisticIssuer from Caddyfile tokens.
//
// Syntax:
//
//	issuer opportunistic {
//	    primary   <module> [<dir_url>] { ... }
//	    fallback  <module> [<dir_url>] { ... }
//	    resolvers <dns_server> ...
//	}
//
// primary and fallback accept the same block syntax as any tls.issuance module
// (e.g. the built-in "acme" module). Both are required.
//
// resolvers sets custom DNS servers used for CNAME delegation lookups during
// DNS-01 prerequisite checks. Multiple addresses may be provided; they are
// tried in order and the first to respond successfully is used.
func (iss *OpportunisticIssuer) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume "opportunistic"
	if d.NextArg() {
		return d.ArgErr()
	}

	for nesting := d.Nesting(); d.NextBlock(nesting); {
		switch d.Val() {
		case "primary":
			if iss.PrimaryRaw != nil {
				return d.Err("primary issuer already specified")
			}
			raw, err := unmarshalIssuer(d)
			if err != nil {
				return err
			}
			iss.PrimaryRaw = raw

		case "fallback":
			if iss.FallbackRaw != nil {
				return d.Err("fallback issuer already specified")
			}
			raw, err := unmarshalIssuer(d)
			if err != nil {
				return err
			}
			iss.FallbackRaw = raw

		case "resolvers":
			iss.Precondition.Resolvers = d.RemainingArgs()
			if len(iss.Precondition.Resolvers) == 0 {
				return d.ArgErr()
			}
			// Resolvers are tried in order; the first to respond successfully is used.

		case "debug":
			if !d.NextArg() {
				return d.ArgErr()
			}
			v, err := strconv.ParseBool(d.Val())
			if err != nil {
				return d.Errf("invalid boolean value for debug: %s", d.Val())
			}
			iss.Debug = v

		default:
			return d.Errf("unknown subdirective '%s'", d.Val())
		}
	}

	return nil
}

// unmarshalIssuer reads the next module name token, delegates Caddyfile
// parsing to that module, and returns the JSON-encoded module object.
// On entry d must be positioned immediately after the directive name
// (i.e. "primary" or "fallback"); the next token must be the module name.
func unmarshalIssuer(d *caddyfile.Dispenser) ([]byte, error) {
	if !d.NextArg() {
		return nil, d.ArgErr()
	}
	modName := d.Val()
	modID := "tls.issuance." + modName

	unm, err := caddyfile.UnmarshalModule(d, modID)
	if err != nil {
		return nil, err
	}
	issuer, ok := unm.(certmagic.Issuer)
	if !ok {
		return nil, d.Errf("module %s (%T) is not a certmagic.Issuer", modID, unm)
	}
	return caddyconfig.JSONModuleObject(issuer, "module", modName, nil), nil
}

// Interface guards
var (
	_ caddyfile.Unmarshaler = (*OpportunisticIssuer)(nil)
)
