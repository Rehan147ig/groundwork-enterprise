// Package secretref parses and validates credential references — the
// ONLY sanctioned way to hand a connector (or any service) its
// credential in production.
//
// Reference grammar:
//
//	keyring://<purpose>[/<id>]      resolved through the keyring
//	                                KeyProvider for the purpose
//	secretsmanager://<name>         external secret-manager adapter
//	env://<VARNAME>                 environment lookup — local/dev ONLY
//
// keyring://connector/msgraph is the canonical connector credential
// reference: purpose "connector" (a known keyring purpose), id "msgraph"
// (informational — the current key for the purpose is returned, so
// rotation moves forward without touching the reference).
package secretref

import (
	"fmt"
	"strings"
)

// Schemes.
const (
	SchemeKeyring        = "keyring"
	SchemeEnv            = "env"
	SchemeSecretsManager = "secretsmanager"
)

// Ref is one parsed credential reference.
type Ref struct {
	Scheme  string // SchemeKeyring | SchemeEnv | SchemeSecretsManager
	Purpose string // keyring purpose (first path segment); "" when absent
	ID      string // optional trailing identifier (informational)
	Raw     string // the original reference, for error messages and audit
}

// Parse validates a credential reference and splits it into parts.
// Malformed references and unknown schemes fail closed.
func Parse(ref string) (Ref, error) {
	raw := strings.TrimSpace(ref)
	if raw == "" {
		return Ref{}, fmt.Errorf("secretref: empty reference")
	}
	rest, ok := strings.CutPrefix(raw, "keyring://")
	if ok {
		return parseKeyring(raw, rest)
	}
	if rest, ok := strings.CutPrefix(raw, "env://"); ok {
		name := strings.TrimSpace(rest)
		if name == "" || strings.ContainsAny(name, "/?&#") {
			return Ref{}, fmt.Errorf("secretref: invalid env reference %q (expected env://VARNAME)", raw)
		}
		return Ref{Scheme: SchemeEnv, ID: name, Raw: raw}, nil
	}
	if strings.HasPrefix(raw, "secretsmanager://") ||
		strings.HasPrefix(raw, "aws:secretsmanager:") ||
		strings.HasPrefix(raw, "gcp:secretmanager:") ||
		strings.HasPrefix(raw, "vault://") {
		return Ref{Scheme: SchemeSecretsManager, Raw: raw}, nil
	}
	return Ref{}, fmt.Errorf("secretref: unsupported reference scheme in %q (allowed: keyring://, secretsmanager://, env:// for local/dev)", raw)
}

func parseKeyring(raw, rest string) (Ref, error) {
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	if len(parts) == 0 || strings.TrimSpace(parts[0]) == "" {
		return Ref{}, fmt.Errorf("secretref: keyring reference %q is missing its purpose (expected keyring://<purpose>[/<id>])", raw)
	}
	for _, p := range parts {
		if p == "" || strings.ContainsAny(p, "?#&") {
			return Ref{}, fmt.Errorf("secretref: invalid keyring reference %q", raw)
		}
	}
	id := ""
	if len(parts) > 1 {
		id = strings.Join(parts[1:], "/")
	}
	return Ref{Scheme: SchemeKeyring, Purpose: parts[0], ID: id, Raw: raw}, nil
}

// IsKeyring reports whether the reference resolves through the keyring.
func (r Ref) IsKeyring() bool { return r.Scheme == SchemeKeyring }

// IsEnv reports whether the reference is a local/dev environment lookup.
func (r Ref) IsEnv() bool { return r.Scheme == SchemeEnv }

// IsSecretsManager reports whether the reference routes to an external
// secret-manager adapter.
func (r Ref) IsSecretsManager() bool { return r.Scheme == SchemeSecretsManager }

// IsKeyringRef reports whether ref parses as a keyring reference.
func IsKeyringRef(ref string) bool {
	r, err := Parse(ref)
	return err == nil && r.IsKeyring()
}

// GuardProductionRef enforces the production credential policy: a
// deployment with GROUNDWORK_ENV=production must hand the connector a
// keyring:// or secretsmanager:// reference — never env:// and never a
// plaintext environment value (the caller checks the latter by passing
// an empty ref). The error names the offending reference and never
// material.
func GuardProductionRef(ref string) error {
	r, err := Parse(ref)
	if err != nil {
		return err
	}
	if r.IsEnv() {
		return fmt.Errorf("secretref: env:// references are forbidden in production (ref %q) — use keyring://<purpose>/<id> or a secrets-manager reference", r.Raw)
	}
	return nil
}
