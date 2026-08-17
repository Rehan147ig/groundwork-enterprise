package contract

import (
	"context"
	"errors"
	"strings"

	"groundwork/query-runtime/internal/aclsync"
)

// VersionedConnector is the versioned contract every Groundwork
// connector implements: the aclsync read surface plus a
// self-describing Descriptor. The Service validates the descriptor once
// at wiring time (Validate) and relies on its declared capabilities.
type VersionedConnector interface {
	aclsync.Connector
	// Descriptor returns the connector's versioned self-description.
	// It must be stable for the lifetime of the process.
	Descriptor() ProviderDescriptor
}

// EventSource is the optional versioned delta surface. Connectors that
// declare CapabilityDelta implement it; the service consumes the
// ChangeEvent envelopes for replay-protected incremental application.
// Events must carry stable IDs and, when the connector declares
// CapabilityTombstones, tombstones for deleted resources.
type EventSource interface {
	// WatchEvents streams versioned change events until ctx is
	// cancelled. Events must be delivered in Sequence order when the
	// connector provides sequences.
	WatchEvents(ctx context.Context, tenantID string) (<-chan ChangeEvent, error)
}

// Validate checks a connector against the current contract: the
// descriptor must be well-formed, and the connector must actually
// implement what it declares (capability claims are verified by the
// contract test suite; here we only check static consistency). A
// connector that fails validation must not be wired into the service.
func Validate(c VersionedConnector) error {
	if c == nil {
		return errors.New("connector contract: nil connector")
	}
	d := c.Descriptor()
	if err := d.Validate(); err != nil {
		return err
	}
	if d.HasCapability(CapabilityDelta) {
		if _, ok := c.(EventSource); !ok {
			return &DescriptorError{Problems: []string{"connector declares delta capability but does not implement EventSource"}}
		}
	}
	if d.HasCapability(CapabilityTombstones) && !d.HasCapability(CapabilityDelta) {
		return &DescriptorError{Problems: []string{"tombstones require the delta capability"}}
	}
	if !d.HasCapability(CapabilityEffectivePermissions) && !d.FailClosedOutsideSubset {
		return &DescriptorError{Problems: []string{"a connector that cannot prove effective permissions must fail closed outside its subset"}}
	}
	return nil
}

// EventSourceOf returns the connector's EventSource when it declares
// delta capability, else nil.
func EventSourceOf(c VersionedConnector) EventSource {
	es, _ := c.(EventSource)
	return es
}

// adapter wraps an aclsync.Connector with an externally supplied
// descriptor, making it a VersionedConnector without touching the
// aclsync package (which must stay contract-free — the contract builds
// on aclsync, not vice versa). Used for connectors that cannot (or must
// not) import the contract package themselves.
type adapter struct {
	aclsync.Connector
	d ProviderDescriptor
}

// deltaAdapter additionally exposes the wrapped connector's event
// surface. Only this type satisfies EventSource, so Validate's
// delta⇒EventSource check stays honest for wrapped connectors.
type deltaAdapter struct {
	adapter
	es EventSource
}

func (a *deltaAdapter) WatchEvents(ctx context.Context, tenantID string) (<-chan ChangeEvent, error) {
	return a.es.WatchEvents(ctx, tenantID)
}

// WrapConnector adapts a plain aclsync.Connector into a
// VersionedConnector using the given descriptor. The caller owns the
// descriptor's correctness; Validate must pass before the connector is
// wired into the service.
func WrapConnector(c aclsync.Connector, d ProviderDescriptor) VersionedConnector {
	base := &adapter{Connector: c, d: d}
	if es, ok := c.(EventSource); ok {
		return &deltaAdapter{adapter: *base, es: es}
	}
	return base
}

func (a *adapter) Descriptor() ProviderDescriptor { return a.d }

// IsVersioned reports whether c implements the versioned contract.
func IsVersioned(c any) bool {
	_, ok := c.(VersionedConnector)
	return ok
}

// ProviderOf returns the connector's stable provider name, or "" when
// the connector is not versioned.
func ProviderOf(c any) string {
	if vc, ok := c.(VersionedConnector); ok {
		return vc.Descriptor().Provider
	}
	return ""
}

// SecretRefOK reports whether a deployment's credential reference is
// acceptable for the connector's auth spec. Plaintext env values are
// only acceptable when the spec explicitly allows the env scheme
// (dev/local); production deployments must use keyring or a secrets
// manager regardless.
func SecretRefOK(d ProviderDescriptor, ref string) bool {
	if !d.Auth.RequiresSecret() {
		return true
	}
	r := strings.TrimSpace(ref)
	switch {
	case strings.HasPrefix(r, string(SchemeKeyring)):
		return d.Auth.HasScheme(SchemeKeyring)
	case strings.HasPrefix(r, "secretsmanager://") || strings.HasPrefix(r, "aws:secretsmanager:") ||
		strings.HasPrefix(r, "gcp:secretmanager:") || strings.HasPrefix(r, "vault://"):
		return d.Auth.HasScheme(SchemeSecretsManager)
	case strings.HasPrefix(r, "env://") || !strings.Contains(r, "://"):
		return d.Auth.HasScheme(SchemeEnv)
	default:
		return false
	}
}
