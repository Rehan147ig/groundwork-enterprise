package connectors

import (
	"context"
	"time"

	gwmetrics "groundwork/query-runtime/internal/metrics"
)

// CredentialExpiryReport is one connector's credential expiry datum
// (Phase 8.5). SecretRef is the reference (keyring://<purpose> or
// env://<NAME>) — never material. Zero Expiry means the reference
// carries no expiry metadata.
type CredentialExpiryReport struct {
	TenantID    string
	ConnectorID string
	SecretRef   string
	Expiry      time.Time
}

// CredentialExpiryScanner publishes the connector credential
// days-until-expiry gauges for every registered connector on a
// cadence (Phase 8.5). It is observability-only: never fails startup,
// never fails closed, and never touches secret material — it dates the
// reference, not the secret.
type CredentialExpiryScanner struct {
	store   Store
	secrets SecretResolver
}

// NewCredentialExpiryScanner wires the monitor over the registry and
// the secret resolver (the same resolver the gateway uses to dispatch).
func NewCredentialExpiryScanner(store Store, secrets SecretResolver) *CredentialExpiryScanner {
	return &CredentialExpiryScanner{store: store, secrets: secrets}
}

// Refresh scans every connector across tenants, dates each secret
// reference, publishes the gauges, and returns the reports (for tests).
// A store failure aborts the scan (the gauges keep their last values);
// an individual reference that cannot be dated reports zero and never
// aborts the scan. Connectors without a secret reference are skipped.
func (s *CredentialExpiryScanner) Refresh(ctx context.Context) ([]CredentialExpiryReport, error) {
	conns, err := s.store.ListAllConnectors(ctx)
	if err != nil {
		return nil, err
	}
	reports := make([]CredentialExpiryReport, 0, len(conns))
	for _, c := range conns {
		if c.SecretRef == "" {
			continue
		}
		report := CredentialExpiryReport{
			TenantID:    c.TenantID,
			ConnectorID: c.ID,
			SecretRef:   c.SecretRef,
			Expiry:      s.secrets.Expiry(ctx, c.TenantID, c.SecretRef),
		}
		gwmetrics.SetConnectorCredentialExpiryMetrics(report.TenantID, report.ConnectorID, report.SecretRef, report.Expiry)
		reports = append(reports, report)
	}
	return reports, nil
}
