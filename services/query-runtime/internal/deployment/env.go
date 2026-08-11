package deployment

import (
	"os"
	"strconv"
	"strings"
)

// ConfigFromEnvironment builds a DeploymentConfig from the deployment
// environment. It is the trusted input to Validate at startup. Only
// deployment configuration envs are read here; runtime behavior envs
// (OIDC, keys, outbox, ...) are left to their owners.
//
//	GROUNDWORK_DEPLOYMENT_REGION      required in production: this deployment's region
//	GROUNDWORK_JURISDICTION           optional: overrides the region's default jurisdiction
//	GROUNDWORK_POSTGRES_REGION        optional: component regions (default: co-located)
//	GROUNDWORK_SPICEDB_REGION
//	GROUNDWORK_QDRANT_REGION
//	GROUNDWORK_ELASTICSEARCH_REGION
//	GROUNDWORK_BACKUP_REGION
//	GROUNDWORK_TELEMETRY_REGION
//	GROUNDWORK_KMS_REGION
//	GROUNDWORK_MODEL_ENDPOINT_REGION
//	GROUNDWORK_TRANSFER_POLICIES      optional: kind:from:to,kind:from:to (explicit consent)
//	GROUNDWORK_EGRESS_ALLOWLIST       optional: comma-separated hostnames (default-deny egress)
//	GROUNDWORK_BACKUP_ENABLED         optional: "true" provisions regional backups
//	GATEWAY_HTTP_PORT                 optional: presence marks the gateway public (sole ingress)
//	GROUNDWORK_POSTGRES_EXPOSED       optional: "true" (or a port) marks a backend exposed —
//	GROUNDWORK_SPICEDB_EXPOSED          publish only for debugging; production validation
//	GROUNDWORK_QDRANT_EXPOSED          reports it as a problem.
//	GROUNDWORK_ES_EXPOSED
//	GROUNDWORK_MINIO_EXPOSED
//	DATABASE_URL                      marks audit storage as configured
func ConfigFromEnvironment() DeploymentConfig {
	cfg := DeploymentConfig{
		DeploymentRegion:       strings.TrimSpace(os.Getenv("GROUNDWORK_DEPLOYMENT_REGION")),
		Jurisdiction:           strings.TrimSpace(os.Getenv("GROUNDWORK_JURISDICTION")),
		PostgresRegion:         strings.TrimSpace(os.Getenv("GROUNDWORK_POSTGRES_REGION")),
		SpiceDBRegion:          strings.TrimSpace(os.Getenv("GROUNDWORK_SPICEDB_REGION")),
		QdrantRegion:           strings.TrimSpace(os.Getenv("GROUNDWORK_QDRANT_REGION")),
		ElasticsearchRegion:    strings.TrimSpace(os.Getenv("GROUNDWORK_ELASTICSEARCH_REGION")),
		BackupRegion:           strings.TrimSpace(os.Getenv("GROUNDWORK_BACKUP_REGION")),
		TelemetryRegion:        strings.TrimSpace(os.Getenv("GROUNDWORK_TELEMETRY_REGION")),
		KMSRegion:              strings.TrimSpace(os.Getenv("GROUNDWORK_KMS_REGION")),
		ModelEndpointRegion:    strings.TrimSpace(os.Getenv("GROUNDWORK_MODEL_ENDPOINT_REGION")),
		TransferPolicies:       ParseTransferPolicies(os.Getenv("GROUNDWORK_TRANSFER_POLICIES")),
		EgressAllowlist:        splitEnvList(os.Getenv("GROUNDWORK_EGRESS_ALLOWLIST")),
		AuditStorageConfigured: strings.TrimSpace(os.Getenv("DATABASE_URL")) != "",
		BackupEnabled:          os.Getenv("GROUNDWORK_BACKUP_ENABLED") == "true",
	}

	// Sole public ingress: the gateway, only when a port is configured.
	if p := strings.TrimSpace(os.Getenv("GATEWAY_HTTP_PORT")); p != "" {
		if port, err := strconv.Atoi(p); err == nil {
			cfg.Gateway = GatewayEndpoint{Enabled: true, Ports: []int{port}, Region: cfg.DeploymentRegion}
		}
	}

	// Backends: private by default; an explicit _EXPOSED flag is a
	// debugging escape hatch that production validation rejects.
	cfg.Services = []ServiceEndpoint{
		{Name: "gateway", Port: firstInt(cfg.Gateway.Ports, 80), Public: cfg.Gateway.Enabled, Region: cfg.DeploymentRegion, Exposed: cfg.Gateway.Enabled},
		{Name: "postgres", Port: 5432, Region: cfg.PostgresRegion, Exposed: exposedEnv("GROUNDWORK_POSTGRES_EXPOSED")},
		{Name: "spicedb", Port: 50051, Region: cfg.SpiceDBRegion, Exposed: exposedEnv("GROUNDWORK_SPICEDB_EXPOSED")},
		{Name: "qdrant", Port: 6333, Region: cfg.QdrantRegion, Exposed: exposedEnv("GROUNDWORK_QDRANT_EXPOSED")},
		{Name: "elasticsearch", Port: 9200, Region: cfg.ElasticsearchRegion, Exposed: exposedEnv("GROUNDWORK_ES_EXPOSED")},
		{Name: "minio", Port: 9000, Region: cfg.DeploymentRegion, Exposed: exposedEnv("GROUNDWORK_MINIO_EXPOSED")},
	}
	return cfg
}

// ParseTransferPolicies parses a comma-separated "kind:from:to" policy
// spec into explicit consent policies. Unknown kinds or malformed
// entries are rejected — a typo must not silently permit a transfer.
func ParseTransferPolicies(spec string) []TransferPolicy {
	var policies []TransferPolicy
	for _, entry := range strings.Split(spec, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		parts := strings.Split(entry, ":")
		if len(parts) != 3 {
			// Malformed entries are ignored by construction: a
			// malformed policy must not grant anything. The caller can
			// not observe this from Validate, so it also reports the
			// raw spec presence via deployment validation logs.
			continue
		}
		kind, from, to := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]), strings.TrimSpace(parts[2])
		if !KnownTransferKinds[kind] {
			continue
		}
		if from == "" || to == "" {
			continue
		}
		policies = append(policies, TransferPolicy{
			Kind:    kind,
			From:    from,
			To:      to,
			Allowed: true,
			Notes:   "configured via GROUNDWORK_TRANSFER_POLICIES",
		})
	}
	return policies
}

func exposedEnv(key string) bool {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return false
	}
	if b, err := strconv.ParseBool(v); err == nil {
		return b
	}
	// A port number also counts as exposed.
	_, err := strconv.Atoi(v)
	return err == nil
}

func firstInt(values []int, fallback int) int {
	if len(values) > 0 {
		return values[0]
	}
	return fallback
}

// splitEnvList splits a comma/space separated env list.
func splitEnvList(v string) []string {
	var out []string
	for _, item := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' || r == ';' }) {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}
