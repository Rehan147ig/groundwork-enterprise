package spicedb

import (
	"fmt"
	"os"
)

// Transport configuration for a SpiceDB connection, read from the
// gateway environment once at startup:
//
//	SPICEDB_INSECURE_PLAINTEXT=true  dev/test only — no TLS
//	SPICEDB_TLS_CA=<path>            PEM bundle pinning the gRPC trust
//	                                anchor to an internal CA
//	SPICEDB_TLS_CERT=<path>          mTLS client certificate (must be
//	SPICEDB_TLS_KEY=<path>           paired with its private key)
//
// Fail-closed by design: ambiguous mixes (plaintext alongside TLS
// paths, or a certificate without its key) return an error instead of
// silently downgrading the transport. With no variables set the client
// dials TLS by default with the system roots.
func EnvTLSOptions() ([]Option, error) {
	plain := os.Getenv("SPICEDB_INSECURE_PLAINTEXT") == "true"
	caFile := os.Getenv("SPICEDB_TLS_CA")
	certFile := os.Getenv("SPICEDB_TLS_CERT")
	keyFile := os.Getenv("SPICEDB_TLS_KEY")

	if plain && (caFile != "" || certFile != "" || keyFile != "") {
		return nil, fmt.Errorf(
			"SPICEDB_INSECURE_PLAINTEXT=true cannot be combined with SPICEDB_TLS_CA/SPICEDB_TLS_CERT/SPICEDB_TLS_KEY",
		)
	}
	if (certFile != "") != (keyFile != "") {
		return nil, fmt.Errorf("SPICEDB_TLS_CERT and SPICEDB_TLS_KEY must be set together")
	}

	var opts []Option
	if plain {
		return append(opts, WithInsecurePlaintext()), nil
	}
	if caFile != "" {
		caPEM, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("SPICEDB_TLS_CA: %w", err)
		}
		opts = append(opts, WithCA(caPEM))
	}
	if certFile != "" {
		certPEM, err := os.ReadFile(certFile)
		if err != nil {
			return nil, fmt.Errorf("SPICEDB_TLS_CERT: %w", err)
		}
		keyPEM, err := os.ReadFile(keyFile)
		if err != nil {
			return nil, fmt.Errorf("SPICEDB_TLS_KEY: %w", err)
		}
		opts = append(opts, WithClientCert(certPEM, keyPEM))
	}
	return opts, nil
}

// EnvOptions is EnvTLSOptions plus the legacy SPICEDB_CA_FILE fallback
// kept for existing deployments (SPICEDB_TLS_CA takes precedence).
func EnvOptions() ([]Option, error) {
	opts, err := EnvTLSOptions()
	if err != nil {
		return nil, err
	}
	if os.Getenv("SPICEDB_TLS_CA") == "" {
		if caFile := os.Getenv("SPICEDB_CA_FILE"); caFile != "" {
			caPEM, err := os.ReadFile(caFile)
			if err != nil {
				return nil, fmt.Errorf("SPICEDB_CA_FILE: %w", err)
			}
			opts = append(opts, WithCA(caPEM))
		}
	}
	return opts, nil
}
