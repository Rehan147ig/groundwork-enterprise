package spicedb

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTempPEM(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return p
}

func clearEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"SPICEDB_INSECURE_PLAINTEXT", "SPICEDB_TLS_CA",
		"SPICEDB_TLS_CERT", "SPICEDB_TLS_KEY", "SPICEDB_CA_FILE",
	} {
		t.Setenv(k, "")
	}
}

func TestEnvTLSOptionsPlaintext(t *testing.T) {
	clearEnv(t)
	t.Setenv("SPICEDB_INSECURE_PLAINTEXT", "true")
	opts, err := EnvTLSOptions()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(opts) != 1 {
		t.Fatalf("expected 1 option (WithInsecurePlaintext), got %d", len(opts))
	}
}

func TestEnvTLSOptionsEmptyUsesSystemRoots(t *testing.T) {
	clearEnv(t)
	opts, err := EnvTLSOptions()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(opts) != 0 {
		t.Fatalf("expected no options (system roots, TLS by default), got %d", len(opts))
	}
}

func TestEnvTLSOptionsFailClosedOnAmbiguity(t *testing.T) {
	clearEnv(t)
	t.Setenv("SPICEDB_INSECURE_PLAINTEXT", "true")
	t.Setenv("SPICEDB_TLS_CA", "ignored")
	if _, err := EnvTLSOptions(); err == nil {
		t.Fatal("expected error mixing plaintext with TLS paths")
	}

	clearEnv(t)
	t.Setenv("SPICEDB_TLS_CERT", writeTempPEM(t, "cert.pem", "cert"))
	if _, err := EnvTLSOptions(); err == nil {
		t.Fatal("expected error for cert without key")
	}

	clearEnv(t)
	t.Setenv("SPICEDB_TLS_KEY", writeTempPEM(t, "key.pem", "key"))
	if _, err := EnvTLSOptions(); err == nil {
		t.Fatal("expected error for key without cert")
	}

	clearEnv(t)
	t.Setenv("SPICEDB_TLS_CA", filepath.Join(t.TempDir(), "missing.pem"))
	if _, err := EnvTLSOptions(); err == nil || !strings.Contains(err.Error(), "SPICEDB_TLS_CA") {
		t.Fatalf("expected read error naming SPICEDB_TLS_CA, got %v", err)
	}
}

func TestEnvTLSOptionsTLSBundle(t *testing.T) {
	clearEnv(t)
	t.Setenv("SPICEDB_TLS_CA", writeTempPEM(t, "ca.pem", "ca"))
	t.Setenv("SPICEDB_TLS_CERT", writeTempPEM(t, "client.pem", "cert"))
	t.Setenv("SPICEDB_TLS_KEY", writeTempPEM(t, "client-key.pem", "key"))
	opts, err := EnvTLSOptions()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(opts) != 2 {
		t.Fatalf("expected WithCA + WithClientCert, got %d options", len(opts))
	}
}

func TestEnvOptionsLegacyCAFallback(t *testing.T) {
	clearEnv(t)
	t.Setenv("SPICEDB_CA_FILE", writeTempPEM(t, "legacy.pem", "ca"))
	opts, err := EnvOptions()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(opts) != 1 {
		t.Fatalf("expected legacy WithCA option, got %d", len(opts))
	}

	clearEnv(t)
	t.Setenv("SPICEDB_TLS_CA", writeTempPEM(t, "newca.pem", "ca"))
	t.Setenv("SPICEDB_CA_FILE", writeTempPEM(t, "legacy2.pem", "old"))
	opts, err = EnvOptions()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(opts) != 1 {
		t.Fatalf("expected exactly one WithCA (SPICEDB_TLS_CA wins), got %d", len(opts))
	}
}
