package engine

import (
	"os"
	"strconv"
	"time"
)

type TimeoutConfig struct {
	Total        time.Duration
	Embedding    time.Duration
	QdrantSearch time.Duration
	ACLCheck     time.Duration
	AuditWrite   time.Duration
}

func DefaultTimeoutConfig() TimeoutConfig {
	return TimeoutConfig{
		Total:        15 * time.Second,
		Embedding:    15 * time.Second,
		QdrantSearch: 15 * time.Second,
		ACLCheck:     60 * time.Millisecond,
		AuditWrite:   30 * time.Millisecond,
	}
}

func TimeoutConfigFromEnv() TimeoutConfig {
	defaults := DefaultTimeoutConfig()
	return TimeoutConfig{
		Total:        envDuration("BACKEND_HTTP_TIMEOUT_MS", defaults.Total),
		Embedding:    envDuration("EMBEDDING_TIMEOUT_MS", defaults.Embedding),
		QdrantSearch: envDuration("QDRANT_TIMEOUT_MS", defaults.QdrantSearch),
		ACLCheck:     envDuration("RELATIONSHIP_TIMEOUT_MS", defaults.ACLCheck),
		AuditWrite:   envDuration("AUDIT_TIMEOUT_MS", defaults.AuditWrite),
	}
}

func (c TimeoutConfig) WithDefaults() TimeoutConfig {
	defaults := DefaultTimeoutConfig()
	if c.Total <= 0 {
		c.Total = defaults.Total
	}
	if c.Embedding <= 0 {
		c.Embedding = defaults.Embedding
	}
	if c.QdrantSearch <= 0 {
		c.QdrantSearch = defaults.QdrantSearch
	}
	if c.ACLCheck <= 0 {
		c.ACLCheck = defaults.ACLCheck
	}
	if c.AuditWrite <= 0 {
		c.AuditWrite = defaults.AuditWrite
	}
	return c
}

func envDuration(key string, fallback time.Duration) time.Duration {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil || parsed <= 0 {
		return fallback
	}
	return time.Duration(parsed) * time.Millisecond
}
