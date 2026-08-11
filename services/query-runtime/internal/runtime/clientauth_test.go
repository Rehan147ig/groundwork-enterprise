package runtime

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// The Qdrant client sends the "api-key" header when APIKey is set.
func TestQdrantSendsAPIKey(t *testing.T) {
	embed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"embedding": []float32{0.1, 0.2, 0.3}})
	}))
	defer embed.Close()

	var mu sync.Mutex
	var gotKey string
	qd := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotKey = r.Header.Get("api-key")
		mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"result": []any{}})
	}))
	defer qd.Close()

	q := QdrantVectorSearcher{
		Endpoint: qd.URL, Collection: "c", Client: qd.Client(),
		EmbeddingURL: embed.URL, EmbeddingTimeout: time.Second, APIKey: "qd-key",
	}
	if _, err := q.SearchVector(context.Background(), QueryRequest{TenantID: "t1", Question: "q"}, 5); err != nil {
		t.Fatalf("search: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if gotKey != "qd-key" {
		t.Fatalf("expected Qdrant request to carry the api-key header, got %q", gotKey)
	}
}
