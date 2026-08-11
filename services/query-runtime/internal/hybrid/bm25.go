// Package hybrid implements the unified hybrid retrieval pipeline
// (dense vector + BM25 lexical with security filters pushed into the
// query planner), replacing the dual-write Qdrant + Elasticsearch
// architecture with a single fused retrieval stage.
//
// LexicalIndex is an in-memory BM25 index: chunks are indexed by
// tenant, and every search applies tenant/region/scope security filters
// before scoring. HybridRetriever fuses dense candidates with lexical
// hits using Reciprocal Rank Fusion so a single, drift-free index
// serves the engine.
package hybrid

import (
	"context"
	"math"
	"strings"
	"sync"
	"unicode"
)

// IndexedChunk is a chunk stored in the lexical index with the
// metadata the engine needs to build a Candidate.
type IndexedChunk struct {
	TenantID    string
	Region      string
	DocumentID  string
	ChunkID     string
	ChunkHash   string
	Page        int
	Offset      int
	Text        string
	Scope       string
	OwnerTags   []string
	Freshness   float64
	SoftDeleted bool
}

// Hit is one BM25 match.
type Hit struct {
	Chunk IndexedChunk
	Score float64
}

// tokenize lowercases and splits on non-alphanumeric runes, dropping
// one- and two-character noise tokens.
func tokenize(text string) []string {
	fields := strings.FieldsFunc(strings.ToLower(text), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	})
	out := fields[:0]
	for _, f := range fields {
		if len(f) >= 3 {
			out = append(out, f)
		}
	}
	return out
}

// bm25Params follow the standard k1/b smoothing defaults.
const (
	k1  = 1.2
	b   = 0.75
	eps = 1e-6
)

type postings struct {
	docs map[string]int // docID -> term frequency
	df   int
	idf  float64
}

type docRecord struct {
	chunk  IndexedChunk
	length int
	terms  map[string]int
}

type tenantIndex struct {
	docs     map[string]docRecord // chunkID -> record
	postings map[string]*postings
	totalLen int
}

// LexicalIndex is the BM25 store. Thread-safe; chunk writes are
// idempotent (re-indexing the same chunkID replaces the record).
type LexicalIndex struct {
	mu      sync.RWMutex
	tenants map[string]*tenantIndex
}

// NewLexicalIndex builds an empty index.
func NewLexicalIndex() *LexicalIndex {
	return &LexicalIndex{tenants: map[string]*tenantIndex{}}
}

// Index inserts or replaces one chunk in the tenant's index.
func (ix *LexicalIndex) Index(chunk IndexedChunk) {
	if chunk.TenantID == "" || chunk.ChunkID == "" {
		return
	}
	ix.mu.Lock()
	defer ix.mu.Unlock()
	t := ix.tenants[chunk.TenantID]
	if t == nil {
		t = &tenantIndex{
			docs:     map[string]docRecord{},
			postings: map[string]*postings{},
		}
		ix.tenants[chunk.TenantID] = t
	}
	if old, exists := t.docs[chunk.ChunkID]; exists {
		ix.removeLocked(t, old)
	}
	terms := map[string]int{}
	for _, term := range tokenize(chunk.Text) {
		terms[term]++
	}
	length := 0
	for term, tf := range terms {
		length += tf
		p := t.postings[term]
		if p == nil {
			p = &postings{docs: map[string]int{}}
			t.postings[term] = p
		}
		if p.docs[chunk.ChunkID] == 0 {
			p.df++
		}
		p.docs[chunk.ChunkID] = tf
	}
	t.totalLen += length
	t.docs[chunk.ChunkID] = docRecord{chunk: chunk, length: length, terms: terms}
	ix.recomputeIDF(t)
}

// Delete removes a chunk from the tenant's index.
func (ix *LexicalIndex) Delete(tenantID, chunkID string) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	t := ix.tenants[tenantID]
	if t == nil {
		return
	}
	if rec, exists := t.docs[chunkID]; exists {
		ix.removeLocked(t, rec)
	}
}

func (ix *LexicalIndex) removeLocked(t *tenantIndex, rec docRecord) {
	for term := range rec.terms {
		p := t.postings[term]
		if p == nil {
			continue
		}
		delete(p.docs, rec.chunk.ChunkID)
		if p.docs[rec.chunk.ChunkID] == 0 {
			p.df--
		}
		if p.df == 0 {
			delete(t.postings, term)
		}
	}
	t.totalLen -= rec.length
	delete(t.docs, rec.chunk.ChunkID)
	ix.recomputeIDF(t)
}

func (ix *LexicalIndex) recomputeIDF(t *tenantIndex) {
	n := len(t.docs)
	for _, p := range t.postings {
		p.idf = math.Log(1 + (float64(n)-float64(p.df)+0.5)/(float64(p.df)+0.5))
	}
}

// Filters are the security constraints pushed into the query planner.
type Filters struct {
	// Region, when set, restricts hits to one region (required: the
	// engine never serves cross-region content).
	Region string
	// Scopes, when set, restricts hits to chunks whose scope is listed.
	Scopes []string
	// IncludeDeleted allows soft-deleted chunks (drift reports only).
	IncludeDeleted bool
}

// Search returns the top `limit` BM25 hits for the tenant's index,
// applying the security filters before scoring.
func (ix *LexicalIndex) Search(ctx context.Context, tenantID, query string, limit int, filters Filters) ([]Hit, error) {
	terms := tokenize(query)
	if len(terms) == 0 {
		return nil, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ix.mu.RLock()
	t := ix.tenants[tenantID]
	if t == nil {
		ix.mu.RUnlock()
		return nil, nil
	}
	avgdl := float64(1)
	if len(t.docs) > 0 {
		avgdl = float64(t.totalLen) / float64(len(t.docs))
	}
	scores := map[string]float64{}
	for _, term := range terms {
		p := t.postings[term]
		if p == nil {
			continue
		}
		for chunkID, tf := range p.docs {
			rec := t.docs[chunkID]
			if !filterPasses(rec.chunk, filters) {
				continue
			}
			denom := float64(tf) + k1*(1-b+b*float64(rec.length)/avgdl)
			scores[chunkID] += p.idf * (float64(tf) * (k1 + 1)) / (denom + eps)
		}
	}
	ix.mu.RUnlock()
	if len(scores) == 0 {
		return nil, nil
	}
	ids := make([]string, 0, len(scores))
	for id := range scores {
		ids = append(ids, id)
	}
	// Simple insertion sort for small sets (the index is per-tenant and
	// bounded); stable across runs.
	for i := 1; i < len(ids); i++ {
		for j := i; j > 0 && scores[ids[j-1]] < scores[ids[j]]; j-- {
			ids[j-1], ids[j] = ids[j], ids[j-1]
		}
	}
	ix.mu.RLock()
	defer ix.mu.RUnlock()
	out := make([]Hit, 0, min(limit, len(ids)))
	for _, id := range ids[:min(limit, len(ids))] {
		out = append(out, Hit{Chunk: t.docs[id].chunk, Score: scores[id]})
	}
	return out, nil
}

// DocCount reports how many chunks the tenant has indexed.
func (ix *LexicalIndex) DocCount(tenantID string) int {
	ix.mu.RLock()
	defer ix.mu.RUnlock()
	if t := ix.tenants[tenantID]; t != nil {
		return len(t.docs)
	}
	return 0
}

func filterPasses(chunk IndexedChunk, filters Filters) bool {
	if chunk.SoftDeleted && !filters.IncludeDeleted {
		return false
	}
	if filters.Region != "" && chunk.Region != filters.Region {
		return false
	}
	if len(filters.Scopes) > 0 && !containsString(filters.Scopes, chunk.Scope) {
		return false
	}
	return true
}

func containsString(list []string, value string) bool {
	for _, item := range list {
		if item == value {
			return true
		}
	}
	return false
}
