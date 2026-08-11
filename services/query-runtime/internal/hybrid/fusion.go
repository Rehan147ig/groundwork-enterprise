package hybrid

import (
	"context"

	"groundwork/query-runtime/internal/runtime"
)

// DenseRetriever is the vector stage of the hybrid pipeline
// (implemented by runtime.QdrantVectorSearcher).
type DenseRetriever interface {
	Retrieve(ctx context.Context, req runtime.QueryRequest, limit int) ([]runtime.Candidate, error)
}

// VectorAdapter adapts a runtime.VectorSearcher (SearchVector) to the
// hybrid pipeline's Retrieve contract.
type VectorAdapter struct {
	Searcher runtime.VectorSearcher
}

func (v VectorAdapter) Retrieve(ctx context.Context, req runtime.QueryRequest, limit int) ([]runtime.Candidate, error) {
	return v.Searcher.SearchVector(ctx, req, limit)
}

var _ DenseRetriever = VectorAdapter{}

// HybridRetriever fuses dense vector candidates with lexical BM25 hits
// via Reciprocal Rank Fusion. It is a drop-in engine.RetrievalClient:
// the engine's tenant/region ACL pass still runs afterwards, so the
// hybrid stage never weakens the security boundary — it only adds
// lexical recall and a single fused ranking.
type HybridRetriever struct {
	Dense   DenseRetriever
	Lexical *LexicalIndex

	// DenseLimit is how many dense candidates are pulled per query.
	DenseLimit int
	// LexicalLimit is how many lexical hits are pulled per query.
	LexicalLimit int
	// RRFK is the RRF smoothing constant (default 60).
	RRFK int

	// MaxCandidates caps the fused result set returned to the engine.
	MaxCandidates int

	// OnFusion, when set, is invoked with (dense, lexical, fused)
	// counts after every retrieve (metrics).
	OnFusion func(dense, lexical, fused int)
}

// NewHybridRetriever builds a fused retriever with sensible limits.
func NewHybridRetriever(dense DenseRetriever, lexical *LexicalIndex) *HybridRetriever {
	return &HybridRetriever{
		Dense:         dense,
		Lexical:       lexical,
		DenseLimit:    50,
		LexicalLimit:  50,
		RRFK:          60,
		MaxCandidates: 50,
	}
}

// Retrieve runs both stages and fuses the results with RRF. The
// lexical stage pushes the tenant + region + scope filters into the
// query before scoring; dense results are merged and de-duplicated by
// chunk id.
func (h *HybridRetriever) Retrieve(ctx context.Context, req runtime.QueryRequest, limit int) ([]runtime.Candidate, error) {
	if h.Dense == nil || h.Lexical == nil {
		return nil, nil // caller fails closed when a backend is missing
	}
	denseLimit := h.DenseLimit
	if denseLimit <= 0 {
		denseLimit = limit
	}
	type denseResult struct {
		candidates []runtime.Candidate
		err        error
	}
	denseCh := make(chan denseResult, 1)
	go func() {
		candidates, err := h.Dense.Retrieve(ctx, req, denseLimit)
		denseCh <- denseResult{candidates: candidates, err: err}
	}()

	filters := Filters{Region: req.Region, Scopes: req.SourceScopes}
	lexicalCh := make(chan []Hit, 1)
	go func() {
		hits, err := h.Lexical.Search(ctx, req.TenantID, req.Question, h.LexicalLimit, filters)
		if err != nil {
			lexicalCh <- nil
			return
		}
		lexicalCh <- hits
	}()

	dense := <-denseCh
	if dense.err != nil {
		return nil, dense.err
	}
	lexical := <-lexicalCh
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	fused := h.fuse(dense.candidates, lexical, limit)
	if h.OnFusion != nil {
		h.OnFusion(len(dense.candidates), len(lexical), len(fused))
	}
	return fused, nil
}

// IndexingRetriever wraps a dense retriever and mirrors every
// retrieved candidate into the lexical index (idempotent by chunk id),
// so the hybrid pipeline is self-populating: chunks the system has
// ever retrieved become lexically searchable without a separate
// indexing job or dual-write sync.
type IndexingRetriever struct {
	Dense DenseRetriever
	Index *LexicalIndex
}

// Retrieve pulls dense candidates and indexes them before returning.
func (i *IndexingRetriever) Retrieve(ctx context.Context, req runtime.QueryRequest, limit int) ([]runtime.Candidate, error) {
	candidates, err := i.Dense.Retrieve(ctx, req, limit)
	if err != nil {
		return nil, err
	}
	if i.Index != nil {
		for _, c := range candidates {
			i.Index.Index(IndexedChunk{
				TenantID:    c.Chunk.TenantID,
				Region:      c.Chunk.Region,
				DocumentID:  c.Chunk.DocumentID,
				ChunkID:     c.Chunk.ChunkID,
				ChunkHash:   c.Chunk.ChunkHash,
				Page:        c.Chunk.Page,
				Offset:      c.Chunk.Offset,
				Text:        c.Chunk.Text,
				Scope:       c.Chunk.RequiredScope,
				OwnerTags:   c.Chunk.OwnerACLTags,
				Freshness:   c.Chunk.FreshnessScore,
				SoftDeleted: c.Chunk.SoftDeleted,
			})
		}
	}
	return candidates, nil
}

var _ DenseRetriever = (*IndexingRetriever)(nil)

// fuse merges dense candidates and lexical hits with RRF and returns
// the top `limit` results as engine candidates.
func (h *HybridRetriever) fuse(dense []runtime.Candidate, lexical []Hit, limit int) []runtime.Candidate {
	k := h.RRFK
	if k <= 0 {
		k = 60
	}
	rrf := map[string]float64{}
	byID := map[string]runtime.Candidate{}
	rank := 1
	for _, c := range dense {
		id := c.Chunk.ChunkID
		if id == "" {
			id = c.Chunk.DocumentID
		}
		rrf[id] += 1.0 / (float64(k) + float64(rank))
		if _, exists := byID[id]; !exists {
			byID[id] = c
		}
		rank++
	}
	rank = 1
	for _, hit := range lexical {
		id := hit.Chunk.ChunkID
		rrf[id] += 1.0 / (float64(k) + float64(rank))
		if _, exists := byID[id]; !exists {
			byID[id] = runtime.Candidate{
				Chunk: runtime.Chunk{
					TenantID:       hit.Chunk.TenantID,
					Region:         hit.Chunk.Region,
					DocumentID:     hit.Chunk.DocumentID,
					ChunkID:        hit.Chunk.ChunkID,
					ChunkHash:      hit.Chunk.ChunkHash,
					Page:           hit.Chunk.Page,
					Offset:         hit.Chunk.Offset,
					Text:           hit.Chunk.Text,
					RequiredScope:  hit.Chunk.Scope,
					OwnerACLTags:   hit.Chunk.OwnerTags,
					FreshnessScore: hit.Chunk.Freshness,
				},
			}
		}
		rank++
	}
	if len(rrf) == 0 {
		return nil
	}
	ids := make([]string, 0, len(rrf))
	for id := range rrf {
		ids = append(ids, id)
	}
	for i := 1; i < len(ids); i++ {
		for j := i; j > 0 && rrf[ids[j-1]] < rrf[ids[j]]; j-- {
			ids[j-1], ids[j] = ids[j], ids[j-1]
		}
	}
	maxOut := limit
	if h.MaxCandidates > 0 && h.MaxCandidates < maxOut {
		maxOut = h.MaxCandidates
	}
	out := make([]runtime.Candidate, 0, min(maxOut, len(ids)))
	for _, id := range ids[:min(maxOut, len(ids))] {
		c := byID[id]
		c.Score = rrf[id]
		out = append(out, c)
	}
	return out
}
