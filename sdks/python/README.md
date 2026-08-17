# Groundwork Python SDK

Official Python SDK for [Groundwork](https://github.com/groundwork/groundwork):
zero-trust access control for AI agents with a tamper-evident audit chain.

```bash
pip install groundwork-python                # core client
pip install 'groundwork-python[langchain]'   # + LangChain retriever
```

## Usage

```python
from groundwork import GroundworkClient

with GroundworkClient("http://localhost:8080", "gw_local_acme_key") as gw:
    result = gw.query("alice", "what is the FY26 budget?")
    print(result.answer, result.immutable_digest)

    report = gw.leak_report()         # requires audit scope
    status = gw.verify_audit()        # hash-chain verification
```

## LangChain retriever

```python
from groundwork import GroundworkClient
from groundwork.integrations.langchain import GroundworkRetriever

retriever = GroundworkRetriever(
    client=GroundworkClient("http://localhost:8080", "gw_local_acme_key"),
    user_id="alice",
    top_k=5,
)
docs = retriever.get_relevant_documents("budget variance")
# each doc: page_content=chunk text, metadata has doc_id, score,
# immutable_digest (chunk hash bound into the audit chain)
```

## Errors

- `PermissionDeniedError` — runtime refused the identity (403)
- `FailClosedError` — runtime could not answer safely (500)
- Retries are automatic for 429/502/503/504 and transport errors with
  exponential backoff + jitter.

## Development

```bash
pip install -e '.[dev,langchain]'
pytest --cov=groundwork --cov-report=term-missing
```