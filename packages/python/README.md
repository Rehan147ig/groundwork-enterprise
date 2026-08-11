# groundwork-sdk (Python)

Zero-dependency typed client for the Groundwork query runtime API. Mirrors
the TypeScript `@groundwork/sdk` surface: same endpoints, response
envelopes, and error semantics.

## Requirements

- Python >= 3.10 (stdlib only — no third-party dependencies)

## Usage

```python
from groundwork.client import GroundworkClient

client = GroundworkClient(
    base_url="http://127.0.0.1:18080",
    api_key="gw_local_acme_key",
    # user_assertion: str | Callable[[], str] | Awaitable — optional
)

agents = client.list_agents()          # {"agents": [...], "count": n}
agent = client.create_agent({...})     # {"agent": {...}}
run = client.simulate_action({...})    # {"simulation": {...}}
```

## Errors

All non-2xx responses and transport failures raise `GroundworkError` with
`status`, `code`, `detail`, and `headers`. Transport failures surface as
`code == "network"` (connection refused/DNS) or `code == "timeout"`.

## User assertions

`groundwork.assertion.mint_user_assertion(secret, sub, tenant_id,
roles=None, ttl=300)` produces an HS256-signed JWT compatible with
`mintUserAssertion` in the TypeScript SDK.

## Tests

```bash
python -m unittest discover -s test -v    # unit tests (no server needed)
python test/smoke.py                      # live smoke (demo runtime on :18080)
```
