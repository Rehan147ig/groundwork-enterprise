"""Dify custom node: Groundwork security node.

This module implements a Dify‑compatible node that can be dropped into a
workflow.  It receives a payload with the fields ``groundwork_endpoint``,
``api_key``, ``user_id`` and ``query``, calls ``POST /v1/query`` against the
Groundwork runtime and returns a ``documents`` list containing the filtered
context.

The node follows Dify's custom extension specification (``manifest.json``
plus a ``node.py`` that implements an ``execute`` function).
"""

import json
import urllib.request
import urllib.error


def execute(payload: dict) -> dict:
    """Run a Groundwork query and return filtered context.

    Parameters
    ----------
    payload : dict
        Expected keys:
        - ``groundwork_endpoint`` (str): runtime base URL, e.g.
          ``https://runtime.example.com``.
        - ``api_key`` (str): Groundwork API key / Entra ID token.
        - ``user_id`` (str): identity of the requesting user or agent.
        - ``query`` (str): natural‑language query to submit.

    Returns
    -------
    dict
        A Dify‑compatible output dict with a ``documents`` key.

        ``{"documents": [
            {"id": "<chunk_id>", "text": "<chunk_text>", "metadata": {...}},
            …
        ]}``

        If the request fails the function returns ``{"documents": [], "error":
        "<message>"}``.
    """
    # -------------------------------------------------------------------------
    # Extract required fields from the payload; gracefully handle missing data.
    # -------------------------------------------------------------------------
    endpoint = payload.get("groundwork_endpoint", "").rstrip("/")
    api_key = payload.get("api_key", "")
    user_id = payload.get("user_id", "")
    query = payload.get("query", "")

    if not all([endpoint, api_key, user_id, query]):
        return {"documents": [], "error": "missing required parameters"}

    # -------------------------------------------------------------------------
    # Build the Groundwork query payload and issue the HTTP POST.
    # -------------------------------------------------------------------------
    body = json.dumps(
        {
            "user_id": user_id,
            "question": query,
            "top_k": 10,
        }
    ).encode("utf-8")

    url = f"{endpoint}/v1/query"
    req = urllib.request.Request(
        url,
        data=body,
        headers={
            "Content-Type": "application/json",
            "X-Groundwork-API-Key": api_key,
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req) as response:
            raw = response.read().decode("utf-8")
            data = json.loads(raw)
    except urllib.error.HTTPError as http_err:
        # 403, 5xx etc – return empty docs and an error string
        return {
            "documents": [],
            "error": f"Groundwork request failed: {http_err.code} {http_err.reason}",
        }
    except Exception as exc:
        return {"documents": [], "error": f"Unexpected error: {exc}"}

    # -------------------------------------------------------------------------
    # Normalise the runtime response into a list of Document‑like dicts.
    # -------------------------------------------------------------------------
    citations = data.get("citations", [])
    documents = []
    for c in citations:
        doc = {
            "id": c.get("chunk_id", ""),
            "text": c.get("text", ""),
            "metadata": {
                "score": c.get("score"),
                "digest": c.get("chunk_hash"),
                "doc_id": c.get("document_id"),
                "page": c.get("page"),
                "offset": c.get("offset"),
                "freshness_score": c.get("freshness_score"),
                "watermark": c.get("watermark"),
            },
        }
        documents.append(doc)

    return {"documents": documents}