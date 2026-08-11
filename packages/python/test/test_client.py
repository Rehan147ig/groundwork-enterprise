"""Unit tests mirroring packages/typescript/test/client.test.mjs.

Run with:  python -m unittest test.test_client -v   (or: python -m unittest discover)
"""

import base64
import hashlib
import hmac
import json
import time
import unittest

from groundwork.client import GroundworkClient
from groundwork.errors import GroundworkError
from groundwork.assertion import mint_user_assertion


def stub_transport(status, body, extra_headers=None):
    headers = {"content-type": "application/json"}
    headers.update(extra_headers or {})
    payload = json.dumps(body).encode("utf-8")

    def transport(method, url, req_headers, body_bytes, timeout_ms):
        return status, dict(headers), payload

    return transport


class TestClientUnit(unittest.TestCase):
    def test_sends_api_key_header_and_parses_agents_list_with_count(self):
        seen = {}

        def transport(method, url, headers, body_bytes, timeout_ms):
            seen["headers"] = headers
            return (
                200,
                {"content-type": "application/json"},
                json.dumps({"agents": [], "count": 0}).encode("utf-8"),
            )

        client = GroundworkClient(base_url="http://localhost:8080", api_key="gw_test_key", transport=transport)
        result = client.list_agents()
        self.assertEqual(result["count"], 0)
        self.assertEqual(result["agents"], [])
        self.assertEqual(seen["headers"]["X-Groundwork-API-Key"], "gw_test_key")

    def test_sends_user_assertion_when_provided_as_provider(self):
        seen = {}

        def transport(method, url, headers, body_bytes, timeout_ms):
            seen["headers"] = headers
            return (
                201,
                {"content-type": "application/json"},
                json.dumps({"agent": {}}).encode("utf-8"),
            )

        client = GroundworkClient(
            base_url="http://localhost:8080",
            api_key="gw_test_key",
            assertion=lambda: "assertion-token-123",
            transport=transport,
        )
        client.create_agent({"name": "research-agent", "business_purpose": "read-only research"})
        self.assertEqual(seen["headers"]["X-Groundwork-User-Assertion"], "assertion-token-123")
        self.assertEqual(seen["headers"]["Content-Type"], "application/json")

    def test_posts_json_body_with_query_endpoint(self):
        seen = {}

        def transport(method, url, headers, body_bytes, timeout_ms):
            seen["body"] = json.loads(body_bytes.decode("utf-8"))
            return (
                200,
                {"content-type": "application/json"},
                json.dumps({"answer": "ok", "trace_id": "t1"}).encode("utf-8"),
            )

        client = GroundworkClient(base_url="http://localhost:8080", api_key="gw_test_key", transport=transport)
        client.query({"query": "summarize incidents", "top_k": 3})
        self.assertEqual(seen["body"], {"query": "summarize incidents", "top_k": 3})

    def test_error_envelope_surfaces_code_and_status(self):
        client = GroundworkClient(
            base_url="http://localhost:8080",
            api_key="gw_test_key",
            transport=stub_transport(503, {"error": "audit_unavailable"}),
        )
        with self.assertRaises(GroundworkError) as ctx:
            client.audit({"limit": 10})
        self.assertEqual(ctx.exception.code, "audit_unavailable")
        self.assertEqual(ctx.exception.status, 503)

    def test_network_failure_wraps_into_groundwork_error(self):
        def transport(method, url, headers, body_bytes, timeout_ms):
            raise ConnectionError("connection refused")

        client = GroundworkClient(base_url="http://localhost:8080", api_key="gw_test_key", transport=transport)
        with self.assertRaises(GroundworkError) as ctx:
            client.health()
        self.assertEqual(ctx.exception.code, "network")
        self.assertEqual(ctx.exception.status, 0)

    def test_trailing_slash_on_base_url_is_normalized(self):
        seen = {}

        def transport(method, url, headers, body_bytes, timeout_ms):
            seen["url"] = url
            return (
                200,
                {"content-type": "application/json"},
                json.dumps({"status": "ok", "service": "query-runtime"}).encode("utf-8"),
            )

        client = GroundworkClient(base_url="http://localhost:8080/", api_key="gw_test_key", transport=transport)
        client.health()
        self.assertEqual(seen["url"], "http://localhost:8080/healthz")

    def test_mint_user_assertion_produces_verifiable_hs256_jwt(self):
        secret = "test-secret-at-least-32-chars-long!!"
        token = mint_user_assertion(hs_secret=secret, subject="user-1", tenant_id="tenant-acme")

        header, payload, signature = token.split(".")
        self.assertTrue(all((header, payload, signature)))

        def b64url_decode(s):
            padded = s + "=" * (-len(s) % 4)
            return base64.urlsafe_b64decode(padded)

        expected = hmac.new(
            secret.encode("utf-8"),
            ("%s.%s" % (header, payload)).encode("utf-8"),
            hashlib.sha256,
        ).digest()
        self.assertEqual(b64url_decode(signature), expected)

        decoded = json.loads(b64url_decode(payload).decode("utf-8"))
        self.assertEqual(decoded["sub"], "user-1")
        self.assertEqual(decoded["tenant_id"], "tenant-acme")
        self.assertGreater(decoded["exp"], int(time.time()))

    def test_usage_methods_hit_the_usage_endpoints(self):
        calls = []

        def transport(method, url, headers, body_bytes, timeout_ms):
            calls.append(
                {
                    "method": method,
                    "url": url,
                    "body": json.loads(body_bytes.decode("utf-8")) if body_bytes else None,
                    "key": headers.get("Idempotency-Key"),
                }
            )
            if method == "GET":
                return (
                    200,
                    {"content-type": "application/json"},
                    json.dumps({"tenant_id": "tenant-acme", "limits": []}).encode("utf-8"),
                )
            return (
                200,
                {"content-type": "application/json"},
                json.dumps(
                    {"tenant_id": "tenant-acme", "limits": [{"metric": "runs", "period": "monthly", "limit": 1000}]}
                ).encode("utf-8"),
            )

        client = GroundworkClient(base_url="http://localhost:8080", api_key="gw_test_key", transport=transport)
        client.usage()
        client.usage_limits()
        client.set_usage_limits({"limits": [{"metric": "runs", "period": "monthly", "limit": 1000}]}, "idem-usage-1")

        self.assertEqual(calls[0]["url"], "http://localhost:8080/v1/usage")
        self.assertEqual(calls[0]["method"], "GET")
        self.assertEqual(calls[1]["url"], "http://localhost:8080/v1/usage/limits")
        self.assertEqual(calls[1]["method"], "GET")
        self.assertEqual(calls[2]["url"], "http://localhost:8080/v1/usage/limits")
        self.assertEqual(calls[2]["method"], "PUT")
        self.assertEqual(
            calls[2]["body"],
            {"limits": [{"metric": "runs", "period": "monthly", "limit": 1000}]},
        )
        self.assertEqual(calls[2]["key"], "idem-usage-1")


if __name__ == "__main__":
    unittest.main()
