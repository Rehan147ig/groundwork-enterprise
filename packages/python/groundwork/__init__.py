"""Zero-dependency typed client for the Groundwork query runtime API.

Mirrors the TypeScript SDK (``@groundwork/sdk``) surface: the same
endpoints, the same request/response envelopes, the same error semantics
(``GroundworkError`` with ``status``/``code``/``detail``), and the same
``mint_user_assertion`` HS256 helper. Responses are returned as plain
``dict``s decoded from the JSON envelopes; request bodies are plain
``dict``s (TypedDicts in :mod:`groundwork.types`).
"""

from .assertion import mint_user_assertion
from .client import GroundworkClient
from .errors import GroundworkError

__all__ = ["GroundworkClient", "GroundworkError", "mint_user_assertion"]
__version__ = "0.1.0"
