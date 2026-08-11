"""Error type shared by every Groundwork SDK surface."""


class GroundworkError(Exception):
    """Raised for every non-2xx response and transport failure.

    Attributes:
        status: HTTP status code (0 for transport-level failures).
        code: The server's stable error code (``{"error": "<code>"}``)
            or one of ``network``/``timeout`` for transport failures,
            or ``None`` when the body was not JSON.
        detail: Optional ``detail`` field from the error envelope.
        headers: Response headers as a plain dict.
    """

    def __init__(self, message, status, code=None, detail=None, headers=None):
        super().__init__(message)
        self.status = status
        self.code = code
        self.detail = detail
        self.headers = headers or {}


def parse_error_response(status, headers, body):
    """Build a :class:`GroundworkError` from a non-2xx response."""
    code = None
    detail = None
    if body:
        import json

        try:
            parsed = json.loads(body)
            if isinstance(parsed, dict) and isinstance(parsed.get("error"), str):
                code = parsed["error"]
                if isinstance(parsed.get("detail"), str):
                    detail = parsed["detail"]
        except (ValueError, TypeError):
            pass
    status_text = code if code else ""
    message = "Groundwork API error %d" % status
    if status_text:
        message += ": " + status_text
    return GroundworkError(message, status, code, detail, headers)
