from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any


GLM_DEFAULT_BASE_URL = "https://open.bigmodel.cn/api/paas/v4"


class GLMHTTPError(RuntimeError):
    def __init__(self, status_code: int, detail: str):
        super().__init__(f"GLM API HTTP {status_code}: {detail}")
        self.status_code = status_code


class GLMClient:
    """Dependency-free client for the GLM Chat Completions API."""

    def __init__(self, base_url: str, api_key: str, model: str, timeout: float = 180):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.timeout = timeout

    def chat(self, payload: dict[str, Any]) -> dict[str, Any]:
        request_payload = {"model": self.model, **payload}
        request = urllib.request.Request(
            self.base_url + "/chat/completions",
            data=json.dumps(request_payload, ensure_ascii=False).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": "aosp-backport-agent",
                "Authorization": "Bearer " + self.api_key,
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                body = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read(2000).decode("utf-8", errors="replace")
            raise GLMHTTPError(exc.code, detail) from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"GLM API connection failed: {exc.reason}") from exc
        except json.JSONDecodeError as exc:
            raise RuntimeError("GLM API returned invalid JSON") from exc
        if not isinstance(body, dict):
            raise RuntimeError("GLM API response must be a JSON object")
        return body
