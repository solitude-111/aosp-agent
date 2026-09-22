from __future__ import annotations

import json
import shutil
import subprocess
import urllib.error
import urllib.request


class OpenAICompatibleClient:
    """Dependency-free client for an OpenAI-compatible Chat Completions endpoint."""

    def __init__(self, base_url: str, api_key: str, model: str, timeout: int = 180):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.timeout = timeout

    def complete(self, system: str, user: str, max_tokens: int = 8192) -> str:
        payload = {"model": self.model, "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ], "max_tokens": max_tokens, "temperature": 0}
        curl = shutil.which("curl")
        if curl:
            completed = subprocess.run(
                [curl, "-sS", "--connect-timeout", "30", "--max-time", str(self.timeout),
                 "--fail-with-body", "-X", "POST", self.base_url + "/chat/completions",
                 "-H", "Content-Type: application/json", "-H", "Accept: application/json",
                 "-H", "User-Agent: aosp-backport-agent", "-H", "Authorization: Bearer " + self.api_key,
                 "--data-binary", json.dumps(payload)], text=True, capture_output=True)
            if completed.returncode:
                detail = (completed.stdout or completed.stderr)[-1000:]
                raise RuntimeError(f"compatible API request failed (curl rc={completed.returncode}): {detail}")
            try:
                body = json.loads(completed.stdout)
            except json.JSONDecodeError as exc:
                raise RuntimeError("compatible API returned invalid JSON") from exc
        else:
            request = urllib.request.Request(
                self.base_url + "/chat/completions",
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json", "Authorization": "Bearer " + self.api_key},
                method="POST",
            )
            try:
                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    body = json.loads(response.read().decode("utf-8"))
            except urllib.error.HTTPError as exc:
                detail = exc.read(1000).decode("utf-8", errors="replace")
                raise RuntimeError(f"compatible API HTTP {exc.code}: {detail}") from exc
            except urllib.error.URLError as exc:
                raise RuntimeError(f"compatible API connection failed: {exc.reason}") from exc
        choices = body.get("choices") or []
        if not choices:
            raise RuntimeError("compatible API returned no choices")
        content = (choices[0].get("message") or {}).get("content")
        if not isinstance(content, str) or not content.strip():
            raise RuntimeError("compatible API returned an empty message")
        return content
