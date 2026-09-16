"""
cli/client.py — thin HTTP client over the FastAPI backend. Every method
maps to exactly one existing API endpoint (backend/main.py) — this file
deliberately contains no scan/graph/risk logic of its own, matching the
platform's rule that the CLI is a client, not a second implementation of
the engine.
"""
from __future__ import annotations

import httpx

from cli.config import CLIConfig


class APIError(Exception):
    def __init__(self, status_code: int, detail: str):
        self.status_code = status_code
        self.detail = detail
        super().__init__(f"[{status_code}] {detail}")


class CloudPathClient:
    def __init__(self, config: CLIConfig, transport: httpx.BaseTransport | None = None):
        self.config = config
        headers = {"Authorization": f"Bearer {config.access_token}"} if config.access_token else {}
        # `transport` is injectable so tests can point this at an in-process
        # ASGI app (httpx.ASGITransport) instead of a real network socket —
        # production use leaves it None and httpx opens a real connection.
        self._client = httpx.Client(base_url=config.api_url, headers=headers, transport=transport, timeout=30.0)

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "CloudPathClient":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def _request(self, method: str, path: str, **kwargs) -> dict:
        response = self._client.request(method, path, **kwargs)
        if response.status_code >= 400:
            detail = response.text
            try:
                detail = response.json().get("detail", detail)
            except Exception:  # noqa: BLE001
                pass
            raise APIError(response.status_code, detail)
        return response.json()

    # ------------------------------------------------------------------
    def health(self) -> dict:
        return self._request("GET", "/health")

    def login(self, username: str, password: str) -> dict:
        # OAuth2PasswordRequestForm expects form-encoded data, not JSON —
        # matches how backend/main.py's /auth/login endpoint is defined.
        response = self._client.post(
            "/api/v1/auth/login", data={"username": username, "password": password}
        )
        if response.status_code >= 400:
            detail = response.json().get("detail", response.text)
            raise APIError(response.status_code, detail)
        return response.json()

    def create_scan(self, region: str = "us-east-1", crown_jewel_ids: list[str] | None = None) -> dict:
        return self._request(
            "POST", "/api/v1/scans", json={"region": region, "crown_jewel_ids": crown_jewel_ids or []}
        )

    def create_scan_async(self, region: str = "us-east-1", crown_jewel_ids: list[str] | None = None) -> dict:
        return self._request(
            "POST", "/api/v1/scans/async", json={"region": region, "crown_jewel_ids": crown_jewel_ids or []}
        )

    def get_scan(self, scan_id: str) -> dict:
        return self._request("GET", f"/api/v1/scans/{scan_id}")

    def list_assets(self, scan_id: str | None = None) -> list[dict]:
        params = {"scan_id": scan_id} if scan_id else {}
        return self._request("GET", "/api/v1/assets", params=params)

    def list_attack_paths(self, scan_id: str | None = None) -> list[dict]:
        params = {"scan_id": scan_id} if scan_id else {}
        return self._request("GET", "/api/v1/attack-paths", params=params)

    def get_statistics(self, scan_id: str | None = None) -> dict:
        params = {"scan_id": scan_id} if scan_id else {}
        return self._request("GET", "/api/v1/statistics", params=params)

    def analyze_attack_path(self, attack_path_id: str) -> dict:
        return self._request("POST", f"/api/v1/attack-paths/{attack_path_id}/analyze")

    def get_attack_path_analysis(self, attack_path_id: str) -> dict:
        return self._request("GET", f"/api/v1/attack-paths/{attack_path_id}/analysis")

    def get_mitre_mappings(self, attack_path_id: str) -> list[dict]:
        return self._request("GET", f"/api/v1/attack-paths/{attack_path_id}/mitre")

    def simulate(self, remove_edges: list[dict], scan_id: str | None = None) -> dict:
        payload = {"remove_edges": remove_edges}
        if scan_id:
            payload["scan_id"] = scan_id
        return self._request("POST", "/api/v1/simulation", json=payload)

    def get_graph(self, scan_id: str | None = None) -> dict:
        params = {"scan_id": scan_id} if scan_id else {}
        return self._request("GET", "/api/v1/graph", params=params)
