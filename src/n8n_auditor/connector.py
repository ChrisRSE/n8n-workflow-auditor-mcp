"""Live n8n instance REST API client."""

import httpx


class N8nConnector:
    """Fetches workflow JSON from a live n8n instance via the REST API.

    Uses n8n API v1: GET /api/v1/workflows (paginated) and GET /api/v1/workflows/{id}.
    Authentication is via the X-N8N-API-KEY header.
    """

    def __init__(self, base_url: str, api_key: str) -> None:
        self._base = base_url.rstrip("/")
        self._headers = {"X-N8N-API-KEY": api_key}

    def fetch_all_workflows(self) -> list[dict]:
        """Fetch all workflow dicts from the n8n instance."""
        return [self._fetch_one(wid) for wid in self._list_ids()]

    def _list_ids(self) -> list[str]:
        ids: list[str] = []
        cursor: str | None = None
        while True:
            params: dict = {"limit": 100}
            if cursor:
                params["cursor"] = cursor
            resp = httpx.get(
                f"{self._base}/api/v1/workflows",
                headers=self._headers,
                params=params,
                timeout=30,
            )
            resp.raise_for_status()
            data = resp.json()
            ids.extend(str(w["id"]) for w in data.get("data", []))
            cursor = data.get("nextCursor")
            if not cursor:
                break
        return ids

    def _fetch_one(self, workflow_id: str) -> dict:
        resp = httpx.get(
            f"{self._base}/api/v1/workflows/{workflow_id}",
            headers=self._headers,
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json()
