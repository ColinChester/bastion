"""Clients for bastiond's edge API: the real HTTP one, and an in-process one for tests."""

from __future__ import annotations

from typing import Protocol

import httpx


class EdgeError(RuntimeError):
    pass


class Edge(Protocol):
    def query(self, name: str, **params): ...
    def ack(self, detection_id: int) -> bool: ...


class EdgeClient:
    def __init__(self, base_url: str, token: str, timeout: float = 15.0):
        self._http = httpx.Client(base_url=base_url, timeout=timeout,
                                  headers={"Authorization": f"Bearer {token}"})

    def query(self, name: str, **params):
        try:
            resp = self._http.get(f"/v1/{name}", params=params)
        except httpx.HTTPError as exc:
            raise EdgeError(f"can't reach bastiond's edge API: {exc}") from exc
        if resp.status_code == 404 and resp.json().get("error") == "not found":
            return None
        if resp.status_code != 200:
            raise EdgeError(f"edge API {name}: HTTP {resp.status_code} "
                            f"{resp.json().get('error', '')}")
        return resp.json()["result"]

    def ack(self, detection_id: int) -> bool:
        try:
            resp = self._http.post(f"/v1/detections/{detection_id}/ack")
        except httpx.HTTPError as exc:
            raise EdgeError(f"can't reach bastiond's edge API: {exc}") from exc
        return resp.status_code == 200

    def healthy(self) -> bool:
        try:
            return self._http.get("/v1/health").status_code == 200
        except httpx.HTTPError:
            return False


class LocalEdge:
    """Calls EdgeQueries directly (same validation as HTTP). For tests and replays."""

    def __init__(self, queries):
        self.queries = queries

    def query(self, name: str, **params):
        from bastion.edge_api import dispatch

        try:
            return dispatch(self.queries, name, {k: str(v) for k, v in params.items()})
        except (KeyError, ValueError, TypeError) as exc:
            raise EdgeError(str(exc)) from exc

    def ack(self, detection_id: int) -> bool:
        return self.queries.ack(detection_id)
