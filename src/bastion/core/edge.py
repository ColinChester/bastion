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

    # ---- executor (Phase 3) -------------------------------------------------------
    def _exec(self, method: str, op: str, **kw):
        try:
            resp = self._http.request(method, f"/v1/exec/{op}", **kw)
        except httpx.HTTPError as exc:
            raise EdgeError(f"can't reach bastiond's edge API: {exc}") from exc
        try:
            body = resp.json()
        except ValueError as exc:
            raise EdgeError(f"executor {op}: HTTP {resp.status_code}") from exc
        if resp.status_code != 200:
            raise EdgeError(body.get("error", f"HTTP {resp.status_code}"))
        return body["result"]

    def exec_get(self, op: str, **params):
        return self._exec("GET", op, params=params)

    def exec_post(self, op: str, body: dict):
        return self._exec("POST", op, json=body)

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

    # With an executor attached, behaves like the HTTP executor routes.
    executor = None

    def _exec(self, table, op, arg):
        from bastion.executor.service import Rejected

        if self.executor is None:
            raise EdgeError("executor is not enabled")
        try:
            return table[op](self.executor, arg)
        except Rejected as exc:
            raise EdgeError(str(exc)) from exc

    def exec_get(self, op: str, **params):
        from bastion.edge_api import EXEC_GET

        return self._exec(EXEC_GET, op, {k: str(v) for k, v in params.items()})

    def exec_post(self, op: str, body: dict):
        from bastion.edge_api import EXEC_POST

        return self._exec(EXEC_POST, op, body)
