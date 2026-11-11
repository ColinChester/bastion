"""Edge API: typed read-only queries and the HTTP layer's auth and input checks."""

from __future__ import annotations

import json
import urllib.error
import urllib.request

import pytest
from conftest import exec_cols, oq

from bastion.collectors import RawRecord
from bastion.daemon import Pipeline
from bastion.edge_api import EdgeQueries, dispatch, start_edge_api
from bastion.store import Store

T0 = 1_793_480_000
TOKEN = "t" * 40


def _exec(pipe, path, cmd, pid, parent, t=T0, **kw):
    cols = exec_cols(path, cmd, pid=pid, **kw)
    cols["parent"], cols["time"] = str(parent), str(t)
    pipe.handle(RawRecord("osquery", oq("process_events", cols)))


@pytest.fixture
def seeded(cfg):
    store = Store(cfg.db_path)  # on disk: the HTTP server opens its own connections
    pipe = Pipeline(cfg, store)
    _exec(pipe, "/bin/zsh", "-zsh", 100, 1, parent_path="", parent_cmdline="")
    _exec(pipe, "/bin/bash", "bash install.sh", 200, 100, t=T0 + 1)
    _exec(pipe, "/usr/sbin/spctl", "spctl --master-disable", 300, 200, t=T0 + 2, platform=1,
          parent_path="/bin/bash", parent_cmdline="bash install.sh")
    _exec(pipe, "/usr/bin/curl", "curl -s https://x.example", 301, 200, t=T0 + 3, platform=1)
    return EdgeQueries(store)


def test_pending_and_ack(seeded):
    pend = seeded.pending()
    assert [d["title"] for d in pend] == ["Gatekeeper Disabled With spctl"]
    d = pend[0]
    assert d["subject"]["process"]["cmd_line"] == "spctl --master-disable"
    assert d["attack_techniques"] == ["T1553.001"]
    assert seeded.ack(d["detection_id"]) is True
    assert seeded.pending() == []
    assert seeded.ack(9999) is False


def test_process_tree_walks_parents_and_lists_children(seeded):
    tree = seeded.process_tree(300, (T0 + 2) * 1000)
    paths = [n.get("process", {}).get("path") for n in tree["lineage_child_first"]]
    assert paths[:3] == ["/usr/sbin/spctl", "/bin/bash", "/bin/zsh"]
    kids = seeded.process_tree(200, (T0 + 1) * 1000)["children"]
    assert {k["process"]["path"] for k in kids} == {"/usr/sbin/spctl", "/usr/bin/curl"}


def test_binary_history_and_bounds(seeded):
    h = seeded.binary_history("/usr/sbin/spctl", days=9999)  # clamped, not an error
    assert h["path"] == "/usr/sbin/spctl" and "first_seen_baseline" in h
    assert seeded.persistence_lookup("ab")["error"]


def test_dispatch_rejects_unknown_queries_and_params(seeded):
    with pytest.raises(KeyError):
        dispatch(seeded, "run-sql", {})
    with pytest.raises(ValueError):
        dispatch(seeded, "event", {"event_id": "1", "sql": "drop"})
    with pytest.raises(ValueError):
        dispatch(seeded, "event", {"event_id": "abc"})


def _get(port, path, token=TOKEN):
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}",
                                 headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req, timeout=5) as resp:
        return json.loads(resp.read())


def test_http_requires_token_and_serves_queries(cfg, seeded):
    cfg.edge_api.enabled, cfg.edge_api.port, cfg.edge_api.token = True, 0, TOKEN
    server = start_edge_api(cfg)
    port = server.server_address[1]
    try:
        assert _get(port, "/v1/pending")["result"][0]["title"].startswith("Gatekeeper")
        with pytest.raises(urllib.error.HTTPError) as bad:
            _get(port, "/v1/pending", token="wrong")
        assert bad.value.code == 401
        with pytest.raises(urllib.error.HTTPError) as unknown:
            _get(port, "/v1/shell?cmd=id")
        assert unknown.value.code == 404
        det = _get(port, "/v1/pending")["result"][0]["detection_id"]
        req = urllib.request.Request(f"http://127.0.0.1:{port}/v1/detections/{det}/ack",
                                     method="POST",
                                     headers={"Authorization": f"Bearer {TOKEN}"})
        assert json.loads(urllib.request.urlopen(req, timeout=5).read()) == {"acked": True}
        assert _get(port, "/v1/pending")["result"] == []
        assert "events_24h" in _get(port, "/v1/status")["result"]
    finally:
        server.shutdown()
        server.server_close()


def test_api_stays_off_without_a_strong_token(cfg):
    cfg.edge_api.enabled, cfg.edge_api.token = True, "short"
    assert start_edge_api(cfg) is None


def test_core_edge_client_over_real_http(cfg, seeded):
    from bastion.core.edge import EdgeClient, EdgeError

    cfg.edge_api.enabled, cfg.edge_api.port, cfg.edge_api.token = True, 0, TOKEN
    server = start_edge_api(cfg)
    url = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        client = EdgeClient(url, TOKEN)
        assert client.healthy()
        det = client.query("pending", limit=5)[0]
        tree = client.query("process-tree", pid=300, at_ms=(T0 + 2) * 1000)
        assert tree["lineage_child_first"][0]["process"]["path"] == "/usr/sbin/spctl"
        assert client.query("event", event_id=424242) is None
        assert client.ack(det["detection_id"]) and client.query("pending") == []
        with pytest.raises(EdgeError):
            EdgeClient(url, "wrong-token").query("pending")
        with pytest.raises(EdgeError):
            client.query("event", event_id="abc")
    finally:
        server.shutdown()
        server.server_close()
