"""Incident page, evaluation harness, tracing switch and the Phase 2 setup commands."""

from __future__ import annotations

import os
import tomllib
from pathlib import Path

from conftest import exec_cols, oq
from fastapi.testclient import TestClient
from test_core import T0, decision_call, finding_call, standard_script

from bastion import cli
from bastion.collectors import RawRecord
from bastion.config import load_config, set_toml_value
from bastion.core.corestore import CoreStore
from bastion.core.edge import LocalEdge
from bastion.core.evaluate import grade, load_labels, report, run_eval, select_cases
from bastion.core.graph import triage
from bastion.core.models import ModelReply, ScriptedClient
from bastion.core.schemas import Verdict
from bastion.core.settings import Settings
from bastion.core.tracing import setup_tracing
from bastion.core.web import create_app
from bastion.daemon import Pipeline
from bastion.edge_api import EdgeQueries
from bastion.store import Store

LABELS = Path(__file__).parent / "labeled_events" / "phase1-labels.yml"
XSS = "<script>alert(1)</script>"


def _seed(cfg, cmd="spctl --master-disable", path="/usr/sbin/spctl"):
    store = Store(cfg.db_path)
    cols = exec_cols(path, cmd, pid=300, platform=1)
    cols["time"] = str(T0)
    Pipeline(cfg, store).handle(RawRecord("osquery", oq("process_events", cols)))
    return store, LocalEdge(EdgeQueries(store))


def test_incident_page_renders_and_escapes_untrusted_text(cfg, tmp_path):
    store, edge = _seed(cfg, cmd=f"spctl --master-disable {XSS}")
    core = CoreStore(":memory:")
    settings = Settings(data_dir=tmp_path)
    final = finding_call(summary=f"Saw {XSS} in the command line.")
    inc = triage(edge.query("pending")[0], settings=settings, edge=edge, store=core,
                 model=ScriptedClient(standard_script(agent_final=final)))
    core.save_incident(inc)
    client = TestClient(create_app(settings, core))
    home = client.get("/")
    assert home.status_code == 200 and "Gatekeeper was switched off" in home.text
    assert "default-src 'none'" in home.headers["content-security-policy"]
    page = client.get(f"/incident/{inc.id}")
    assert page.status_code == 200
    assert XSS not in page.text and "&lt;script&gt;" in page.text
    assert "get_process_tree" in page.text and "Observe-only" in page.text
    assert client.get("/incident/nope").status_code == 404
    assert client.get("/?verdict=benign").status_code == 200
    assert client.post("/").status_code == 405  # read-only


def test_labels_load_and_cover_every_rule():
    labels = load_labels(LABELS)
    names = [lb.name for lb in labels]
    assert len(names) == len(set(names))
    from bastion.detect.sigma import load_rules
    rules, _ = load_rules(cli.Config().resolved_rules_dir())
    labeled_rules = {lb.rule for lb in labels if lb.expect == "threat"}
    assert {r.title for r in rules} <= labeled_rules
    assert {lb.expect for lb in labels} == {"threat", "benign"}


def test_grading():
    assert grade("threat", Verdict.SUSPICIOUS) == "PASS"
    assert grade("threat", Verdict.BENIGN) == "MISS"
    assert grade("benign", Verdict.MALICIOUS) == "FALSE ALARM"
    assert grade("benign", Verdict.BENIGN) == "PASS"
    assert grade("threat", Verdict.INCONCLUSIVE) == "UNSURE"


def test_eval_runs_without_acking_saving_or_spending_the_ledger(cfg, tmp_path):
    decoy = "/Users/colin/git/bastion/build/decoys/spctl"
    store, edge = _seed(cfg, cmd=f"{decoy} --master-disable", path=decoy)
    # make the seeded detection recent enough for the eval window
    store.db.execute("UPDATE detections SET time_ms = strftime('%s','now') * 1000 - 5000, "
                     "last_ms = strftime('%s','now') * 1000 - 5000")
    settings = Settings(data_dir=tmp_path)
    labels = load_labels(LABELS)
    cases, uncovered = run_eval(settings=settings, edge=edge, labels=labels, days=2,
                                model=ScriptedClient(standard_script()))
    assert [(c.label.name, c.grade) for c in cases] == [("trigger-gatekeeper", "PASS")]
    assert "gh-cli-keychain" in uncovered
    assert len(edge.query("pending")) == 1          # not acknowledged
    text = report(cases, uncovered, settings)
    assert "**1 of 1 correct**" in text and "trigger-gatekeeper" in text
    # a model that waves it through is graded as a missed threat
    cases, _ = run_eval(settings=settings, edge=edge, labels=labels, days=2,
                        model=ScriptedClient(standard_script(
                            agent_final=finding_call("benign", 0.95))))
    assert cases[0].grade == "MISS"


def test_first_matching_label_wins_and_sampling_is_capped():
    labels = load_labels(LABELS)
    title = "Keychain Secrets Read With the security CLI"
    dets = [{"detection_id": i, "time_ms": i, "title": title, "subject": {"process": {
        "cmd_line": "security find-generic-password -s gh:github.com -wa x"}}}
        for i in range(10)]
    dets.append({"detection_id": 99, "time_ms": 99, "title": title, "subject": {"process": {
        "path": "/x/build/decoys/security", "cmd_line": "-s bastion-test"}}})
    cases = select_cases(labels, dets, per_label=2)
    assert sorted(c.label.name for c in cases) == ["gh-cli-keychain", "gh-cli-keychain",
                                                   "trigger-keychain"]


def test_tracing_is_off_without_an_endpoint(monkeypatch):
    monkeypatch.delenv("PHOENIX_COLLECTOR_ENDPOINT", raising=False)
    assert setup_tracing() is False


def test_set_toml_value_edits_in_place():
    text = '[notify]\nmode = "daily"\ntopic = "x"\n\n[baseline]\nlearning_days = 14\n'
    out = set_toml_value(text, "notify", "mode", '"off"')
    out = set_toml_value(out, "edge_api", "enabled", "true")
    out = set_toml_value(out, "edge_api", "token", '"abc"')
    out = set_toml_value(out, "baseline", "new_key", "5")
    parsed = tomllib.loads(out)
    assert parsed["notify"] == {"mode": "off", "topic": "x"}
    assert parsed["edge_api"] == {"enabled": True, "token": "abc"}
    assert parsed["baseline"] == {"learning_days": 14, "new_key": 5}


def test_enable_edge_api_writes_config_and_token_file(tmp_path, monkeypatch, capsys):
    conf = tmp_path / "config.toml"
    conf.write_text('[notify]\nmode = "daily"\n')
    token_file = tmp_path / "token"
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    args = ["--config", str(conf), "enable-edge-api", "--token-file", str(token_file),
            "--quiet-bastiond-pushes"]
    assert cli.main(args) == 0
    token = token_file.read_text().strip()
    cfg = load_config(conf)
    assert cfg.edge_api.enabled and cfg.edge_api.token == token and len(token) == 64
    assert cfg.notify.mode == "off"
    assert token not in capsys.readouterr().out
    assert oct(token_file.stat().st_mode & 0o777) == "0o600"
    cli.main(args)  # idempotent: the token is kept
    assert load_config(conf).edge_api.token == token


def test_backfill_indexes_old_events(cfg):
    store, edge = _seed(cfg)
    store.db.execute("UPDATE events SET pid = NULL, ppid = NULL, proc_path = NULL, "
                     "file_path = NULL")
    assert store.events_where("pid", 300) == []
    assert store.backfill_lookup_columns() >= 1
    assert len(store.events_where("pid", 300)) == 1
    assert store.backfill_lookup_columns() == 0


def test_warden_garbage_falls_back_to_the_analyst(cfg, tmp_path):
    store, edge = _seed(cfg)

    def script(model, system, messages, tools, force_tool):
        if force_tool == "submit_decision":
            return ModelReply("no tool call at all")
        return standard_script()(model, system, messages, tools, force_tool)

    inc = triage(edge.query("pending")[0], settings=Settings(data_dir=tmp_path), edge=edge,
                 store=CoreStore(":memory:"), model=ScriptedClient(script))
    assert inc.decision.verdict == Verdict.SUSPICIOUS and inc.decision.notify
    assert any("no submit_decision call" in e for e in inc.errors)
    assert decision_call().tool_calls[0].name == "submit_decision"


def test_eval_records_model_errors_instead_of_crashing(cfg, tmp_path):
    from bastion.core.models import ModelError

    decoy = "/Users/colin/git/bastion/build/decoys/spctl"
    store, edge = _seed(cfg, cmd=f"{decoy} --master-disable", path=decoy)
    store.db.execute("UPDATE detections SET time_ms = strftime('%s','now') * 1000 - 5000, "
                     "last_ms = strftime('%s','now') * 1000 - 5000")

    def broken(*_):
        raise ModelError("BadRequestError: 400")

    settings = Settings(data_dir=tmp_path)
    cases, _ = run_eval(settings=settings, edge=edge, labels=load_labels(LABELS), days=2,
                        model=ScriptedClient(broken))
    assert [c.grade for c in cases] == ["ERROR"]
    assert "| ERROR | trigger-gatekeeper |" in report(cases, [], settings)
