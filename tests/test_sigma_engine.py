import pytest

from bastion.detect.sigma import SigmaError, compile_rule


def rule(detection, category="process_creation"):
    return compile_rule({"title": "t", "id": "x", "level": "low",
                         "logsource": {"product": "macos", "category": category},
                         "detection": detection})


def proc(path="/bin/x", cmd="", parent=None, team=""):
    ev = {"class_uid": 1007, "activity_id": 1,
          "process": {"file": {"path": path}, "cmd_line": cmd}, "unmapped": {"team_id": team}}
    if parent:
        ev["actor"] = {"process": {"file": {"path": parent}}}
    return ev


def test_wildcards_are_case_insensitive():
    r = rule({"s": {"Image": "*/DOWNLOADS/*"}, "condition": "s"})
    assert r.matches(proc("/Users/c/Downloads/a"))
    assert not r.matches(proc("/Users/c/Desktop/a"))


def test_list_is_or_and_all_is_and():
    r = rule({"s": {"CommandLine|contains": ["foo", "bar"]}, "condition": "s"})
    assert r.matches(proc(cmd="x bar"))
    r = rule({"s": {"CommandLine|contains|all": ["foo", "bar"]}, "condition": "s"})
    assert not r.matches(proc(cmd="x bar"))
    assert r.matches(proc(cmd="foo bar"))


def test_null_matches_missing_or_empty():
    r = rule({"s": {"TeamId": None}, "condition": "s"})
    assert r.matches(proc(team=""))
    assert not r.matches(proc(team="ABC"))


def test_condition_precedence_and_of():
    det = {"a1": {"Image|endswith": "/a"}, "a2": {"Image|endswith": "/b"},
           "f": {"ParentImage|endswith": "/zsh"},
           "condition": "1 of a* and not f"}
    r = rule(det)
    assert r.matches(proc("/x/b", parent="/bin/bash"))
    assert not r.matches(proc("/x/b", parent="/bin/zsh"))
    r = rule({**det, "condition": "all of a*"})
    assert not r.matches(proc("/x/a"))


def test_parentheses_and_or():
    det = {"a": {"Image|endswith": "/a"}, "b": {"Image|endswith": "/b"},
           "c": {"CommandLine|contains": "go"}, "condition": "(a or b) and c"}
    r = rule(det)
    assert r.matches(proc("/a", "go"))
    assert not r.matches(proc("/a", "stop"))


def test_regex_and_exists():
    r = rule({"s": {"Image|re": r"^/Users/[^/]+/\.[^/]+/"}, "condition": "s"})
    assert r.matches(proc("/Users/c/.hidden/x"))
    r = rule({"s": {"ParentImage|exists": True}, "condition": "s"})
    assert r.matches(proc(parent="/bin/zsh"))
    assert not r.matches(proc())


def test_list_of_maps_is_or():
    r = rule({"s": [{"Image|endswith": "/a"}, {"CommandLine|contains": "zz"}],
              "condition": "s"})
    assert r.matches(proc("/b", "zz"))


@pytest.mark.parametrize("det,msg", [
    ({"s": ["keyword"], "condition": "s"}, "keyword"),
    ({"s": {"Image|base64": "x"}, "condition": "s"}, "unsupported modifier"),
    ({"s": {"Image": "x"}, "condition": "s and t"}, "unknown selection"),
    ({"s": {"Nope": "x"}, "condition": "s"}, "not mapped"),
])
def test_unsupported_constructs_fail_loudly(det, msg):
    with pytest.raises((SigmaError, KeyError), match=msg):
        rule(det)


def test_dotted_field_is_raw_ocsf_path():
    r = rule({"s": {"process.file.path|endswith": "/x"}, "condition": "s"})
    assert r.matches(proc("/bin/x"))
