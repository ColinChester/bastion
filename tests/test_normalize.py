from conftest import exec_cols, norm, oq

from bastion.collectors import RawRecord
from bastion.normalize import Normalizer


def test_osquery_exec_maps_to_process_activity():
    ev = norm(oq("process_events", exec_cols("/usr/bin/curl", "curl -s x", team_id="",
                                             platform=1)))
    assert ev["class_uid"] == 1007 and ev["activity_id"] == 1
    assert ev["process"]["file"]["path"] == "/usr/bin/curl"
    assert ev["process"]["cmd_line"] == "curl -s x"
    assert ev["actor"]["process"]["file"]["path"] == "/bin/zsh"
    assert ev["unmapped"]["platform_binary"] == 1
    assert ev["unmapped"]["initial_snapshot"] is False
    assert ev["time"] == 1793480000 * 1000


def test_parent_filled_from_cache_when_join_missing():
    n = Normalizer()
    n.normalize(RawRecord("osquery", oq("process_events",
                                        exec_cols("/bin/bash", "bash x.sh", pid=100))))
    child = exec_cols("/usr/bin/curl", parent_path="", parent_cmdline="", pid=101)
    ev = n.normalize(RawRecord("osquery", oq("process_events", child)))[0]
    assert ev["actor"]["process"]["file"]["path"] == "/bin/bash"


def test_initial_snapshot_flag():
    ev = norm(oq("launchd", {"path": "/Library/LaunchDaemons/x.plist", "label": "x"},
                 counter=0))
    assert ev["unmapped"]["initial_snapshot"] is True
    assert ev["unmapped"]["persistence"]["label"] == "x"


def test_removed_rows_and_non_exec_dropped():
    n = Normalizer()
    assert n.normalize(RawRecord("osquery", oq("process_events", exec_cols("/x"),
                                               action="removed"))) == []
    c = exec_cols("/x")
    c["event_type"] = "fork"
    assert n.normalize(RawRecord("osquery", oq("process_events", c))) == []


def test_es_file_rename_uses_destination():
    ev = norm(oq("file_events", {"pid": "5", "path": "/bin/mv", "filename": "/tmp/a.plist",
                                 "dest_filename": "/Library/LaunchDaemons/a.plist",
                                 "event_type": "rename"}))
    assert ev["activity_id"] == 5
    assert ev["file"]["path"] == "/Library/LaunchDaemons/a.plist"
    assert ev["file"]["unmapped_source_path"] == "/tmp/a.plist"


def test_network_events():
    ev = norm(oq("listening_ports", {"pid": "9", "port": "8080", "protocol": "6",
                                     "address": "0.0.0.0", "path": "/usr/local/bin/node"}))
    assert ev["class_uid"] == 4001 and ev["activity_id"] == 7
    assert ev["src_endpoint"]["port"] == 8080
    ev = norm(oq("open_sockets", {"path": "/x/y", "remote_address": "1.2.3.4",
                                  "remote_port": "443", "protocol": "6"}))
    assert ev["activity_id"] == 1 and ev["dst_endpoint"]["ip"] == "1.2.3.4"


def test_unknown_query_becomes_inventory():
    ev = norm(oq("trusted_roots", {"common_name": "Evil CA", "sha1": "ab"}))
    assert ev["class_uid"] == 0
    assert ev["unmapped"]["inventory"]["kind"] == "trusted_roots"


def test_santa_file_format_with_pipe_in_args():
    line = ("[2026-10-31T20:00:00.123Z] I santad: action=EXEC|decision=ALLOW|reason=BINARY|"
            "sha256=deadbeef|cert_cn=Developer ID Application: X|teamid=ABCDE12345|"
            "signingid=ABCDE12345:com.x|pid=10|ppid=1|uid=501|user=colin|mode=M|"
            "path=/Applications/X.app/Contents/MacOS/X|args=X --filter a|b")
    ev = norm(line, "santa")
    assert ev["process"]["cmd_line"] == "X --filter a|b"
    assert ev["unmapped"]["santa"]["decision"] == "ALLOW"
    assert ev["unmapped"]["team_id"] == "ABCDE12345"
    assert ev["metadata"]["log_name"] == "santa"


def test_santa_non_exec_ignored_and_garbage_safe():
    n = Normalizer()
    assert n.normalize(RawRecord("santa", "[2026-10-31T20:00:00Z] I santad: action=DISKAPPEAR|"
                                          "mount=/Volumes/X")) == []
    assert n.normalize(RawRecord("santa", "not a santa line")) == []
    assert n.normalize(RawRecord("osquery", {"columns": None, "name": "process_events"})) == []


def test_santa_json_format():
    d = {"event_time": "2026-10-31T20:00:00Z",
         "execution": {"target": {"executable": {"path": "/tmp/x", "hash": {"hash": "aa"}},
                                  "id": {"pid": 5}, "parent_id": {"pid": 1},
                                  "team_id": "", "effective_user": {"uid": 501, "name": "c"}},
                       "args": ["/tmp/x", "-v"], "decision": "DECISION_ALLOW",
                       "reason": "REASON_UNKNOWN", "mode": "MODE_MONITOR"}}
    import json
    ev = norm(json.dumps(d), "santa")
    assert ev["process"]["file"]["path"] == "/tmp/x"
    assert ev["unmapped"]["santa"]["decision"] == "ALLOW"


def test_unified_log():
    ev = norm({"timestamp": "2026-10-31 16:02:03.123456-0400", "processID": 7,
               "processImagePath": "/usr/bin/sudo", "subsystem": "",
               "eventMessage": "colin : TTY=ttys000 ; USER=root ; COMMAND=/usr/bin/id"},
              "unified_log")
    assert ev["class_uid"] == 0 and "COMMAND=/usr/bin/id" in ev["message"]
