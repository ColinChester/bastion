import os

from bastion.collectors.tail import FileTailer
from bastion.store import Store


def test_tail_skips_existing_then_reads_appends(tmp_path, store):
    f = tmp_path / "log"
    f.write_text("old1\nold2\n")
    t = FileTailer(str(f), "x", store)
    assert t.read_available() == []  # first run starts at end
    with f.open("a") as fh:
        fh.write("new1\nnew2\npart")
    assert t.read_available() == ["new1", "new2"]
    with f.open("a") as fh:
        fh.write("ial\n")
    assert t.read_available() == ["partial"]


def test_tail_checkpoint_survives_restart(tmp_path):
    db = tmp_path / "s.db"
    f = tmp_path / "log"
    f.write_text("")
    s1 = Store(db)
    FileTailer(str(f), "x", s1).read_available()
    with f.open("a") as fh:
        fh.write("a\n")
    assert FileTailer(str(f), "x", s1).read_available() == ["a"]
    s1.close()
    with f.open("a") as fh:
        fh.write("b\n")
    assert FileTailer(str(f), "x", Store(db)).read_available() == ["b"]


def test_tail_handles_rotation(tmp_path, store):
    f = tmp_path / "log"
    f.write_text("")
    t = FileTailer(str(f), "x", store)
    t.read_available()
    with f.open("a") as fh:
        fh.write("before\n")
    assert t.read_available() == ["before"]
    os.rename(f, tmp_path / "log.0")
    f.write_text("after\n")
    assert t.read_available() == ["after"]


def test_tail_missing_file(tmp_path, store):
    assert FileTailer(str(tmp_path / "nope"), "x", store).read_available() == []


def test_detection_dedupe_window(store):
    finding = {"time": 1000, "severity": "high",
               "finding_info": {"uid": "r1", "title": "T"}}
    d1, new1 = store.add_or_merge_detection(finding, "k", 60_000, 1)
    d2, new2 = store.add_or_merge_detection({**finding, "time": 30_000}, "k", 60_000, 2)
    d3, new3 = store.add_or_merge_detection({**finding, "time": 200_000}, "k", 60_000, 3)
    assert new1 and not new2 and new3 and d1 == d2 != d3
    dets = list(store.iter_detections())
    assert dets[0]["hits"] == 2


def test_purge_and_compression_roundtrip(store):
    eid = store.add_event({"time": 1, "class_uid": 1007, "metadata": {"log_name": "osquery"},
                           "process": {"cmd_line": "x" * 1000}})
    assert store.get_event(eid)["process"]["cmd_line"] == "x" * 1000
    store.add_event({"time": 10 * 86_400_000, "class_uid": 1007,
                     "metadata": {"log_name": "osquery"}})
    assert store.purge(retention_days=5, now_ms=10 * 86_400_000) == 1


def test_baseline_touch(store):
    assert store.baseline_touch("binary", "a", 1) is True
    assert store.baseline_touch("binary", "a", 2) is False
    assert store.baseline_size() == {"binary": 1}
