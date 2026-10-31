from pathlib import Path

import pytest

from bastion.config import load_config


def test_defaults_when_missing(tmp_path):
    cfg = load_config(tmp_path / "nope.toml")
    assert cfg.retention_days == 30
    assert cfg.notify.mode == "daily"
    assert cfg.resolved_rules_dir().is_dir()


def test_partial_file_merges(tmp_path):
    p = tmp_path / "c.toml"
    p.write_text('data_dir = "/tmp/b"\n[notify]\nntfy_topic = "abc"\n'
                 '[sources.santa]\nenabled = false\n[baseline]\nlearning_days = 7\n')
    cfg = load_config(p)
    assert cfg.data_dir == Path("/tmp/b")
    assert cfg.notify.ntfy_topic == "abc" and cfg.notify.ntfy_server == "https://ntfy.sh"
    assert cfg.santa.enabled is False and cfg.osquery.enabled is True
    assert cfg.baseline.learning_days == 7


def test_unknown_key_rejected(tmp_path):
    p = tmp_path / "c.toml"
    p.write_text("[notify]\nntfy_topik = 'x'\n")
    with pytest.raises(ValueError, match="ntfy_topik"):
        load_config(p)


def test_shipped_template_parses():
    tpl = Path(__file__).resolve().parents[1] / "config" / "config.toml.template"
    text = tpl.read_text().replace("__NTFY_TOPIC__", "t")
    p = Path("/tmp/bastion-template-test.toml")
    p.write_text(text)
    cfg = load_config(p)
    assert cfg.notify.ntfy_topic == "t"
