from bastion.redact import MASK, Redactor

R = Redactor()


def test_known_token_formats():
    samples = [
        "export GITHUB_TOKEN=ghp_" + "a" * 36,
        "curl -H 'x-api-key: sk-ant-api03-" + "b" * 40 + "'",
        "aws configure set aws_access_key_id AKIAABCDEFGHIJKLMNOP",
        "OPENAI_API_KEY=sk-proj-" + "c" * 40,
    ]
    for s in samples:
        out = R.redact(s)
        assert MASK in out, s
        assert "a" * 36 not in out and "b" * 40 not in out and "c" * 40 not in out


def test_keeps_key_name_hides_value():
    out = R.redact("mysql --password=hunter2hunter2 -u root")
    assert "--password=" in out and "hunter2" not in out


def test_url_credentials_and_query_secrets():
    out = R.redact("git clone https://colin:s3cretpass@github.com/x/y.git")
    assert "s3cretpass" not in out and "github.com/x/y.git" in out
    out = R.redact("https://api.example.com/v1?access_token=abcdef123456&page=2")
    assert "abcdef123456" not in out and "page=2" in out


def test_bearer_header():
    out = R.redact("curl -H 'Authorization: Bearer abcdefghijklmnopqrstuvwxyz012345'")
    assert "abcdefghijklmnopqrstuvwxyz012345" not in out


def test_detection_relevant_text_survives():
    for s in ["security find-generic-password -wa Chrome",
              "/usr/bin/osascript -e display dialog with hidden answer",
              "launchctl bootout system/com.northpolesec.santa.daemon",
              "xattr -d com.apple.quarantine /Users/colin/Downloads/app.app"]:
        assert R.redact(s) == s


def test_event_walk_and_env_drop():
    ev = {"process": {"cmd_line": "tool --token=abcdefghijkl"},
          "unmapped": {"env": "HOME=/x SECRET=y"}, "n": 5}
    out = R.redact_event(ev)
    assert "abcdefghijkl" not in out["process"]["cmd_line"]
    assert out["unmapped"]["env"] == MASK
    assert out["n"] == 5
    assert ev["unmapped"]["env"] != MASK  # original untouched


def test_private_key_block():
    pem = "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\nBBBB\n-----END OPENSSH PRIVATE KEY-----"
    assert R.redact(pem) == MASK


def test_auth_header_values_are_redacted_not_the_scheme():
    r = Redactor()
    assert r.redact("Authorization: Bearer abcdefghijklmnop") == "Authorization: Bearer [REDACTED]"
    assert "dXNlcjpwYXNz" not in r.redact("authorization: Basic dXNlcjpwYXNzd29yZA==")


def test_plain_words_after_secret_words_stay_readable():
    r = Redactor()
    assert r.redact("/opt/homebrew/bin/gh auth git-credential get") == (
        "/opt/homebrew/bin/gh auth git-credential get")
    assert r.redact("mysql --password supersecret1") == "mysql --password [REDACTED]"
    assert r.redact("export API_TOKEN=abcdef123456") == "export API_TOKEN=[REDACTED]"
