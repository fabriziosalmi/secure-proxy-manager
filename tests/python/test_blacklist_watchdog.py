"""Unit tests for the proxy sidecar that applies configuration to Squid.

proxy/blacklist_watchdog.py had no test of any kind. Its happy path is covered
transitively — tests/ci-e2e.sh gates on the watchdog syncing a blacklist into
Squid — but that is the only path anything reached. The branches below are the
ones that decide whether a failed reload is retried, reported or silently
dropped, and none of them had ever run under test (SECURE-TEST-02).

The module is imported without executing main(): everything under test is a
module-level function with no global state.
"""
import json
import os
import subprocess
import sys
import types

import pytest

WATCHDOG = os.path.join(os.path.dirname(__file__), "..", "..", "proxy", "blacklist_watchdog.py")


def load_watchdog():
    """Import the definitions without starting the poll loop."""
    src = open(WATCHDOG).read().split("def main()")[0]
    mod = types.ModuleType("watchdog_under_test")
    mod.__dict__["__file__"] = WATCHDOG
    exec(compile(src, WATCHDOG, "exec"), mod.__dict__)  # noqa: S102
    return mod


@pytest.fixture(scope="module")
def w():
    return load_watchdog()


# ── trigger_stamp ────────────────────────────────────────────────────────────

def test_trigger_stamp_reads_the_backend_written_content(w, tmp_path):
    """The backend writes time.Now().Unix() as the file's CONTENT.

    Reading that rather than the mtime is what keeps the acknowledgement an
    integer, which is the only shape Go's int64 field accepts (SECURE-API-01).
    """
    p = tmp_path / ".reload-squid"
    p.write_text("1788937285")
    assert w.trigger_stamp(str(p), 999) == 1788937285
    assert isinstance(w.trigger_stamp(str(p), 999), int)


def test_trigger_stamp_falls_back_when_content_is_unusable(w, tmp_path):
    p = tmp_path / ".reload-squid"
    p.write_text("not-a-number")
    assert w.trigger_stamp(str(p), 42.7) == 42
    assert w.trigger_stamp(str(tmp_path / "absent"), 7.9) == 7


# ── write_result ─────────────────────────────────────────────────────────────

@pytest.fixture
def config_dir(tmp_path, monkeypatch):
    """Redirect the module's hardcoded /config to a temp directory.

    write_result addresses /config directly, which is correct in the container
    it ships in. Rather than change production code for testability, the test
    creates the real path when it can (CI runs this in a container) and
    otherwise skips — an honest skip beats a test that passes against a mock of
    the thing under test.
    """
    try:
        os.makedirs("/config", exist_ok=True)
        probe = "/config/.watchdog-test-probe"
        with open(probe, "w") as fh:
            fh.write("x")
        os.remove(probe)
    except OSError:
        pytest.skip("/config is not writable here; this test needs the container")
    yield "/config"
    for leftover in os.listdir("/config"):
        if leftover.startswith(".reload-squid"):
            os.remove(os.path.join("/config", leftover))


def test_write_result_emits_an_integer_mtime(w, config_dir):
    """A float here is refused by the Go decoder, so the whole handshake fails."""
    w.write_result("reload-squid", 1788937285.959049, 0, 0)
    raw = open(os.path.join(config_dir, ".reload-squid.result")).read()

    assert "1788937285.9" not in raw, f"the mtime was emitted as a float: {raw}"
    payload = json.loads(raw)
    assert payload["trigger_mtime"] == 1788937285
    assert isinstance(payload["trigger_mtime"], int), "a float is unreadable by the backend"
    assert payload["applied"] is True


def test_write_result_marks_a_refused_reload_as_not_applied(w, config_dir):
    w.write_result("reload-squid", 100, 1, None)
    payload = json.loads(open(os.path.join(config_dir, ".reload-squid.result")).read())
    assert payload["applied"] is False
    assert payload["generator_rc"] == 1
    assert payload["reconfigure_rc"] is None


# ── atomic_copy ──────────────────────────────────────────────────────────────

def test_atomic_copy_publishes_the_whole_file_or_nothing(w, tmp_path):
    src = tmp_path / "src.txt"
    dst = tmp_path / "dst.txt"
    src.write_text("1.2.3.4\n5.6.7.8\n")
    w.atomic_copy(str(src), str(dst))
    assert dst.read_text() == "1.2.3.4\n5.6.7.8\n"


def test_atomic_copy_leaves_no_debris_and_no_partial_destination(w, tmp_path):
    """A failure must not leave a temp file behind or a truncated destination.

    Squid reads the destination directly; a partial one is a truncated ACL.
    """
    src = tmp_path / "src.txt"
    dst = tmp_path / "dst.txt"
    src.write_text("good\n")
    w.atomic_copy(str(src), str(dst))

    # Fail mid-stream. chmod is not usable here: these tests run as root in a
    # container, where permissions are not enforced.
    import shutil as _shutil
    original = _shutil.copyfileobj

    def explode(*a, **kw):
        raise OSError("simulated I/O failure mid-copy")

    _shutil.copyfileobj = explode
    try:
        with pytest.raises(OSError):
            w.atomic_copy(str(src), str(dst))
    finally:
        _shutil.copyfileobj = original

    assert dst.read_text() == "good\n", "the destination was replaced by a failed copy"
    leftovers = [p.name for p in tmp_path.iterdir() if ".tmp" in p.name]
    assert leftovers == [], f"a failed copy left debris: {leftovers}"


# ── squid_config_ok ──────────────────────────────────────────────────────────

def test_squid_config_ok_reports_the_parse_result(w, monkeypatch):
    """This gate is what stops a non-parsing config from being applied."""
    monkeypatch.setattr(subprocess, "run",
                        lambda *a, **kw: types.SimpleNamespace(returncode=0, stdout=b"", stderr=b""))
    assert w.squid_config_ok() is True
    monkeypatch.setattr(subprocess, "run",
                        lambda *a, **kw: types.SimpleNamespace(returncode=1, stdout=b"", stderr=b"parse error"))
    assert w.squid_config_ok() is False


def test_squid_config_ok_fails_closed_when_squid_cannot_be_run(w, monkeypatch):
    """A missing or hung binary must not read as 'the config is fine'."""
    def boom(*a, **kw):
        raise FileNotFoundError("/usr/sbin/squid")
    monkeypatch.setattr(subprocess, "run", boom)
    assert w.squid_config_ok() is False


# ── list manifest (SECURE-ARCH-01) ───────────────────────────────────────────
#
# The backend writes lists.manifest.json after the lists; the watchdog must not
# turn a list whose bytes disagree with it into a live Squid ACL.

def _sha(data: bytes) -> str:
    import hashlib
    return hashlib.sha256(data).hexdigest()


def _manifest(tmp_path, files, version=1):
    p = tmp_path / "lists.manifest.json"
    p.write_text(json.dumps({
        "version": version,
        "generated_at": 1,
        "files": {n: {"sha256": h, "bytes": 0} for n, h in files.items()},
    }))
    return str(p)


def test_matching_checksum_publishes_the_list(w, tmp_path):
    src, dst = tmp_path / "ip_blacklist.txt", tmp_path / "local.txt"
    src.write_bytes(b"203.0.113.9\n")
    w.atomic_copy(str(src), str(dst), _sha(b"203.0.113.9\n"))
    assert dst.read_bytes() == b"203.0.113.9\n"


def test_mismatch_keeps_the_previous_copy_and_leaves_no_temp(w, tmp_path):
    src, dst = tmp_path / "ip_blacklist.txt", tmp_path / "local.txt"
    dst.write_bytes(b"previous good list\n")
    src.write_bytes(b"203.0.113.")  # truncated mid-line
    with pytest.raises(w.ChecksumMismatch):
        w.atomic_copy(str(src), str(dst), _sha(b"203.0.113.9\n"))
    assert dst.read_bytes() == b"previous good list\n"
    assert [f.name for f in tmp_path.iterdir() if ".tmp" in f.name] == []


def test_no_expected_checksum_copies_as_before(w, tmp_path):
    src, dst = tmp_path / "a", tmp_path / "b"
    src.write_bytes(b"x\n")
    w.atomic_copy(str(src), str(dst))
    assert dst.read_bytes() == b"x\n"


def test_manifest_missing_is_distinct_from_invalid(w, tmp_path):
    assert w.load_manifest(str(tmp_path / "absent.json")) == ("missing", None)
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    kind, reason = w.load_manifest(str(bad))
    assert kind == "invalid" and "unreadable" in reason


def test_manifest_with_unknown_version_or_bad_checksum_is_invalid(w, tmp_path):
    kind, _ = w.load_manifest(_manifest(tmp_path, {"a": "0" * 64}, version=99))
    assert kind == "invalid"
    kind, reason = w.load_manifest(_manifest(tmp_path, {"a": "short"}))
    assert kind == "invalid" and "bad checksum" in reason


def test_valid_manifest_yields_the_checksums(w, tmp_path):
    h = "a" * 64
    assert w.load_manifest(_manifest(tmp_path, {"ip_blacklist.txt": h})) == ("ok", {"ip_blacklist.txt": h})


def test_refusals_are_logged_once_per_state(w, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(w, "MANIFEST", str(tmp_path / "m.json"))
    refused = {}
    w.note_refusal(refused, "/config/x", 5.0, "why")
    w.note_refusal(refused, "/config/x", 5.0, "why")
    w.note_refusal(refused, "/config/x", 6.0, "why")
    assert capsys.readouterr().out.count("REFUSED") == 2


# ── the poll loop's jobs (SECURE-QUAL-01) ────────────────────────────────────
#
# main() was one 142-line function at cyclomatic complexity 36 and the tests
# loaded the module without running it, so none of these branches had a test.
# Each job is now a function of a small state object; these run them one by one.

class _Run:
    """A stand-in for subprocess.run that records calls and can be told to fail."""

    def __init__(self, returncodes=None, raises=None):
        self.calls = []
        self.returncodes = returncodes or {}
        self.raises = raises

    def __call__(self, argv, **_kw):
        self.calls.append(list(argv))
        if self.raises:
            raise self.raises
        rc = self.returncodes.get(argv[-1], 0)
        return types.SimpleNamespace(returncode=rc, stdout="", stderr=b"boom")


@pytest.fixture
def state(w, tmp_path, monkeypatch):
    trigger = tmp_path / ".reload-squid"
    monkeypatch.setattr(w, "RELOAD_TRIGGER", str(trigger))
    monkeypatch.setattr(w, "CLEAR_CACHE_TRIGGER", str(tmp_path / ".clear-cache"))
    monkeypatch.setattr(w, "PAIRS", [])
    monkeypatch.setattr(w, "resolved_ips", lambda: "1.1.1.1,2.2.2.2")
    monkeypatch.setattr(w, "promote_config", lambda: None)
    return w.WatchdogState(), trigger


def _touch_trigger(trigger, content="1788937285"):
    trigger.write_text(content)


def test_reload_generation_failure_keeps_the_running_config(w, state, monkeypatch):
    st, trigger = state
    _touch_trigger(trigger)
    run = _Run(returncodes={"/usr/local/bin/generate_squid_conf.sh": 2})
    results = []
    monkeypatch.setattr(w.subprocess, "run", run)
    monkeypatch.setattr(w, "write_result", lambda *a: results.append(a))

    w.check_reload_trigger(st)

    assert results == [("reload-squid", 1788937285, 2, None)]
    assert ["/usr/sbin/squid", "-k", "reconfigure"] not in run.calls
    assert st.mtimes[w.RELOAD_TRIGGER] == w.mtime(w.RELOAD_TRIGGER)  # consumed: the result reports the failure


def test_reload_refuses_a_config_that_does_not_parse(w, state, monkeypatch):
    st, trigger = state
    _touch_trigger(trigger)
    run = _Run()
    results = []
    monkeypatch.setattr(w.subprocess, "run", run)
    monkeypatch.setattr(w, "squid_config_ok", lambda *_a: False)
    monkeypatch.setattr(w, "write_result", lambda *a: results.append(a))

    w.check_reload_trigger(st)

    assert results == [("reload-squid", 1788937285, 0, 1)]
    assert ["/usr/sbin/squid", "-k", "reconfigure"] not in run.calls


def test_reload_success_reconfigures_and_acknowledges(w, state, monkeypatch):
    st, trigger = state
    _touch_trigger(trigger)
    run = _Run()
    results = []
    monkeypatch.setattr(w.subprocess, "run", run)
    monkeypatch.setattr(w, "squid_config_ok", lambda *_a: True)
    monkeypatch.setattr(w, "write_result", lambda *a: results.append(a))

    w.check_reload_trigger(st)

    assert results == [("reload-squid", 1788937285, 0, 0)]
    assert ["/usr/sbin/squid", "-k", "reconfigure"] in run.calls
    # An unchanged trigger is not acted on twice.
    run.calls.clear()
    w.check_reload_trigger(st)
    assert run.calls == []


def test_reload_exception_is_reported_and_retried_not_consumed(w, state, monkeypatch):
    """SECURE-ERR-01: an exception must leave the trigger unconsumed."""
    st, trigger = state
    _touch_trigger(trigger)
    results = []
    monkeypatch.setattr(w.subprocess, "run", _Run(raises=OSError("no squid")))
    monkeypatch.setattr(w, "write_result", lambda *a: results.append(a))
    before = st.mtimes[w.RELOAD_TRIGGER]

    w.check_reload_trigger(st)

    assert results == [("reload-squid", 1788937285, 1, None)]
    assert st.mtimes[w.RELOAD_TRIGGER] == before, "the failed attempt consumed the trigger"


def test_clear_cache_purges_and_falls_back_to_shutdown(w, state, monkeypatch, tmp_path):
    st, _ = state
    (tmp_path / ".clear-cache").write_text("x")
    run = _Run(returncodes={"purge": 1})
    monkeypatch.setattr(w.subprocess, "run", run)

    w.check_clear_cache_trigger(st)

    assert ["/usr/sbin/squid", "-k", "purge"] in run.calls
    assert ["/usr/sbin/squid", "-k", "shutdown"] in run.calls


def test_rotation_happens_once_per_day_change(w, state, monkeypatch):
    st, _ = state
    run = _Run()
    monkeypatch.setattr(w.subprocess, "run", run)
    st.last_rotate_day = -1
    w.rotate_logs_daily(st)
    w.rotate_logs_daily(st)
    assert run.calls.count(["/usr/sbin/squid", "-k", "rotate"]) == 1


def test_resolver_drift_regenerates_only_when_both_services_resolve(w, state, monkeypatch):
    st, _ = state
    run = _Run()
    monkeypatch.setattr(w.subprocess, "run", run)

    monkeypatch.setattr(w, "resolved_ips", lambda: "1.1.1.1,")  # waf not resolvable yet
    w.heal_resolver_drift(st)
    assert run.calls == [] and st.resolv_fp == "1.1.1.1,2.2.2.2"

    monkeypatch.setattr(w, "resolved_ips", lambda: "1.1.1.1,9.9.9.9")
    w.heal_resolver_drift(st)
    assert ["/usr/local/bin/generate_squid_conf.sh"] in run.calls
    assert st.resolv_fp == "1.1.1.1,9.9.9.9"


def test_logs_are_made_readable_and_a_missing_log_is_ignored(w, tmp_path, monkeypatch):
    real = tmp_path / "access.log"
    real.write_text("x")
    real.chmod(0o600)
    monkeypatch.setattr(w, "LOGS", [str(real), str(tmp_path / "absent.log")])
    w.keep_logs_readable()
    assert real.stat().st_mode & 0o777 == 0o644


def test_lists_sync_only_when_the_manifest_agrees(w, tmp_path, monkeypatch):
    src = tmp_path / "ip_blacklist.txt"
    dst = tmp_path / "local.txt"
    src.write_bytes(b"203.0.113.9\n")
    monkeypatch.setattr(w, "PAIRS", [(str(src), str(dst))])
    monkeypatch.setattr(w, "MANIFEST", str(tmp_path / "lists.manifest.json"))
    st = w.WatchdogState()
    st.mtimes[str(src)] = -1  # as if the file had just changed

    # A manifest that names the file with different bytes: refused, Squid keeps
    # what it had, and the change stays pending for the next poll.
    _manifest(tmp_path, {"ip_blacklist.txt": _sha(b"something else\n")})
    dst.write_bytes(b"previous\n")
    assert w.sync_lists(st) is False
    assert dst.read_bytes() == b"previous\n"
    assert st.mtimes[str(src)] == -1

    # The backend catches up: the same file now matches and is published.
    _manifest(tmp_path, {"ip_blacklist.txt": _sha(b"203.0.113.9\n")})
    assert w.sync_lists(st) is True
    assert dst.read_bytes() == b"203.0.113.9\n"
    assert w.sync_lists(st) is False  # unchanged since


def test_a_list_missing_from_the_manifest_is_refused(w, tmp_path, monkeypatch):
    src = tmp_path / "ip_blacklist.txt"
    src.write_bytes(b"x\n")
    monkeypatch.setattr(w, "PAIRS", [(str(src), str(tmp_path / "local.txt"))])
    monkeypatch.setattr(w, "MANIFEST", str(tmp_path / "lists.manifest.json"))
    st = w.WatchdogState()
    st.mtimes[str(src)] = -1
    _manifest(tmp_path, {"other.txt": "a" * 64})
    assert w.sync_lists(st) is False


def test_poll_once_runs_every_job_in_order(w, monkeypatch):
    order = []
    st = object()
    for name in ("touch_heartbeat", "heal_resolver_drift", "keep_logs_readable", "rotate_logs_daily",
                 "check_reload_trigger", "check_clear_cache_trigger"):
        monkeypatch.setattr(w, name, lambda *a, _n=name: order.append(_n))
    monkeypatch.setattr(w, "sync_lists", lambda s: order.append("sync_lists") or True)
    monkeypatch.setattr(w, "reconfigure_squid", lambda: order.append("reconfigure_squid"))

    w.poll_once(st)

    assert order == ["touch_heartbeat", "heal_resolver_drift", "keep_logs_readable", "rotate_logs_daily",
                     "check_reload_trigger", "check_clear_cache_trigger", "sync_lists", "reconfigure_squid"]


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))


# ── generate_checked: the live file is replaced only by a config that parses ──
#
# The generator used to write the live squid.conf in place and the parse check
# ran afterwards, so a refused config was already on disk for the next
# reconfigure or restart to load. The resolver-drift path did not check at all.

def _generating_run(next_path, content="new\n", gen_rc=0):
    run = _Run(returncodes={"/usr/local/bin/generate_squid_conf.sh": gen_rc})
    inner = run.__call__

    def call(argv, **kw):
        if list(argv) == ["/usr/local/bin/generate_squid_conf.sh"]:
            assert kw.get("env", {}).get("SQUID_CONF") == str(next_path), "the generator was pointed at the live file"
            next_path.write_text(content)
        return inner(argv, **kw)
    call.calls = run.calls
    return call


def test_generate_checked_keeps_the_live_file_when_the_new_one_does_not_parse(w, tmp_path, monkeypatch):
    live, nxt = tmp_path / "squid.conf", tmp_path / "squid.conf.next"
    live.write_text("old\n")
    monkeypatch.setattr(w, "SQUID_CONF", str(live))
    monkeypatch.setattr(w, "SQUID_CONF_NEXT", str(nxt))
    monkeypatch.setattr(w.subprocess, "run", _generating_run(nxt))
    monkeypatch.setattr(w, "squid_config_ok", lambda path=None: False)

    _, applied = w.generate_checked()

    assert applied is False
    assert live.read_text() == "old\n", "a config that does not parse replaced the live one"


def test_generate_checked_promotes_a_config_that_parses(w, tmp_path, monkeypatch):
    live, nxt = tmp_path / "squid.conf", tmp_path / "squid.conf.next"
    live.write_text("old\n")
    monkeypatch.setattr(w, "SQUID_CONF", str(live))
    monkeypatch.setattr(w, "SQUID_CONF_NEXT", str(nxt))
    monkeypatch.setattr(w.subprocess, "run", _generating_run(nxt))
    checked = []
    monkeypatch.setattr(w, "squid_config_ok", lambda path=None: checked.append(path) or True)

    _, applied = w.generate_checked()

    assert applied is True
    assert checked == [str(nxt)], "the parse check did not run on the new file"
    assert live.read_text() == "new\n" and not nxt.exists()


def test_resolver_drift_does_not_reconfigure_onto_a_refused_config(w, state, monkeypatch):
    st, _ = state
    run = _Run()
    monkeypatch.setattr(w.subprocess, "run", run)
    monkeypatch.setattr(w, "squid_config_ok", lambda *_a: False)
    monkeypatch.setattr(w, "resolved_ips", lambda: "1.1.1.1,9.9.9.9")

    w.heal_resolver_drift(st)

    assert ["/usr/local/bin/generate_squid_conf.sh"] in run.calls
    assert ["/usr/sbin/squid", "-k", "reconfigure"] not in run.calls


# ── refresh_domain_acl: Squid's own copy of the domain blacklist ─────────────

@pytest.fixture(autouse=True)
def acl_status(w, tmp_path, monkeypatch):
    """Every test writes the ACL status into its own directory, never /config."""
    path = tmp_path / "domain_acl_status.json"
    monkeypatch.setattr(w, "DOMAIN_ACL_STATUS", str(path))
    return path


def test_domain_acl_status_says_whether_squid_holds_the_list(w, tmp_path, monkeypatch, acl_status):
    # The backend cannot see SPM_SQUID_DOMAIN_ACL_MAX; the dashboard's "blocked
    # at DNS only" notice reads this file. Names are counted after normalizing,
    # the count the limit is applied to.
    src, dst = tmp_path / "local.txt", tmp_path / "squid.txt"
    monkeypatch.setattr(w, "DOMAIN_LIST", str(src))
    monkeypatch.setattr(w, "DOMAIN_ACL", str(dst))
    src.write_text("a.example\n*.a.example\nb.example\n")

    monkeypatch.setenv("SPM_SQUID_DOMAIN_ACL_MAX", "2")
    w.refresh_domain_acl()
    status = json.loads(acl_status.read_text())
    want = {"version": 1, "names": 2, "limit": 2, "held": True}
    assert {k: status[k] for k in want} == want
    assert isinstance(status["written_at"], int)

    monkeypatch.setenv("SPM_SQUID_DOMAIN_ACL_MAX", "1")
    w.refresh_domain_acl()
    status = json.loads(acl_status.read_text())
    assert (status["names"], status["limit"], status["held"]) == (2, 1, False)
    assert dst.read_text() == ""


def test_domain_acl_status_is_not_held_when_squids_file_cannot_be_written(w, tmp_path, monkeypatch, acl_status):
    src = tmp_path / "local.txt"
    monkeypatch.setattr(w, "DOMAIN_LIST", str(src))
    monkeypatch.setattr(w, "DOMAIN_ACL", str(tmp_path / "missing-dir" / "squid.txt"))
    monkeypatch.setenv("SPM_SQUID_DOMAIN_ACL_MAX", "10")
    src.write_text("a.example\n")
    w.refresh_domain_acl()
    status = json.loads(acl_status.read_text())
    assert (status["names"], status["limit"], status["held"]) == (1, 10, False)


def test_domain_acl_holds_the_list_up_to_the_limit_and_nothing_above(w, tmp_path, monkeypatch):
    src, dst = tmp_path / "local.txt", tmp_path / "squid.txt"
    monkeypatch.setattr(w, "DOMAIN_LIST", str(src))
    monkeypatch.setattr(w, "DOMAIN_ACL", str(dst))
    src.write_text("a.example\nb.example\n")

    monkeypatch.setenv("SPM_SQUID_DOMAIN_ACL_MAX", "2")
    w.refresh_domain_acl()
    assert dst.read_text() == "a.example\nb.example\n"

    # Over the limit, Squid must not load it: a reconfigure with millions of
    # dstdomain entries exhausted the proxy's memory limit.
    monkeypatch.setenv("SPM_SQUID_DOMAIN_ACL_MAX", "1")
    w.refresh_domain_acl()
    assert dst.read_text() == ""
    assert not (tmp_path / "squid.txt.tmp").exists()


def test_domain_acl_holds_exact_names_once(w, tmp_path, monkeypatch):
    # "*.name" is a literal host to dstdomain and never matched; dnsmasq blocks
    # the exact name, so Squid must hold that name.
    src, dst = tmp_path / "local.txt", tmp_path / "squid.txt"
    monkeypatch.setattr(w, "DOMAIN_LIST", str(src))
    monkeypatch.setattr(w, "DOMAIN_ACL", str(dst))
    monkeypatch.setenv("SPM_SQUID_DOMAIN_ACL_MAX", "10")
    src.write_text("*.Evil.example\nevil.example\n.other.example\n# note\n\nthird.example # x\n")
    w.refresh_domain_acl()
    assert dst.read_text() == "evil.example\nother.example\nthird.example\n"


def test_domain_acl_limit_counts_names_after_normalizing(w, tmp_path, monkeypatch):
    src, dst = tmp_path / "local.txt", tmp_path / "squid.txt"
    monkeypatch.setattr(w, "DOMAIN_LIST", str(src))
    monkeypatch.setattr(w, "DOMAIN_ACL", str(dst))
    monkeypatch.setenv("SPM_SQUID_DOMAIN_ACL_MAX", "1")
    src.write_text("*.a.example\na.example\n")
    w.refresh_domain_acl()
    assert dst.read_text() == "a.example\n"


# ── IP ACL files: collapsed, so Squid has no covered entry to warn about ─────

def test_ip_lines_collapse_to_the_covering_networks(w):
    lines = ["10.200.0.0/16", "10.200.3.7", "10.200.3.0/24", "192.0.2.0/25", "192.0.2.128/25",
             "198.51.100.9", "198.51.100.9", "2001:db8::/32", "2001:db8::1", "# comment", "",
             "203.0.113.5 # trailing note", "not-an-ip", "10.0.0.0/33"]
    out, bad = w.normalize_ip_lines(lines)
    assert out == ["10.200.0.0/16", "192.0.2.0/24", "198.51.100.9", "203.0.113.5", "2001:db8::/32"]
    assert bad == 2


def test_ip_lines_match_the_same_destinations(w):
    import ipaddress
    lines = [f"10.1.{i}.{j}" for i in range(4) for j in range(256)] + ["10.1.4.0/22", "172.16.5.5"]
    out, _ = w.normalize_ip_lines(lines)
    before = {ipaddress.ip_address(a) for net in lines for a in ipaddress.ip_network(net)}
    after = {ipaddress.ip_address(a) for net in out for a in ipaddress.ip_network(net)}
    assert before == after
    assert out == ["10.1.0.0/21", "172.16.5.5"]


def test_a_synced_ip_list_is_collapsed_and_others_are_copied_verbatim(w, state, tmp_path, monkeypatch):
    st, _ = state
    ip_src, ip_dst = tmp_path / "ip_blacklist.txt", tmp_path / "ip_local.txt"
    dom_src, dom_dst = tmp_path / "dst_allow_domain.txt", tmp_path / "dom_local.txt"
    ip_src.write_text("10.0.0.0/8\n10.1.2.3\n")
    dom_src.write_text(".example.com\n")
    monkeypatch.setattr(w, "IP_ACL_FILES", {str(ip_dst)})
    monkeypatch.setattr(w, "load_manifest", lambda: None)
    monkeypatch.setattr(w, "expected_checksum", lambda *a: (True, None))
    st.mtimes = {str(ip_src): None, str(dom_src): None}
    assert w.sync_list(st, str(ip_src), str(ip_dst), None)
    assert w.sync_list(st, str(dom_src), str(dom_dst), None)
    assert ip_dst.read_text() == "10.0.0.0/8\n"
    assert dom_dst.read_text() == ".example.com\n"


def test_normalize_cli_rewrites_ip_files_and_skips_missing_ones(w, tmp_path):
    f = tmp_path / "list.txt"
    f.write_text("192.0.2.1\n192.0.2.0/24\n")
    assert w.normalize_cli(["ip", str(f), str(tmp_path / "absent.txt")]) == 0
    assert f.read_text() == "192.0.2.0/24\n"
    assert w.normalize_cli(["bogus"]) == 2


def test_a_list_sync_refreshes_the_domain_acl_before_reconfiguring(w, state, monkeypatch):
    st, _ = state
    calls = []
    monkeypatch.setattr(w, "sync_lists", lambda s: True)
    monkeypatch.setattr(w, "refresh_domain_acl", lambda: calls.append("acl"))
    monkeypatch.setattr(w, "reconfigure_squid", lambda: calls.append("reconfigure"))
    for job in ("touch_heartbeat", "heal_resolver_drift", "keep_logs_readable", "rotate_logs_daily",
                "check_reload_trigger", "check_clear_cache_trigger"):
        monkeypatch.setattr(w, job, lambda *a: None)
    w.poll_once(st)
    assert calls == ["acl", "reconfigure"]
