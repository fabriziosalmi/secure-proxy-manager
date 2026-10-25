"""Cache statistics collection in proxy/blacklist_watchdog.py.

The watchdog used to call /usr/sbin/squidclient, which is not in the image, so
/config/cache_stats.txt was never written and the UI could only say "not
collected". It now reads Squid's cache manager info page from localhost and
writes /config/cache_stats.json.

The fixtures are pages captured from Squid 7.7 in the proxy image:
  squid_7.7_info.txt        info at 210 s of uptime, after cacheable traffic
  squid_7.7_info_at_8s.txt  info at 8 s, after 12 hits: Squid prints 0.0%
  squid_7.7_storedir.txt    storedir of the same proxy (cache_dir 50 MB)
"""
import http.server
import json
import os
import re
import socket
import threading
import types
import urllib.error

import pytest

HERE = os.path.dirname(__file__)
WATCHDOG = os.path.join(HERE, "..", "..", "proxy", "blacklist_watchdog.py")
FIXTURES = os.path.join(HERE, "fixtures")


def fixture(name):
    with open(os.path.join(FIXTURES, name), encoding="utf-8") as f:
        return f.read()


def load_watchdog():
    """Import the definitions without starting the poll loop."""
    src = open(WATCHDOG).read().split("def main()")[0]
    mod = types.ModuleType("watchdog_cache_stats_under_test")
    mod.__dict__["__file__"] = WATCHDOG
    exec(compile(src, WATCHDOG, "exec"), mod.__dict__)  # noqa: S102
    return mod


@pytest.fixture(scope="module")
def w():
    return load_watchdog()


# ── the parser, on what Squid 7.7 printed ────────────────────────────────────

def test_info_page_of_squid_7_7_is_read_field_by_field(w):
    got = w.parse_squid_info(fixture("squid_7.7_info.txt"))
    assert got == {
        "request_hit_ratio_5min_pct": 64.7, "request_hit_ratio_60min_pct": 64.7,
        "byte_hit_ratio_5min_pct": 91.6, "byte_hit_ratio_60min_pct": 91.6,
        "disk_used_kb": 252, "disk_used_pct": 0.5,
        "memory_used_kb": 468, "memory_used_pct": 0.2,
        "uptime_s": 210.475,
        "store_entries": 64, "memory_objects": 11, "disk_objects": 11,
    }


def test_ratios_before_squids_first_sample_are_absent_not_zero(w):
    """At 8 s Squid had served 12 hits and printed "5min: 0.0%": it samples its
    counters once a minute and has no window yet. The sizes are real."""
    text = fixture("squid_7.7_info_at_8s.txt")
    assert "Hits as % of all requests:\t5min: 0.0%, 60min: 0.0%" in text
    got = w.parse_squid_info(text)
    for key in ("request_hit_ratio_5min_pct", "request_hit_ratio_60min_pct",
                "byte_hit_ratio_5min_pct", "byte_hit_ratio_60min_pct"):
        assert got[key] is None, key
    assert got["uptime_s"] == 8.365
    assert got["disk_used_kb"] == 220 and got["memory_used_kb"] == 436 and got["store_entries"] == 56


def test_a_field_squid_did_not_print_is_none_never_zero(w):
    got = w.parse_squid_info("\tStorage Swap size:\t220 KB\n\tUP Time:\t300.0 seconds\n")
    assert got["disk_used_kb"] == 220
    assert all(v is None for k, v in got.items() if k not in ("disk_used_kb", "uptime_s")), got


def test_the_format_the_backend_used_to_expect_is_not_read(w):
    """No Squid in the image prints these: the old parser read nothing."""
    got = w.parse_squid_info("Request Hit Ratios:\t5min: 42.3%, 60min: 38.1%\n"
                             "StoreEntries                : 1234\n\tUP Time:\t300.0 seconds\n")
    assert got["request_hit_ratio_5min_pct"] is None and got["store_entries"] is None


def test_a_negative_byte_hit_ratio_is_kept_as_squid_printed_it(w):
    got = w.parse_squid_info("\tHits as % of bytes sent:\t5min: -3.5%, 60min: -0.0%\n\tUP Time:\t300.0 seconds\n")
    assert got["byte_hit_ratio_5min_pct"] == -3.5
    assert got["byte_hit_ratio_60min_pct"] == 0.0


def test_storedir_gives_the_disk_capacity(w):
    assert w.parse_squid_storedir(fixture("squid_7.7_storedir.txt")) == 51200
    assert w.parse_squid_storedir("") is None
    two = "Maximum Swap Size      : 51200 KB\nMaximum Swap Size      : 1024 KB\n"
    assert w.parse_squid_storedir(two) is None


def test_the_manager_port_follows_squid_conf(w, tmp_path):
    conf = tmp_path / "squid.conf"
    conf.write_text("# http_port 9\nhttp_port 3129 ssl-bump \\\n  cert=/x\n")
    assert w.squid_http_port(str(conf)) == 3129
    conf.write_text("http_port 0.0.0.0:8080\n")
    assert w.squid_http_port(str(conf)) == 8080
    assert w.squid_http_port(str(tmp_path / "absent.conf")) == 3128


def test_the_backend_reads_every_field_the_watchdog_writes(w):
    """backend-go/internal/handlers/cache_stats.go decodes the file by name: a
    field renamed on one side only would arrive as null."""
    go = open(os.path.join(HERE, "..", "..", "backend-go", "internal", "handlers", "cache_stats.go")).read()
    tags = set(re.findall(r'json:"([a-z0-9_]+)"', go))
    written = {"version", "collected_at", "interval_s", "disk_capacity_kb", *w.CACHE_STATS_FIELDS}
    assert written <= tags, sorted(written - tags)


# ── fetch: a real HTTP request to 127.0.0.1 ──────────────────────────────────

class _FakeCacheManager(http.server.BaseHTTPRequestHandler):
    pages = {}

    def do_GET(self):  # noqa: N802 - the stdlib's name
        body = self.pages.get(self.path)
        if body is None:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(body.encode())

    def log_message(self, *_a):
        pass


@pytest.fixture
def manager():
    _FakeCacheManager.pages = {"/squid-internal-mgr/info": fixture("squid_7.7_info.txt")}
    srv = http.server.HTTPServer(("127.0.0.1", 0), _FakeCacheManager)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield srv.server_address[1]
    srv.shutdown()
    srv.server_close()


def test_fetch_reads_the_page_from_localhost_and_ignores_proxy_settings(w, manager, monkeypatch):
    # An http_proxy in the environment must not route the request through it.
    # urllib reads the environment when the opener is built, at import: so the
    # module is imported again with the variables set.
    monkeypatch.setenv("http_proxy", "http://192.0.2.1:9")
    monkeypatch.setenv("HTTP_PROXY", "http://192.0.2.1:9")
    monkeypatch.delenv("no_proxy", raising=False)
    monkeypatch.delenv("NO_PROXY", raising=False)
    w = load_watchdog()
    monkeypatch.setattr(w, "CACHE_MGR_TIMEOUT", 2)
    assert w.fetch_cache_manager("info", manager) == fixture("squid_7.7_info.txt")
    with pytest.raises(urllib.error.HTTPError):
        w.fetch_cache_manager("menu", manager)


def test_fetch_gives_up_after_the_timeout(w, monkeypatch):
    silent = socket.socket()
    silent.bind(("127.0.0.1", 0))
    silent.listen(1)  # accepts the connection, never answers
    monkeypatch.setattr(w, "CACHE_MGR_TIMEOUT", 0.3)
    try:
        with pytest.raises(OSError):
            w.fetch_cache_manager("info", silent.getsockname()[1])
    finally:
        silent.close()


# ── collection: interval, atomic write, failures ─────────────────────────────

class _Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


@pytest.fixture
def collector(w, tmp_path, monkeypatch):
    """A state, a fake cache manager serving the fixtures, and a clock."""
    out = tmp_path / "config" / "cache_stats.json"
    out.parent.mkdir()
    conf = tmp_path / "squid.conf"
    conf.write_text("http_port 3128\n")
    old = 1_700_000_000
    os.utime(conf, (old, old))
    monkeypatch.setattr(w, "CACHE_STATS", str(out))
    monkeypatch.setattr(w, "SQUID_CONF", str(conf))
    pages = {"info": fixture("squid_7.7_info.txt"), "storedir": fixture("squid_7.7_storedir.txt")}
    fetched = []

    def fetch(page, port):
        fetched.append(page)
        body = pages[page]
        if isinstance(body, Exception):
            raise body
        return body

    monkeypatch.setattr(w, "fetch_cache_manager", fetch)
    clock = _Clock()
    monkeypatch.setattr(w.time, "monotonic", clock)
    st = types.SimpleNamespace(cache_stats_due=0.0, cache_stats_problem=None,
                               disk_capacity_kb=None, disk_capacity_conf=None)
    return types.SimpleNamespace(st=st, out=out, conf=conf, pages=pages, fetched=fetched, clock=clock)


def test_a_collection_writes_the_raw_numbers_and_when_they_were_collected(w, collector):
    c = collector
    before = int(w.time.time())
    assert w.collect_cache_stats(c.st) is True
    doc = json.loads(c.out.read_text())
    assert doc["version"] == 1 and doc["interval_s"] == 60
    assert before <= doc["collected_at"] <= int(w.time.time())
    assert doc["request_hit_ratio_60min_pct"] == 64.7 and doc["disk_used_kb"] == 252
    assert doc["disk_capacity_kb"] == 51200
    assert set(doc) == {"version", "collected_at", "interval_s", "disk_capacity_kb", *w.CACHE_STATS_FIELDS}
    assert c.out.stat().st_mode & 0o777 == 0o644  # the backend runs as another user
    assert os.listdir(c.out.parent) == ["cache_stats.json"]


def test_collection_runs_once_per_interval_not_every_poll(w, collector):
    c = collector
    assert w.collect_cache_stats(c.st) is True
    c.fetched.clear()
    for _ in range(29):  # the 2 s polls of the next minute
        c.clock.t += 2
        assert w.collect_cache_stats(c.st) is False
    assert c.fetched == []
    c.clock.t += 2
    assert w.collect_cache_stats(c.st) is True
    # The capacity is read again only when squid.conf changes: each fetch is a
    # request Squid counts in its hit ratio.
    assert c.fetched == ["info"]


def test_the_capacity_is_read_again_after_squid_conf_changes(w, collector):
    c = collector
    w.collect_cache_stats(c.st)
    c.pages["storedir"] = c.pages["storedir"].replace("51200 KB", "102400 KB")
    os.utime(c.conf, None)  # regenerated just now
    for _ in range(2):  # a config younger than one interval may not be loaded yet
        c.clock.t += 60
        c.fetched.clear()
        w.collect_cache_stats(c.st)
        assert c.fetched == ["info", "storedir"]
    assert json.loads(c.out.read_text())["disk_capacity_kb"] == 102400
    old = int(w.time.time()) - 120
    os.utime(c.conf, (old, old))
    c.clock.t += 60
    c.fetched.clear()
    w.collect_cache_stats(c.st)
    assert c.fetched == ["info", "storedir"]
    c.clock.t += 60
    c.fetched.clear()
    w.collect_cache_stats(c.st)
    assert c.fetched == ["info"]


def test_a_failed_fetch_keeps_the_last_file_and_is_logged_once(w, collector, capsys):
    c = collector
    w.collect_cache_stats(c.st)
    written = c.out.read_text()
    capsys.readouterr()
    c.pages["info"] = urllib.error.URLError(ConnectionRefusedError(111, "Connection refused"))
    for _ in range(3):
        c.clock.t += 60
        assert w.collect_cache_stats(c.st) is False
    assert c.out.read_text() == written  # its collected_at now ages: the backend says out of date
    log = capsys.readouterr().out
    assert log.count("cache statistics not collected: info: URLError") == 1, log
    c.pages["info"] = fixture("squid_7.7_info.txt")
    c.clock.t += 60
    assert w.collect_cache_stats(c.st) is True
    assert capsys.readouterr().out.count("cache statistics: collected") == 1


def test_an_info_page_without_any_field_is_not_written(w, collector, capsys):
    c = collector
    c.pages["info"] = "<html>Access Denied</html>"
    assert w.collect_cache_stats(c.st) is False
    assert not c.out.exists()
    assert "none of the expected fields" in capsys.readouterr().out


def test_without_storedir_the_capacity_is_absent_and_the_rest_written(w, collector, capsys):
    c = collector
    c.pages["storedir"] = TimeoutError("timed out")
    assert w.collect_cache_stats(c.st) is True
    doc = json.loads(c.out.read_text())
    assert doc["disk_capacity_kb"] is None
    assert doc["disk_used_kb"] == 252
    assert "storedir: TimeoutError" in capsys.readouterr().out
    c.pages["storedir"] = fixture("squid_7.7_storedir.txt")
    c.clock.t += 60
    w.collect_cache_stats(c.st)
    assert json.loads(c.out.read_text())["disk_capacity_kb"] == 51200


def test_a_failed_write_leaves_the_previous_file_whole(w, collector, monkeypatch):
    c = collector
    w.collect_cache_stats(c.st)
    written = c.out.read_text()

    def refuse(*_a):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(w.os, "replace", refuse)
    c.clock.t += 60
    assert w.collect_cache_stats(c.st) is False
    assert c.out.read_text() == written
    assert os.listdir(c.out.parent) == ["cache_stats.json"]  # no temporary file left behind


def test_a_poll_survives_any_collection_failure(w, collector, monkeypatch):
    """poll_once runs the collection last; whatever the fetch raises, the
    loop must reach the next tick."""
    c = collector
    for exc in (urllib.error.URLError("refused"), TimeoutError("timed out"), ConnectionResetError(),
                w.http.client.RemoteDisconnected("closed")):
        c.pages["info"] = exc
        c.clock.t += 60
        assert w.collect_cache_stats(c.st) is False
