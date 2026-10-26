"""Tests for the generated Squid error pages (issue #443)."""

# ruff: noqa: S101

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import re
import shutil
import subprocess

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "generate-error-pages.py"
ERROR_PAGES_DIR = REPO_ROOT / "proxy" / "error-pages"
REPO_URL = "https://github.com/fabriziosalmi/secure-proxy-manager"
FORBIDDEN_NON_POLICY_RE = re.compile(r"\b(blocked|policy|denied|restricted)\b", re.IGNORECASE)
TITLE_RE = re.compile(r"<title>(.*?)</title>", re.DOTALL)
STYLE_RE = re.compile(r"<style>.*?</style>", re.DOTALL)
EXTERNAL_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)

# Canonical ERR_ACCESS_DENIED on main (blob b7e2ace in commit 8f9734c).
MAIN_ERR_ACCESS_DENIED_B7E2ACE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Access Denied: Secure Proxy Manager</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
    background: #0a0a0a;
    color: #e2e8f0;
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
  }
  .container {
    text-align: center;
    max-width: 520px;
    padding: 2rem;
  }
  .shield {
    width: 80px;
    height: 80px;
    margin: 0 auto 1.5rem;
    opacity: 0.9;
  }
  .shield svg { width: 100%; height: 100%; }
  h1 {
    font-size: 1.5rem;
    font-weight: 700;
    color: #f1f5f9;
    margin-bottom: 0.5rem;
  }
  .status {
    display: inline-block;
    background: rgba(239, 68, 68, 0.15);
    color: #ef4444;
    border: 1px solid rgba(239, 68, 68, 0.3);
    padding: 0.25rem 0.75rem;
    border-radius: 9999px;
    font-size: 0.75rem;
    font-weight: 600;
    letter-spacing: 0.05em;
    margin-bottom: 1.5rem;
  }
  .message {
    color: #94a3b8;
    font-size: 0.9rem;
    line-height: 1.6;
    margin-bottom: 1.5rem;
  }
  .detail-box {
    background: #111827;
    border: 1px solid #1e293b;
    border-radius: 8px;
    padding: 1rem;
    margin-bottom: 1.5rem;
    text-align: left;
  }
  .detail-row {
    display: flex;
    justify-content: space-between;
    padding: 0.35rem 0;
    font-size: 0.8rem;
  }
  .detail-label { color: #64748b; }
  .detail-value { color: #cbd5e1; font-family: 'SF Mono', 'Fira Code', monospace; font-size: 0.75rem; max-width: 280px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .divider {
    border-top: 1px solid #1e293b;
    margin: 1.5rem 0 1rem;
  }
  .footer {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 0.5rem;
    color: #475569;
    font-size: 0.7rem;
  }
  .footer a {
    color: #3b82f6;
    text-decoration: none;
    font-weight: 500;
  }
  .footer a:hover { text-decoration: underline; }
  .credits {
    color: #334155;
    font-size: 0.65rem;
    margin-top: 0.75rem;
  }
</style>
</head>
<body>
<div class="container">
  <div class="shield">
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" fill="none">
      <path d="M29 4 L35 4 L36.5 10.2 C38.8 10.9 40.9 11.9 42.8 13.2 L48.4 9.8 L52.2 13.6 L48.8 19.2 C50.1 21.1 51.1 23.2 51.8 25.5 L58 27 L58 33 L51.8 34.5 C51.1 36.8 50.1 38.9 48.8 40.8 L52.2 46.4 L48.4 50.2 L42.8 46.8 C40.9 48.1 38.8 49.1 36.5 49.8 L35 56 L29 56 L27.5 49.8 C25.2 49.1 23.1 48.1 21.2 46.8 L15.6 50.2 L11.8 46.4 L15.2 40.8 C13.9 38.9 12.9 36.8 12.2 34.5 L6 33 L6 27 L12.2 25.5 C12.9 23.2 13.9 21.1 15.2 19.2 L11.8 13.6 L15.6 9.8 L21.2 13.2 C23.1 11.9 25.2 10.9 27.5 10.2 Z" fill="#1e293b" stroke="#3b82f6" stroke-width="1.2"/>
      <circle cx="32" cy="30" r="12" fill="#0f172a" stroke="#3b82f6" stroke-width="1.2"/>
      <circle cx="32" cy="30" r="8" fill="#1e3a5f"/>
      <circle cx="32" cy="30" r="6" fill="none" stroke="#3b82f6" stroke-width="1" opacity="0.5"/>
      <circle cx="32" cy="30" r="4.5" fill="#3b82f6"/>
      <circle cx="32" cy="30" r="2" fill="#0f172a"/>
      <circle cx="34" cy="28" r="1.8" fill="#93c5fd" opacity="0.9"/>
      <circle cx="30.5" cy="32" r="0.8" fill="#93c5fd" opacity="0.5"/>
    </svg>
  </div>

  <h1>Access Denied</h1>
  <div class="status">BLOCKED BY PROXY</div>

  <p class="message">
    This request has been blocked by the security proxy.
    The destination is restricted by your network policy.
  </p>

  <div class="detail-box">
    <div class="detail-row">
      <span class="detail-label">Destination</span>
      <span class="detail-value">%U</span>
    </div>
    <div class="detail-row">
      <span class="detail-label">Client IP</span>
      <span class="detail-value">%a</span>
    </div>
    <div class="detail-row">
      <span class="detail-label">Time</span>
      <span class="detail-value">%T</span>
    </div>
  </div>

  <div class="divider"></div>

  <div class="footer">
    <span>Protected by</span>
    <a href="https://github.com/fabriziosalmi/secure-proxy-manager" target="_blank">Secure Proxy Manager</a>
  </div>
  <div class="credits">
    Built with care by Fabrizio Salmi, Claude &amp; Gemini
  </div>
</div>
<script>
// XSS protection: sanitize any Squid-injected variables
document.querySelectorAll('.detail-value').forEach(function(el){
  el.textContent = el.textContent;
});
</script>
</body>
</html>
"""  # noqa: E501


def load_generator():
    spec = importlib.util.spec_from_file_location("generate_error_pages", SCRIPT_PATH)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_generation_matches_committed_files():
    gen = load_generator()
    errors = gen.check_files(ERROR_PAGES_DIR)
    assert errors == [], (
        "proxy/error-pages/ is out of sync with scripts/generate-error-pages.py:\n  "
        + "\n  ".join(errors)
    )


def test_access_denied_matches_main_b7e2ace():
    """ERR_ACCESS_DENIED matches main (b7e2ace) except xmlns removal, %a -> %i for Client IP, and F3/F4 CSS."""
    if shutil.which("git"):
        chk = subprocess.run(
            ["git", "cat-file", "-e", "b7e2ace"],
            cwd=REPO_ROOT,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        if chk.returncode == 0:
            blob = subprocess.run(
                ["git", "show", "b7e2ace"],
                cwd=REPO_ROOT,
                capture_output=True,
                text=True,
                check=True,
            ).stdout
            assert blob == MAIN_ERR_ACCESS_DENIED_B7E2ACE

    actual = (ERROR_PAGES_DIR / "ERR_ACCESS_DENIED").read_text(encoding="utf-8")

    # On main (b7e2ace), the "Client IP" row used Squid token %a (authenticated
    # user identity, which renders "-" without proxy login or the username with
    # proxy login) instead of %i (the client IP address). We replace %a with %i
    # so the "Client IP" row renders the client IP.
    expected_outside_style = STYLE_RE.sub(
        "<style></style>",
        MAIN_ERR_ACCESS_DENIED_B7E2ACE.replace(
            '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" fill="none">',
            '<svg viewBox="0 0 64 64" fill="none">',
            1,
        ).replace(
            '<span class="detail-label">Client IP</span>\n      <span class="detail-value">%a</span>',
            '<span class="detail-label">Client IP</span>\n      <span class="detail-value">%i</span>',
            1,
        ),
        count=1,
    )
    actual_outside_style = STYLE_RE.sub("<style></style>", actual, count=1)
    assert actual_outside_style == expected_outside_style, (
        "ERR_ACCESS_DENIED differs from main (b7e2ace) outside <style> by more than xmlns removal and %a -> %i"
    )

    expected_style = (
        STYLE_RE.search(MAIN_ERR_ACCESS_DENIED_B7E2ACE)
        .group(0)
        .replace(
            "  .container {\n    text-align: center;\n    max-width: 520px;\n    padding: 2rem;\n  }",
            (
                "  .container {\n    text-align: center;\n    width: 100%;\n"
                "    max-width: 520px;\n    min-width: 0;\n    padding: 2rem;\n  }"
            ),
            1,
        )
        .replace(
            "    letter-spacing: 0.05em;\n    margin-bottom: 1.5rem;\n  }",
            (
                "    letter-spacing: 0.05em;\n    margin-bottom: 1.5rem;\n  }\n"
                "  .status-amber {\n    background: rgba(245, 158, 11, 0.15);\n"
                "    color: #f59e0b;\n    border-color: rgba(245, 158, 11, 0.3);\n  }"
            ),
            1,
        )
        .replace(
            (
                "  .detail-row {\n    display: flex;\n    justify-content: space-between;\n"
                "    padding: 0.35rem 0;\n    font-size: 0.8rem;\n  }"
            ),
            (
                "  .detail-row {\n    display: flex;\n    justify-content: space-between;\n"
                "    gap: 1rem;\n    padding: 0.35rem 0;\n    font-size: 0.8rem;\n  }"
            ),
            1,
        )
        .replace(
            "  .detail-label { color: #64748b; }",
            "  .detail-label { color: #64748b; flex-shrink: 0; }",
            1,
        )
        .replace(
            "max-width: 280px; overflow: hidden;",
            "min-width: 0; overflow: hidden;",
            1,
        )
    )
    actual_style = STYLE_RE.search(actual).group(0)
    assert actual_style == expected_style, (
        "ERR_ACCESS_DENIED <style> differs from main (b7e2ace) + F3/F4 additions"
    )


def _check_single_page(code: str, text: str, kind: str) -> list[str]:
    errs: list[str] = []
    if kind != "policy":
        found_words = sorted({w.lower() for w in FORBIDDEN_NON_POLICY_RE.findall(text)})
        if found_words:
            errs.append(f"{code} (kind={kind}): contains policy words {found_words}")
        if '<div class="status status-amber">' not in text:
            errs.append(
                f'{code} (kind={kind}): non-policy page must use amber badge <div class="status status-amber">'
            )
    elif '<div class="status">' not in text:
        errs.append(f'{code} (kind=policy): missing red badge <div class="status">')

    if "max-width: 280px" in text:
        errs.append(f"{code}: contains fixed 'max-width: 280px' causing 390px overflow")
    if "flex-shrink: 0" not in text or "gap: 1rem" not in text:
        errs.append(f"{code}: missing responsive .detail-row/.detail-label CSS rules")
    if "squid/" in text.lower():
        errs.append(f"{code}: contains 'squid/'")
    if "src=" in text.lower():
        errs.append(f"{code}: contains 'src='")

    bad_urls = [u for u in EXTERNAL_URL_RE.findall(text) if u != REPO_URL]
    if bad_urls:
        errs.append(f"{code}: contains external URL(s) {bad_urls}")

    req = ("%U", "%i", "%T") if code == "ERR_ACCESS_DENIED" else ("%U", "%T", "%c")
    forb = ("%a", "%c") if code == "ERR_ACCESS_DENIED" else ("%a", "%i")
    errs.extend(f"{code}: missing Squid token {t}" for t in req if t not in text)
    errs.extend(f"{code}: unexpected Squid token {t}" for t in forb if t in text)
    return errs


def test_content_invariants():
    gen = load_generator()
    kind_by_code = {code: kind for code, kind, _, _, _ in gen.PAGES}
    disk_files = sorted(p for p in ERROR_PAGES_DIR.iterdir() if p.is_file())
    assert disk_files, "no files found in proxy/error-pages/"

    titles: dict[str, list[str]] = {}
    violations: list[str] = []

    for path in disk_files:
        code = path.name
        text = path.read_text(encoding="utf-8")
        kind = kind_by_code.get(code)
        if kind is None:
            violations.append(f"{code}: not listed in PAGES")
            continue

        m = TITLE_RE.search(text)
        if not m or not m.group(1).strip():
            violations.append(f"{code}: missing <title>")
        else:
            titles.setdefault(m.group(1).strip(), []).append(code)

        violations.extend(_check_single_page(code, text, kind))

    duplicate_titles = {t: codes for t, codes in titles.items() if len(codes) > 1}
    for title, codes in sorted(duplicate_titles.items()):
        violations.append(f"duplicate <title>{title}</title> shared by: {', '.join(codes)}")

    assert violations == [], "content violations in proxy/error-pages/:\n  " + "\n  ".join(violations)


def _squid_templates_from_env_or_image() -> list[str] | None:
    env_dir = os.environ.get("SQUID_ERRORS_DIR")
    if env_dir and Path(env_dir).is_dir():
        return sorted(p.name for p in Path(env_dir).iterdir() if p.is_file())
    local_dir = Path("/usr/share/squid/errors/en")
    if local_dir.is_dir():
        return sorted(p.name for p in local_dir.iterdir() if p.is_file())
    image = os.environ.get("SQUID_TEST_IMAGE", "spm-proxy-test")
    if shutil.which("docker"):
        insp = subprocess.run(
            ["docker", "image", "inspect", image],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        if insp.returncode == 0:
            res = subprocess.run(
                ["docker", "run", "--rm", "--entrypoint", "/bin/ls", image, "-1", "/usr/share/squid/errors/en"],
                capture_output=True,
                text=True,
                check=True,
            )
            return sorted(line.strip() for line in res.stdout.splitlines() if line.strip())
    return None


def test_coverage_against_squid_templates():
    # Authoritative check in CI is tests/shell/generate_squid_conf_test.sh:488,
    # which runs inside the built proxy image and pins count=43 against
    # /usr/share/squid/errors/en. When neither /usr/share/squid/errors/en nor
    # the proxy test image is available (e.g. the standalone test-python runner),
    # skip explicitly instead of passing silently.
    gen = load_generator()
    page_codes = [code for code, _, _, _, _ in gen.PAGES]
    assert len(page_codes) == len(set(page_codes)), "duplicate codes in PAGES"

    stock_names = set(gen.STOCK_FILES)
    overlap = set(page_codes) & stock_names
    assert not overlap, f"templates in both PAGES and STOCK_FILES: {sorted(overlap)}"

    disk_names = {p.name for p in ERROR_PAGES_DIR.iterdir() if p.is_file()}
    missing_on_disk = sorted(set(page_codes) - disk_names)
    assert not missing_on_disk, f"templates in PAGES but missing in proxy/error-pages/: {missing_on_disk}"

    squid_templates = _squid_templates_from_env_or_image()
    if squid_templates is None:
        image = os.environ.get("SQUID_TEST_IMAGE", "spm-proxy-test")
        pytest.skip(
            "Squid templates not available via SQUID_ERRORS_DIR, /usr/share/squid/errors/en, "
            f"or docker image {image!r}; authoritative check runs in "
            "tests/shell/generate_squid_conf_test.sh (count=43)"
        )

    covered_spm = set(page_codes) & disk_names
    uncovered = sorted(set(squid_templates) - covered_spm - stock_names)
    stale = sorted((set(page_codes) | stock_names) - set(squid_templates))
    assert not uncovered, (
        f"Squid templates in /usr/share/squid/errors/en without SPM page ({len(uncovered)}): "
        + ", ".join(uncovered)
    )
    assert not stale, f"entries in PAGES/STOCK_FILES not present in /usr/share/squid/errors/en: {stale}"
