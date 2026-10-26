"""Tests for the generated Squid error pages (issue #443)."""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import re
import shutil
import subprocess

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "generate-error-pages.py"
ERROR_PAGES_DIR = REPO_ROOT / "proxy" / "error-pages"
REPO_URL = "https://github.com/fabriziosalmi/secure-proxy-manager"
FORBIDDEN_NON_POLICY_RE = re.compile(r"\b(blocked|policy|denied|restricted)\b", re.IGNORECASE)
TITLE_RE = re.compile(r"<title>(.*?)</title>", re.DOTALL)
EXTERNAL_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)


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

        if kind != "policy":
            found_words = sorted({w.lower() for w in FORBIDDEN_NON_POLICY_RE.findall(text)})
            if found_words:
                violations.append(f"{code} (kind={kind}): contains policy words {found_words}")

        if "squid/" in text.lower():
            violations.append(f"{code}: contains 'squid/'")

        if "src=" in text.lower():
            violations.append(f"{code}: contains 'src='")

        urls = EXTERNAL_URL_RE.findall(text)
        bad_urls = [u for u in urls if u != REPO_URL]
        if bad_urls:
            violations.append(f"{code}: contains external URL(s) {bad_urls}")

        for token in ("%U", "%T", "%c"):
            if token not in text:
                violations.append(f"{code}: missing Squid token {token}")

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
    gen = load_generator()
    page_codes = [code for code, _, _, _, _ in gen.PAGES]
    assert len(page_codes) == len(set(page_codes)), "duplicate codes in PAGES"

    stock_names = set(gen.STOCK_FILES)
    overlap = set(page_codes) & stock_names
    assert not overlap, f"templates in both PAGES and STOCK_FILES: {sorted(overlap)}"

    disk_names = {p.name for p in ERROR_PAGES_DIR.iterdir() if p.is_file()}
    covered_spm = set(page_codes) & disk_names

    squid_templates = _squid_templates_from_env_or_image()
    if squid_templates is not None:
        uncovered = sorted(set(squid_templates) - covered_spm - stock_names)
        stale = sorted((set(page_codes) | stock_names) - set(squid_templates))
        assert not uncovered, (
            f"Squid templates in /usr/share/squid/errors/en without SPM page ({len(uncovered)}): "
            + ", ".join(uncovered)
        )
        assert not stale, f"entries in PAGES/STOCK_FILES not present in /usr/share/squid/errors/en: {stale}"

    missing_on_disk = sorted(set(page_codes) - disk_names)
    assert not missing_on_disk, f"templates in PAGES but missing in proxy/error-pages/: {missing_on_disk}"
