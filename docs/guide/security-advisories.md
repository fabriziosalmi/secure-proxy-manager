# Security Advisories

How Secure Proxy Manager (SPM) responds to upstream vulnerabilities in the
components it bundles — most importantly Squid, which it ships from the Ubuntu
security pocket.

## How SPM keeps Squid patched

The proxy image is built `FROM ubuntu:22.04` and installs `squid-openssl` from
Ubuntu's repositories. The *package revision* (e.g. `5.9-0ubuntu0.22.04.7`), not
the upstream `5.9`, is what carries security fixes. Two mechanisms guarantee a
published image is patched:

1. **Version floor (fail-closed).** `proxy/Dockerfile` declares
   `ARG SQUID_MIN_VERSION` and asserts, after install, that the installed
   `squid-openssl` is `>=` that floor. If it is older, **the build fails** — an
   unpatched proxy image can never be produced. Bump `SQUID_MIN_VERSION`
   whenever Ubuntu jammy ships a new Squid CVE fix.
2. **apt cache bust.** `ARG APT_REFRESH` is changed on every CI run
   (`.github/workflows/multi-arch.yml` passes `github.run_id`), so a stale
   buildx/GHA cache layer can never reinstall an old Squid after Ubuntu
   publishes a fix.

The backend's CVE checker (`/api/health` → `squid_cves`) also matches the
running Squid version line against a curated advisory list and logs a warning on
startup.

> After pulling a Squid security update you must **rebuild and redeploy** the
> proxy image — a running container keeps whatever package it was built with.

## CVE-2026-47729 — "Squidbleed"

An out-of-bounds read in Squid's **FTP gateway** that can leak heap memory —
including other clients' HTTP `Authorization` headers, cookies and session
tokens — to anyone who can make the proxy fetch a directory listing from an FTP
server they control. The bug dates back to 1997 and affects **Squid &lt; 7.6**.

- **Severity:** Medium (CVSS 6.5), but high impact in shared-proxy environments
  (multiple users behind one Squid), which is exactly SPM's use case.
- **Fixed in:** upstream Squid 7.6; Ubuntu 22.04 (jammy) `5.9-0ubuntu0.22.04.7`.

### SPM mitigations (defence in depth)

1. **Patched package.** `SQUID_MIN_VERSION` is set to the fixed jammy revision,
   so builds refuse anything older.
2. **FTP gateway disabled.** SPM never proxies FTP. The Squid config
   (`proxy/squid.conf` and the generated config) denies the FTP scheme outright
   (`acl ftp_proto proto FTP` → `http_access deny ftp_proto`) and drops port 21
   from `Safe_ports`. This removes the Squidbleed attack surface **regardless**
   of the Squid package version.

If you run a customised Squid config, make sure FTP proxying stays disabled.

## Related 2026 Squid advisories

These were fixed in the same Squid 7.6 / jammy updates. SPM is **not** exposed
to them in its default configuration:

| CVE | Issue | Applies only if |
| --- | --- | --- |
| CVE-2026-50012 | Heap overflow in `cache_digest` reply handling | Squid built `--enable-cache-digests` (Ubuntu's is not) |
| CVE-2026-33526 / CVE-2026-32748 | DoS via the ICP protocol | ICP is enabled (SPM does not enable it) |

## References

- [Ubuntu security tracker — CVE-2026-47729](https://ubuntu.com/security/CVE-2026-47729)
- [Squid security advisories](https://github.com/squid-cache/squid/security/advisories)
- [The Hacker News — Squidbleed](https://thehackernews.com/2026/06/29-year-old-squid-proxy-squidbleed.html)
