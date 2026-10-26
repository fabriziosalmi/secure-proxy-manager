# Security Advisories

How Secure Proxy Manager (SPM) handles vulnerabilities in the components it
ships, above all Squid, which it installs from Ubuntu's repositories.

## How the proxy image keeps Squid patched

The proxy image is built `FROM ubuntu:26.04` and installs `squid-openssl` from
the Ubuntu archive. Ubuntu ships security fixes as new package revisions, so
the package version, not the upstream version, says whether a fix is in.

1. **Version floor.** `proxy/Dockerfile` declares `ARG SQUID_MIN_VERSION`
   (currently `7.2-2ubuntu2.2`) and fails the build when the installed
   `squid-openssl` is older. The floor is only meaningful for the Ubuntu
   release it was written for, because dpkg compares the upstream version
   first: `ARG SQUID_FLOOR_FOR` names that release, the build refuses to run on
   another one, and `scripts/check-image-pins.sh`, run in CI, compares it with
   the `FROM` line.
2. **apt cache bust.** The release workflow
   (`.github/workflows/multi-arch.yml`) passes a new `APT_REFRESH` build
   argument on every run, so a cached apt layer cannot reinstall an older
   Squid.

A build of the proxy image from this repository on 2026-10-25 installed
`squid-openssl` `7.7-0ubuntu0.26.04.1` (Squid 7.7).

At start the backend reads the Squid version the proxy wrote to
`/config/squid_version.txt` and matches its major version against the list in
`backend-go/internal/workers/cve_checker.go`. That list has entries for Squid
3, 4 and 5 only: for a major version with no table (such as the Squid 7 the
image ships), `GET /api/status` and `GET /api/security/cve` report
`cves_checked: false` alongside `squid_version` and `squid_cves: 0` (or
`cves: []`), and the dashboard shows `Not checked for Squid 7.x` instead of a
zero CVE count.

> A running container keeps the package it was built with. After a Squid
> security update, rebuild (or pull) the proxy image and recreate the
> container.

## CVE-2026-47729 ("Squidbleed")

From the [Ubuntu entry](https://ubuntu.com/security/CVE-2026-47729): before
Squid 7.6, the FTP gateway could read past its input buffer while parsing a
directory listing from a misbehaving FTP server, so a client using the gateway
could read memory from other, unrelated transactions. CVSS 3.0 base score 6.5
(Medium). Fixed upstream in 7.6; Ubuntu 26.04 (resolute) is fixed in
`7.2-2ubuntu2.2`.

### Mitigations in SPM

1. **Patched package.** `SQUID_MIN_VERSION` is the fixed resolute revision, so
   the build refuses anything older.
2. **FTP disabled.** The generated configuration denies the FTP scheme right
   after the method rules, ahead of every allow rule (`acl ftp_proto proto FTP`,
   `http_access deny ftp_proto`) and leaves port 21 out of `Safe_ports`, so the
   FTP gateway is not reachable whatever the package version.

If you add directives through `/config/custom_squid_extra.conf`, keep FTP
disabled.

## Related Squid advisories

| CVE | Issue (from Ubuntu's entry) | Applies only if | SPM |
| --- | --- | --- | --- |
| CVE-2026-50012 | Heap overflow in cache digest reply handling; fixed in 7.6, resolute in `7.2-2ubuntu2.2` | Squid built with `--enable-cache-digests` **and** configured with `cache_peer` entries | Ubuntu's build has `--enable-cache-digests` (from `squid -v`); the generated configuration defines no `cache_peer` |
| CVE-2026-33526, CVE-2026-32748 | Denial of service through ICP; fixed in 7.5; resolute listed as not affected | a non-zero `icp_port` | The generated configuration sets no `icp_port` |

## References

- [Ubuntu: CVE-2026-47729](https://ubuntu.com/security/CVE-2026-47729)
- [Ubuntu: CVE-2026-50012](https://ubuntu.com/security/CVE-2026-50012)
- [Squid security advisories](https://github.com/squid-cache/squid/security/advisories)
