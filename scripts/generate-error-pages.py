#!/usr/bin/env python3
"""Generate branded Squid error pages in proxy/error-pages/ from a single table.

Usage:
    python3 scripts/generate-error-pages.py          # write proxy/error-pages/*
    python3 scripts/generate-error-pages.py --check  # verify files match table
"""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

REPO_ROOT = Path(__file__).resolve().parent.parent
OUTPUT_DIR = REPO_ROOT / "proxy" / "error-pages"

BADGES: dict[str, str] = {
    "policy": "BLOCKED BY PROXY",
    "destination": "DESTINATION ERROR",
    "request": "REQUEST ERROR",
    "proxy": "PROXY ERROR",
}

# Templates in /usr/share/squid/errors/en/ that are not HTTP error pages and
# stay as the stock Squid files copied by generate_squid_conf.sh before the
# SPM error pages overwrite the error templates.
STOCK_FILES: dict[str, str] = {
    "ERR_AGENT_CONFIGURE": "Browser proxy configuration guide (not a request error).",
    "ERR_AGENT_WPAD": "Browser WPAD auto-detection guide (not a request error).",
    "ERR_DIR_LISTING": "FTP/Gopher directory listing template (%g, %z).",
    "ERR_FTP_PUT_CREATED": "201 Created success response for FTP PUT uploads.",
    "ERR_FTP_PUT_MODIFIED": "200 OK success response for FTP PUT updates.",
    "error-details.txt": "TLS/X.509 error detail dictionary read by Squid internally.",
}

# (code, kind, title, summary, action)
# Squid 7 src/errorpage.cc (ErrorState::compileLegacyCode) expands:
#   %U -> canonical request URL without password (html_quote applied, do_quote=1)
#   %T -> current UTC timestamp in RFC 1123 format (html_quote applied, do_quote=1)
#   %c -> Squid error page name, e.g. ERR_DNS_FAIL (html_quote applied, do_quote=1)
PAGES: list[tuple[str, str, str, str, str]] = [
    (
        "ERR_ACCESS_DENIED",
        "policy",
        "Access Denied",
        "This request has been blocked by the security proxy.",
        "The destination is restricted by your network policy.",
    ),
    (
        "ERR_ACL_TIME_QUOTA_EXCEEDED",
        "policy",
        "Time Quota Exceeded",
        "This request has been blocked because your online time quota is exhausted.",
        "Wait for the next quota period or contact your network administrator.",
    ),
    (
        "ERR_CACHE_ACCESS_DENIED",
        "policy",
        "Proxy Authentication Required",
        "You must sign in to the proxy before this request can be processed.",
        "Enter your proxy username and password when prompted, or contact your administrator.",
    ),
    (
        "ERR_CACHE_MGR_ACCESS_DENIED",
        "policy",
        "Cache Manager Access Denied",
        "Access to the internal proxy diagnostics interface is restricted by policy.",
        "Sign in with valid cache manager credentials from an authorized host.",
    ),
    (
        "ERR_CANNOT_FORWARD",
        "proxy",
        "Unable to Forward Request",
        "The proxy could not forward this request to the origin server or an upstream peer.",
        "Check upstream network connectivity or contact the proxy administrator.",
    ),
    (
        "ERR_CONFLICT_HOST",
        "destination",
        "URI Host Conflict",
        "The destination host header does not match the address the request was sent to.",
        "Check your DNS settings and verify the destination address.",
    ),
    (
        "ERR_CONNECT_FAIL",
        "destination",
        "Connection Failed",
        "The destination server refused the connection or did not respond.",
        "Verify that the remote service is running and reachable, then try the request again.",
    ),
    (
        "ERR_DNS_FAIL",
        "destination",
        "DNS Lookup Failed",
        "The proxy could not resolve the destination hostname to an IP address.",
        "Check that the address is spelled correctly. If it is right, the domain "
        "may not exist or the DNS server is not responding.",
    ),
    (
        "ERR_ESI",
        "destination",
        "ESI Processing Failed",
        "The proxy could not process the Edge Side Includes template returned by the server.",
        "Report this template error to the operator of the destination website.",
    ),
    (
        "ERR_FORWARDING_DENIED",
        "policy",
        "Forwarding Denied",
        "This proxy will not forward the request on behalf of a peer cache.",
        "Check the upstream peering configuration on the client cache.",
    ),
    (
        "ERR_FTP_DISABLED",
        "policy",
        "FTP Protocol Disabled",
        "FTP access through this proxy is blocked by network policy.",
        "Use HTTPS instead, or contact your administrator if FTP access is required.",
    ),
    (
        "ERR_FTP_FAILURE",
        "destination",
        "FTP Command Failed",
        "An FTP protocol error occurred while communicating with the remote server.",
        "Verify the FTP path and remote server status, then try again.",
    ),
    (
        "ERR_FTP_FORBIDDEN",
        "destination",
        "FTP Authentication Failed",
        "The remote FTP server rejected the login credentials or refused file access.",
        "Check the FTP username, password, and file permissions on the remote server.",
    ),
    (
        "ERR_FTP_NOT_FOUND",
        "destination",
        "FTP File Not Found",
        "The requested file or directory was not found on the remote FTP server.",
        "Check the file path in the URL and try the request again.",
    ),
    (
        "ERR_FTP_PUT_ERROR",
        "destination",
        "FTP Upload Failed",
        "The remote FTP server could not store the uploaded file.",
        "Check the target path, write permissions, and available disk space on the FTP server.",
    ),
    (
        "ERR_FTP_UNAVAILABLE",
        "destination",
        "FTP Server Unavailable",
        "The remote FTP server is too busy or temporarily unavailable.",
        "Wait a moment and retry the FTP request.",
    ),
    (
        "ERR_GATEWAY_FAILURE",
        "proxy",
        "Gateway Proxy Failure",
        "An internal proxy error or configuration problem prevented the request from completing.",
        "Try the request again, or contact the proxy administrator if the error continues.",
    ),
    (
        "ERR_ICAP_FAILURE",
        "proxy",
        "Security Inspection Unavailable",
        "The security inspection service is not available, so the request was not forwarded.",
        "Try again in a moment, or notify the proxy administrator if the problem persists.",
    ),
    (
        "ERR_INVALID_REQ",
        "request",
        "Invalid HTTP Request",
        "The client sent an HTTP request that is malformed or incomplete.",
        "Check the request method, URL, and HTTP headers, then try again.",
    ),
    (
        "ERR_INVALID_RESP",
        "destination",
        "Invalid Server Response",
        "The destination server returned an HTTP response that is malformed or unreadable.",
        "Try again later or contact the operator of the destination website.",
    ),
    (
        "ERR_INVALID_URL",
        "request",
        "Invalid URL",
        "The requested URL is missing a valid protocol scheme, hostname, or path.",
        "Check the URL for typos or unsupported characters and try again.",
    ),
    (
        "ERR_LIFETIME_EXP",
        "destination",
        "Connection Lifetime Expired",
        "The connection stayed open past the maximum allowed duration and was closed.",
        "Start a new request to continue the transfer.",
    ),
    (
        "ERR_NO_RELAY",
        "proxy",
        "No WAIS Relay Configured",
        "This proxy has no WAIS relay host configured to handle the request.",
        "Contact the proxy administrator if WAIS relay support is needed.",
    ),
    (
        "ERR_ONLY_IF_CACHED_MISS",
        "request",
        "Document Not in Cache",
        "The client requested a cached copy only, and no valid entry exists in the proxy cache.",
        "Retry the request without the only-if-cached Cache-Control directive.",
    ),
    (
        "ERR_PRECONDITION_FAILED",
        "request",
        "Precondition Failed",
        "A conditional header sent by the client did not match the current state of the resource.",
        "Refresh the resource and repeat the request with updated conditional headers.",
    ),
    (
        "ERR_PROTOCOL_UNKNOWN",
        "request",
        "Unsupported Protocol",
        "The proxy does not support the URL protocol scheme used in this request.",
        "Use a supported protocol such as HTTP or HTTPS.",
    ),
    (
        "ERR_READ_ERROR",
        "destination",
        "Network Read Error",
        "The connection was interrupted while reading data from the destination server.",
        "The remote server or network path may have dropped the connection. Try your request again.",
    ),
    (
        "ERR_READ_TIMEOUT",
        "destination",
        "Network Read Timeout",
        "The destination server took too long to send data over the network.",
        "The remote server or network path may be congested or down. Try your request again.",
    ),
    (
        "ERR_SECURE_CONNECT_FAIL",
        "destination",
        "Secure Connection Failed",
        "The proxy could not establish a secure TLS connection with the destination server.",
        "The remote host may present an untrusted certificate or incompatible TLS settings.",
    ),
    (
        "ERR_SHUTTING_DOWN",
        "proxy",
        "Proxy Shutting Down",
        "The proxy is restarting or shutting down and cannot serve requests right now.",
        "Wait a few seconds and retry your request.",
    ),
    (
        "ERR_SOCKET_FAILURE",
        "proxy",
        "Socket Creation Failed",
        "The proxy could not open a network socket to complete this request.",
        "The proxy may be under heavy load. Wait a moment and try your request again.",
    ),
    (
        "ERR_TOO_BIG",
        "request",
        "Request or Response Too Large",
        "The upload body or server response exceeds the maximum size configured on the proxy.",
        "Reduce the size of the transfer or contact the proxy administrator.",
    ),
    (
        "ERR_UNSUP_HTTPVERSION",
        "request",
        "Unsupported HTTP Version",
        "The proxy does not accept the HTTP protocol version used by the client.",
        "Configure your client to send HTTP/1.1 requests.",
    ),
    (
        "ERR_UNSUP_REQ",
        "request",
        "Unsupported Request Method",
        "The proxy does not support the requested HTTP method for this protocol.",
        "Use a standard HTTP method supported by the target resource.",
    ),
    (
        "ERR_URN_RESOLVE",
        "request",
        "Cannot Resolve URN",
        "The proxy could not resolve the Uniform Resource Name to a target URL.",
        "Request the resource using its direct HTTP or HTTPS URL instead.",
    ),
    (
        "ERR_WRITE_ERROR",
        "destination",
        "Network Write Error",
        "The connection was interrupted while sending data over the network.",
        "The remote server may have closed the connection early. Try your request again.",
    ),
    (
        "ERR_ZERO_SIZE_OBJECT",
        "destination",
        "Empty Server Response",
        "The destination server closed the connection without sending any data.",
        "The remote service may have dropped the connection. Try your request again.",
    ),
]

LAYOUT = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{title}: Secure Proxy Manager</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
    background: #0a0a0a;
    color: #e2e8f0;
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
  }}
  .container {{
    text-align: center;
    width: 100%;
    max-width: 520px;
    min-width: 0;
    padding: 2rem;
  }}
  .shield {{
    width: 80px;
    height: 80px;
    margin: 0 auto 1.5rem;
    opacity: 0.9;
  }}
  .shield svg {{ width: 100%; height: 100%; }}
  h1 {{
    font-size: 1.5rem;
    font-weight: 700;
    color: #f1f5f9;
    margin-bottom: 0.5rem;
  }}
  .status {{
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
  }}
  .status-amber {{
    background: rgba(245, 158, 11, 0.15);
    color: #f59e0b;
    border-color: rgba(245, 158, 11, 0.3);
  }}
  .message {{
    color: #94a3b8;
    font-size: 0.9rem;
    line-height: 1.6;
    margin-bottom: 1.5rem;
  }}
  .detail-box {{
    background: #111827;
    border: 1px solid #1e293b;
    border-radius: 8px;
    padding: 1rem;
    margin-bottom: 1.5rem;
    text-align: left;
  }}
  .detail-row {{
    display: flex;
    justify-content: space-between;
    gap: 1rem;
    padding: 0.35rem 0;
    font-size: 0.8rem;
  }}
  .detail-label {{ color: #64748b; flex-shrink: 0; }}
  .detail-value {{ color: #cbd5e1; font-family: 'SF Mono', 'Fira Code', monospace; font-size: 0.75rem; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
  .divider {{
    border-top: 1px solid #1e293b;
    margin: 1.5rem 0 1rem;
  }}
  .footer {{
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 0.5rem;
    color: #475569;
    font-size: 0.7rem;
  }}
  .footer a {{
    color: #3b82f6;
    text-decoration: none;
    font-weight: 500;
  }}
  .footer a:hover {{ text-decoration: underline; }}
  .credits {{
    color: #334155;
    font-size: 0.65rem;
    margin-top: 0.75rem;
  }}
</style>
</head>
<body>
<div class="container">
  <div class="shield">
    <svg viewBox="0 0 64 64" fill="none">
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

  <h1>{title}</h1>
  <div class="{status_class}">{badge}</div>

  <p class="message">
    {summary}
    {action}
  </p>

  <div class="detail-box">
    <div class="detail-row">
      <span class="detail-label">Destination</span>
      <span class="detail-value">%U</span>
    </div>
{detail_rows}
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
document.querySelectorAll('.detail-value').forEach(function(el){{
  el.textContent = el.textContent;
}});
</script>
</body>
</html>
"""  # noqa: E501

ACCESS_DENIED_ROWS = """    <div class="detail-row">
      <span class="detail-label">Client IP</span>
      <span class="detail-value">%a</span>
    </div>
    <div class="detail-row">
      <span class="detail-label">Time</span>
      <span class="detail-value">%T</span>
    </div>"""

DEFAULT_DETAIL_ROWS = """    <div class="detail-row">
      <span class="detail-label">Time</span>
      <span class="detail-value">%T</span>
    </div>
    <div class="detail-row">
      <span class="detail-label">Error Code</span>
      <span class="detail-value">%c</span>
    </div>"""


def render_all() -> dict[str, str]:
    rendered: dict[str, str] = {}
    for code, kind, title, summary, action in PAGES:
        if kind not in BADGES:
            raise ValueError(f"{code}: unknown kind {kind!r}")
        status_class = "status" if kind == "policy" else "status status-amber"
        detail_rows = ACCESS_DENIED_ROWS if code == "ERR_ACCESS_DENIED" else DEFAULT_DETAIL_ROWS
        rendered[code] = LAYOUT.format(
            title=title,
            status_class=status_class,
            badge=BADGES[kind],
            summary=summary,
            action=action,
            detail_rows=detail_rows,
        )
    return rendered


def check_files(out_dir: Path = OUTPUT_DIR) -> list[str]:
    expected = render_all()
    errors: list[str] = []
    actual_files = {p.name for p in out_dir.iterdir() if p.is_file()} if out_dir.is_dir() else set()
    missing = sorted(set(expected) - actual_files)
    extra = sorted(actual_files - set(expected))
    if missing:
        errors.append(f"missing generated error pages ({len(missing)}): {', '.join(missing)}")
    if extra:
        errors.append(f"unexpected files in {out_dir} ({len(extra)}): {', '.join(extra)}")
    for code, content in sorted(expected.items()):
        path = out_dir / code
        if path.is_file():
            disk = path.read_text(encoding="utf-8")
            if disk != content:
                errors.append(f"{code}: file content differs from generator output")
    return errors


def write_files(out_dir: Path = OUTPUT_DIR) -> None:
    expected = render_all()
    out_dir.mkdir(parents=True, exist_ok=True)
    for p in out_dir.iterdir():
        if p.is_file() and p.name not in expected:
            p.unlink()
    for code, content in sorted(expected.items()):
        (out_dir / code).write_text(content, encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Verify that proxy/error-pages/ matches the generated output without writing.",
    )
    args = parser.parse_args(argv)
    if args.check:
        errs = check_files()
        if errs:
            for e in errs:
                print(f"FAIL: {e}", file=sys.stderr)
            return 1
        print(f"OK: {len(PAGES)} generated error pages in {OUTPUT_DIR} are up to date")
        return 0
    write_files()
    print(f"Wrote {len(PAGES)} error pages to {OUTPUT_DIR}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
