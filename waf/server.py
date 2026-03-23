import re
import urllib.parse
import socketserver
from pyicap import ICAPServer, BaseICAPRequestHandler

# Simple rules for Outbound WAF (Content Inspection)
BLOCK_RULES = [
    # Block basic SQL injection payloads
    re.compile(b'(?i)(UNION\s+SELECT|DROP\s+TABLE|INSERT\s+INTO)'),
    # Block basic XSS payloads
    re.compile(b'(?i)(<script>|javascript:)'),
    # Block simulated sensitive data leak (e.g. "CONFIDENTIAL_SECRET_123")
    re.compile(b'CONFIDENTIAL_SECRET_[0-9]+'),
]

class ThreadingSimpleServer(socketserver.ThreadingMixIn, ICAPServer):
    pass

class WAFICAPHandler(BaseICAPRequestHandler):

    def waf_OPTIONS(self):
        print("Received OPTIONS request")
        self.set_icap_response(200)
        self.set_icap_header(b'Methods', b'REQMOD, RESPMOD')
        self.set_icap_header(b'Service', b'SecureProxy-WAF-1.0')
        self.set_icap_header(b'Preview', b'1024')
        self.set_icap_header(b'Transfer-Preview', b'*')
        self.set_icap_header(b'Transfer-Ignore', b'jpg,jpeg,gif,png,swf,flv')
        self.set_icap_header(b'Transfer-Complete', b'')
        self.set_icap_header(b'Max-Connections', b'100')
        self.send_headers(False)

    def waf_REQMOD(self):
        # Inspect URL for malicious patterns
        url = self.enc_req[1] if len(self.enc_req) > 1 else b""
        
        # Decode URL for accurate regex matching (e.g. %20 -> space)
        try:
            # Replace + with space for query strings, then decode
            decoded_url = urllib.parse.unquote_to_bytes(url.replace(b'+', b' '))
        except:
            decoded_url = url
            
        print(f"INSPECTING URL: {decoded_url}")
        
        for rule in BLOCK_RULES:
            if rule.search(decoded_url):
                print(f"WAF BLOCKED OUTBOUND REQUEST URL: Matched rule {rule.pattern}")
                self.send_block_response()
                return

        # If safe, tell Squid no adaptation is required
        self.no_adaptation_required()

    def waf_RESPMOD(self):
        # We can implement inbound inspection here (e.g. malware scanning)
        self.no_adaptation_required()

    def send_block_response(self):
        # Create a HTTP 403 response
        http_body = b"<html><body><h1>403 Forbidden - Blocked by WAF</h1><p>Your request contains prohibited content.</p></body></html>"
        
        self.set_icap_response(200)
        self.set_enc_status(b"HTTP/1.1 403 Forbidden")
        self.set_enc_header(b"Content-Type", b"text/html")
        self.set_enc_header(b"Content-Length", str(len(http_body)).encode())
        self.send_headers(True)
        self.send_chunk(http_body)
        self.send_chunk(b"")

port = 1344
print(f"Starting ICAP WAF server on port {port}...")
server = ThreadingSimpleServer(('', port), WAFICAPHandler)
try:
    server.serve_forever()
except KeyboardInterrupt:
    print("Shutting down...")
