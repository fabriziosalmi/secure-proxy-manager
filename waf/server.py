import re
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

    def waf_options(self):
        self.set_icap_response(200)
        self.set_icap_header('Methods', 'REQMOD, RESPMOD')
        self.set_icap_header('Service', 'SecureProxy-WAF-1.0')
        self.set_icap_header('Preview', '1024')
        self.set_icap_header('Transfer-Preview', '*')
        self.set_icap_header('Transfer-Ignore', 'jpg,jpeg,gif,png,swf,flv')
        self.set_icap_header('Transfer-Complete', '')
        self.set_icap_header('Max-Connections', '100')
        self.send_headers(False)

    def waf_reqmod(self):
        # We only inspect requests that have a body (e.g., POST/PUT)
        if self.has_body:
            body_data = b""
            while True:
                chunk = self.read_chunk()
                if chunk == b"":
                    break
                body_data += chunk
            
            # Check against WAF rules
            for rule in BLOCK_RULES:
                if rule.search(body_data):
                    print(f"WAF BLOCKED OUTBOUND REQUEST: Matched rule {rule.pattern}")
                    # Send a 403 Forbidden HTTP response
                    self.send_block_response()
                    return
            
            # If safe, reconstruct the request and send it back
            self.set_icap_response(200)
            self.set_enc_status(b' '.join(self.enc_req))
            for h, v in self.enc_req_headers.items():
                for i in v:
                    self.set_enc_header(h, i)
            self.send_headers(True)
            self.send_chunk(body_data)
            self.send_chunk(b"")
        else:
            self.no_adaptation_required()

    def waf_respmod(self):
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
