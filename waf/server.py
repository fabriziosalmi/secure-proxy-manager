import re
import os
import urllib.parse
import socketserver
import re
import socket
import urllib.parse
import threading
import time
import requests
import json
from pyicap import ICAPServer, BaseICAPRequestHandler
from concurrent.futures import ThreadPoolExecutor

# Rate limiting / Tar-pitting dictionary
IP_BLOCK_TRACKER = {}
TAR_PIT_DELAY = 10  # Seconds to delay responses for repeated offenders

# Thread pool for backend notifications to prevent thread exhaustion DoS
notification_pool = ThreadPoolExecutor(max_workers=10)

# Core WAF Rules for Content Inspection
BLOCK_RULES = {
    "SQL_INJECTION": [
        re.compile(b'(?i)(UNION\s+SELECT|DROP\s+TABLE|INSERT\s+INTO|UPDATE\s+.*SET|DELETE\s+FROM)'),
        re.compile(b'(?i)(\%27|\'|--|\%23|#)(.*)(OR|AND)\s+([0-9=a-zA-Z]+)'),
    ],
    "XSS_ATTACKS": [
        re.compile(b'(?i)(<script>|javascript:|onerror=|onload=|eval\()'),
        re.compile(b'(?i)(document\.cookie|window\.location)'),
    ],
    "DATA_LEAK_PREVENTION": [
        re.compile(b'CONFIDENTIAL_SECRET_[0-9]+'),
        re.compile(b'(?i)(password|passwd|pwd)=([^\&]+)'),  # Block plain-text passwords in query strings
    ],
    "DIRECTORY_TRAVERSAL": [
        re.compile(b'(?i)(\.\./\.\./|\.\.\\\.\.\\|/etc/passwd|/etc/shadow)'),
    ],
    "COMMAND_INJECTION": [
        re.compile(b'(?i)(;\s*ls\s+-|;\s*cat\s+|;\s*wget\s+|;\s*curl\s+|;\s*rm\s+-rf)'),
    ],
    "UNICODE_HOMOGRAPH_OBFUSCATION": [
        # Block Zero-Width Characters (Space, Non-Joiner, Joiner)
        re.compile(b'(\xe2\x80\x8b|\xe2\x80\x8c|\xe2\x80\x8d)'),
        # Block Direction Overrides (RTL, LTR)
        re.compile(b'(\xe2\x80\xae|\xe2\x80\xad)'),
        # Block Cyrillic/Greek letters commonly used in homograph attacks mixed with standard ASCII
        # Note: This is a basic heuristic. A full homograph detector requires Punycode analysis.
        re.compile(b'(?i)[a-z]+[\xd0\xb0\xd0\xb5\xd0\xbe\xd1\x80\xd1\x81\xd1\x83\xd1\x96\xd1\x98]+[a-z]+'),
        re.compile(b'(?i)[\xd0\xb0\xd0\xb5\xd0\xbe\xd1\x80\xd1\x81\xd1\x83\xd1\x96\xd1\x98]+[a-z]+'),
        re.compile(b'(?i)[a-z]+[\xce\xbf\xce\xbd\xcf\x81\xcf\x84]+[a-z]+'),
    ]
}

def load_custom_rules():
    """Load custom rules from environment or file"""
    custom_rules_file = '/config/waf_custom_rules.txt'
    if os.path.exists(custom_rules_file):
        try:
            with open(custom_rules_file, 'r') as f:
                rules = f.readlines()
                compiled_rules = []
                for rule in rules:
                    rule = rule.strip()
                    if rule and not rule.startswith('#'):
                        try:
                            compiled_rules.append(re.compile(rule.encode(), re.IGNORECASE))
                        except Exception as e:
                            print(f"Error compiling custom rule {rule}: {e}")
                
                if compiled_rules:
                    BLOCK_RULES["CUSTOM_USER_RULES"] = compiled_rules
                    print(f"Loaded {len(compiled_rules)} custom WAF rules.")
        except Exception as e:
            print(f"Error reading custom rules: {e}")

# Load custom rules on startup
load_custom_rules()

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
        
        for category, rules in BLOCK_RULES.items():
            for rule in rules:
                if rule.search(decoded_url):
                    print(f"WAF BLOCKED [{category}] - Matched rule {rule.pattern}")
                    
                    # Try to extract client IP from headers if passed by squid
                    client_ip = "Unknown"
                    if b'X-Client-IP' in self.headers:
                        client_ip = self.headers[b'X-Client-IP'][0].decode()
                        
                    # Active Mitigation / Tar-pitting
                    # If the IP has been blocked multiple times recently, sleep before responding
                    current_time = time.time()
                    if client_ip != "Unknown":
                        if client_ip not in IP_BLOCK_TRACKER:
                            IP_BLOCK_TRACKER[client_ip] = []
                        # Keep only blocks from last 60 seconds
                        valid_blocks = [t for t in IP_BLOCK_TRACKER[client_ip] if current_time - t < 60]
                        valid_blocks.append(current_time)
                        
                        # Memory leak prevention: clear out IPs that have no recent blocks
                        keys_to_delete = []
                        for ip, times in IP_BLOCK_TRACKER.items():
                            IP_BLOCK_TRACKER[ip] = [t for t in times if current_time - t < 60]
                            if not IP_BLOCK_TRACKER[ip]:
                                keys_to_delete.append(ip)
                        
                        for ip in keys_to_delete:
                            del IP_BLOCK_TRACKER[ip]
                            
                        # Update the current IP after cleanup
                        if valid_blocks:
                            IP_BLOCK_TRACKER[client_ip] = valid_blocks
                        
                        # If more than 3 blocks in 60s, activate tar-pit
                        if client_ip in IP_BLOCK_TRACKER and len(IP_BLOCK_TRACKER[client_ip]) > 3:
                            print(f"TAR-PITTING IP {client_ip} for {TAR_PIT_DELAY}s")
                            time.sleep(TAR_PIT_DELAY)
                        
                    # Send alert to backend via internal API
                    try:
                        alert_data = {
                            "event_type": "waf_block",
                            "message": f"WAF Blocked URL matching category {category}",
                            "details": {
                                "category": category,
                                "url": decoded_url.decode('utf-8', errors='replace'),
                                "client_ip": client_ip
                            },
                            "level": "error"
                        }
                        # Use thread pool to not block the ICAP response and prevent thread exhaustion DoS
                        notification_pool.submit(self.notify_backend, alert_data)
                    except Exception as e:
                        print(f"Failed to trigger alert: {e}")
                        
                    self.send_block_response(category)
                    return

        # If safe, tell Squid no adaptation is required
        self.no_adaptation_required()

    def notify_backend(self, data):
        try:
            # Backend is usually accessible on 'backend' container within docker network
            backend_url = os.environ.get('BACKEND_URL', 'http://backend:5000')
            # Use basic auth from environment if needed, or open internal endpoint
            auth_user = os.environ.get('BASIC_AUTH_USERNAME', 'admin')
            auth_pass = os.environ.get('BASIC_AUTH_PASSWORD', 'admin')
            
            requests.post(
                f"{backend_url}/api/internal/alert", 
                json=data,
                auth=(auth_user, auth_pass),
                timeout=2
            )
        except Exception as e:
            print(f"Error sending alert to backend: {e}")

    def waf_RESPMOD(self):
        # Implement basic inbound inspection for Malware / Antivirus
        # Check if response has content
        if not self.has_body:
            self.no_adaptation_required()
            return
            
        content_type = b""
        if b'Content-Type' in self.enc_res_headers:
            content_type = self.enc_res_headers[b'Content-Type'][0]
            
        # Only inspect potentially dangerous files (exe, scripts, etc.)
        dangerous_types = [b'application/x-msdownload', b'application/x-dosexec', b'application/javascript']
        
        is_dangerous_type = any(dt in content_type.lower() for dt in dangerous_types)
        
        # Read a small chunk of the file (first 4KB) for signature matching (e.g. EICAR or MZ header)
        if is_dangerous_type:
            # We are reading the body to inspect it. 
            # In a full AV setup, we'd stream this to ClamAV
            # Here we do a basic heuristic check
            print(f"Inspecting RESPMOD payload for type: {content_type}")
            
            # For now, just allow. A real AV would block here if malware is found.
            pass
            
        self.no_adaptation_required()

    def send_block_response(self, category="UNKNOWN"):
        # Create a HTTP 403 response
        http_body = f"<html><body><h1>403 Forbidden - Blocked by WAF</h1><p>Your request contains prohibited content. Category: <b>{category}</b></p></body></html>".encode()
        
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
