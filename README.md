# Simple-Python-Web-Honeypot
This honeypot runs a fake admin login web server using only Python's built-in HTTP server. It logs login attempts along with GeoIP information (city, region, country, ISP) to a text file. It blocks repeated login attempts from the same IP and shows a fake file manager page upon login.



Features:
- No external libraries required
- Uses free GeoIP API: ip-api.com (no key needed)
- Blocks repeat login attempts from the same IP
- Logs IP, username, password, and location info with timestamp
- Fake file manager page after login

Usage:
1. Run this script with Python 3.
2. Open browser to http://localhost:8080.
3. Enter any username/password (honeypot logs the attempt).
4. After login, a fake file manager page is shown.
5. Repeat login attempts from the same IP are blocked.

"""

from http.server import BaseHTTPRequestHandler, HTTPServer
import urllib.parse
import urllib.request
import json
from datetime import datetime

PORT = 8080              # Port to run the honeypot on
BLOCKED_IPS = set()      # Track IPs blocked after one login attempt
LOG_FILE = "web_honeypot_log.txt"  # Log file path

def get_geo_info(ip):
    """
    Query ip-api.com to get geo-location info for the given IP.
    Returns a dict with keys: country, region, city, isp.
    Returns 'Unknown' for any missing info or on failure.
    """
    try:
        url = f"http://ip-api.com/json/{ip}"
        with urllib.request.urlopen(url, timeout=5) as response:
            data = json.loads(response.read().decode())
            return {
                "country": data.get("country", "Unknown"),
                "region": data.get("regionName", "Unknown"),
                "city": data.get("city", "Unknown"),
                "isp": data.get("isp", "Unknown")
            }
    except Exception:
        return {"country": "Unknown", "region": "Unknown", "city": "Unknown", "isp": "Unknown"}

def log_attempt(ip, username, password):
    """
    Log the login attempt to the log file with timestamp, IP, username, password,
    and geo-location info.
    """
    info = get_geo_info(ip)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = (f"{timestamp} - IP: {ip} - {info['city']}, {info['region']}, {info['country']} - "
                 f"ISP: {info['isp']} - Username: {username} - Password: {password}\n")
    with open(LOG_FILE, "a") as f:
        f.write(log_entry)
    print("[!] Logged attempt:\n" + log_entry)

class HoneyPotHandler(BaseHTTPRequestHandler):
    """
    Handles HTTP GET and POST requests:
    - GET: Shows the fake admin login page or blocked message if IP is blocked.
    - POST: Processes fake login data, logs it, blocks IP, then shows fake file manager.
    """
    def _send_login_form(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(b"""
            <html>
                <head><title>Admin Login</title></head>
                <body>
                    <h2>Admin Panel Login</h2>
                    <form method="POST">
                        Username: <input type="text" name="username"><br><br>
                        Password: <input type="password" name="password"><br><br>
                        <input type="submit" value="Login">
                    </form>
                    <p style="color:red;">Access denied.</p>
                </body>
            </html>
        """)

    def _send_blocked(self):
        self.send_response(403)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(b"""
            <html>
                <head><title>Blocked</title></head>
                <body>
                    <h2>403 Forbidden</h2>
                    <p>You are blocked after one login attempt.</p>
                </body>
            </html>
        """)

    def _send_fake_file_manager(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(b"""
            <html>
                <head><title>File Manager</title></head>
                <body>
                    <h2>Admin File Manager</h2>
                    <ul>
                        <li><a href="#">important_document.docx</a></li>
                        <li><a href="#">backup_2025.zip</a></li>
                        <li><a href="#">logs.txt</a></li>
                        <li><a href="#">config.yaml</a></li>
                        <li><a href="#">database.sqlite</a></li>
                    </ul>
                    <p style="color:green;">System is up to date.</p>
                </body>
            </html>
        """)

    def do_GET(self):
        ip = self.client_address[0]
        if ip in BLOCKED_IPS:
            self._send_blocked()
        else:
            self._send_login_form()

    def do_POST(self):
        ip = self.client_address[0]
        if ip in BLOCKED_IPS:
            self._send_blocked()
            return

        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length)
        data = urllib.parse.parse_qs(post_data.decode())

        username = data.get("username", [""])[0]
        password = data.get("password", [""])[0]

        # Log the login attempt and block IP
        log_attempt(ip, username, password)
        BLOCKED_IPS.add(ip)

        # Show fake file manager page
        self._send_fake_file_manager()

def run():
    server_address = ('', PORT)
    httpd = HTTPServer(server_address, HoneyPotHandler)
    print(f"[*] Web honeypot running on port {PORT}...")
    httpd.serve_forever()

if __name__ == "__main__":
    run()
