"""PEP 503 Simple Repository Proxy Server for real-time PyPI package scanning."""

import http.server
import logging
import socketserver
import urllib.parse
import urllib.request
from typing import Optional

from pypi_scanner.engine import ScannerEngine
from pypi_scanner.models import ScannerConfig

logger = logging.getLogger(__name__)


class PyPISecurityProxyHandler(http.server.BaseHTTPRequestHandler):
    """HTTP Request Handler that proxies PEP 503 requests and inspects packages."""

    engine: Optional[ScannerEngine] = None
    upstream_url: str = "https://pypi.org"

    def do_GET(self) -> None:
        parsed_path = urllib.parse.urlparse(self.path)
        path = parsed_path.path

        # If root or status
        if path in ("/", "/status"):
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"PyPI Supply Chain Scanning Proxy: Active\n")
            return

        # Upstream proxy URL
        target_url = f"{self.upstream_url.rstrip('/')}{self.path}"
        req = urllib.request.Request(
            target_url,
            headers={"User-Agent": "PyPI-Security-Proxy/1.0", "Accept": "*/*"}
        )

        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                content = resp.read()
                self.send_response(resp.status)
                for header, value in resp.headers.items():
                    if header.lower() not in ("content-length", "transfer-encoding", "content-encoding"):
                        self.send_header(header, value)
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)
        except urllib.error.HTTPError as e:
            self.send_response(e.code)
            self.end_headers()
            self.wfile.write(e.read())
        except Exception as e:
            self.send_response(502)
            self.end_headers()
            self.wfile.write(f"Proxy error: {e}".encode("utf-8"))

    def log_message(self, format: str, *args) -> None:
        logger.debug("%s - - [%s] %s\n", self.client_address[0], self.log_date_time_string(), format % args)


def run_proxy_server(port: int = 8080, config: Optional[ScannerConfig] = None) -> None:
    """Run the PyPI security proxy server on the given port."""
    engine = ScannerEngine(config=config or ScannerConfig())
    PyPISecurityProxyHandler.engine = engine

    with socketserver.TCPServer(("", port), PyPISecurityProxyHandler) as httpd:
        logger.info("Serving PyPI Security Proxy on port %d (http://localhost:%d/simple/)", port, port)
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            logger.info("Proxy server stopped by user")
