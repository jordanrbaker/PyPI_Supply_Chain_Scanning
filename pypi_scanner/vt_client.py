"""VirusTotal API v3 client for hash lookup, file upload, and analysis polling."""

import json
import logging
import mimetypes
import os
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from pypi_scanner.models import VTAnalysisStats

logger = logging.getLogger(__name__)

VT_BASE_URL = "https://www.virustotal.com/api/v3"
DEFAULT_USER_AGENT = "PyPI-Supply-Chain-Scanner/1.0"


class VTClientError(Exception):
    """Base exception for VirusTotal client errors."""
    pass


class VTAuthError(VTClientError):
    """Authentication or missing API key error."""
    pass


class VTRateLimitError(VTClientError):
    """API quota or rate limit exceeded error."""
    pass


class VirusTotalClient:
    """Client for VirusTotal API v3."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: str = VT_BASE_URL,
        mock: bool = False,
        timeout: int = 30,
    ):
        self.api_key = api_key or os.environ.get("VIRUSTOTAL_API_KEY") or os.environ.get("VT_API_KEY")
        self.base_url = base_url.rstrip("/")
        self.mock = mock
        self.timeout = timeout
        # For mock testing: map sha256 -> stats dict or None (404)
        self.mock_registry: Dict[str, Optional[Dict[str, Any]]] = {}

    def set_mock_hash_result(self, sha256: str, result: Optional[Dict[str, Any]]) -> None:
        """Register a mock result for a given SHA256 (None simulates 404 Not Found)."""
        self.mock_registry[sha256.lower()] = result

    def _get_headers(self) -> Dict[str, str]:
        if not self.api_key and not self.mock:
            raise VTAuthError(
                "VirusTotal API key is missing. Set VIRUSTOTAL_API_KEY environment variable, "
                "configure it in config.json, or pass --vt-api-key."
            )
        return {
            "x-apikey": self.api_key or "mock_key",
            "User-Agent": DEFAULT_USER_AGENT,
            "Accept": "application/json",
        }

    def lookup_file_hash(self, sha256: str) -> Optional[VTAnalysisStats]:
        """Look up a file SHA-256 hash in VirusTotal.
        
        Args:
            sha256: 64-character SHA-256 hash string.
            
        Returns:
            VTAnalysisStats if the file exists on VirusTotal,
            or None if the file is NOT found (HTTP 404).
            
        Raises:
            VTAuthError: On 401/missing key.
            VTRateLimitError: On 429 quota exceeded.
            VTClientError: On other API errors.
        """
        clean_hash = sha256.strip().lower()

        if self.mock:
            if clean_hash in self.mock_registry:
                mock_data = self.mock_registry[clean_hash]
                if mock_data is None:
                    # Simulates 404 Not Found
                    logger.debug("[MOCK VT] Hash %s returned 404 Not Found", clean_hash)
                    return None
                return VTAnalysisStats.from_dict(mock_data.get("last_analysis_stats"))
            # Default mock behavior: treat as 404 if not registered
            logger.debug("[MOCK VT] Unregistered hash %s returned 404 Not Found", clean_hash)
            return None

        url = f"{self.base_url}/files/{clean_hash}"
        headers = self._get_headers()
        req = urllib.request.Request(url, headers=headers, method="GET")

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8"))
                    attributes = data.get("data", {}).get("attributes", {})
                    stats_dict = attributes.get("last_analysis_stats", {})
                    logger.info("VirusTotal lookup for %s succeeded: %s", clean_hash[:12], stats_dict)
                    return VTAnalysisStats.from_dict(stats_dict)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                logger.info("SHA-256 %s is not in VirusTotal database (404 Not Found)", clean_hash)
                return None
            elif e.code == 401:
                raise VTAuthError(f"Invalid or unauthorized VirusTotal API key (HTTP 401): {e.reason}")
            elif e.code == 429:
                raise VTRateLimitError(f"VirusTotal API rate limit or quota exceeded (HTTP 429): {e.reason}")
            else:
                body = e.read().decode("utf-8", errors="replace")
                raise VTClientError(f"VirusTotal API error (HTTP {e.code}): {body}")
        except urllib.error.URLError as e:
            raise VTClientError(f"Network error contacting VirusTotal: {e.reason}")

        return None

    def upload_file(self, file_path: Path) -> str:
        """Upload a file (e.g. .zip package) to VirusTotal for analysis.
        
        Args:
            file_path: Path to the local file to upload.
            
        Returns:
            Analysis ID string from VirusTotal.
        """
        if not file_path.exists():
            raise FileNotFoundError(f"File to upload does not exist: {file_path}")

        file_size = file_path.stat().st_size
        logger.info("Uploading file %s (%.2f KB) to VirusTotal", file_path.name, file_size / 1024.0)

        if self.mock:
            mock_analysis_id = f"mock_analysis_{uuid.uuid4().hex[:12]}"
            logger.info("[MOCK VT] File %s uploaded with analysis ID: %s", file_path.name, mock_analysis_id)
            return mock_analysis_id

        # Determine upload endpoint (standard upload up to 32MB)
        if file_size > 32 * 1024 * 1024:
            upload_url = self._get_large_file_upload_url()
        else:
            upload_url = f"{self.base_url}/files"

        content_type, body = self._encode_multipart_file(file_path)
        headers = self._get_headers()
        headers["Content-Type"] = content_type
        headers["Content-Length"] = str(len(body))

        req = urllib.request.Request(upload_url, data=body, headers=headers, method="POST")

        try:
            with urllib.request.urlopen(req, timeout=self.timeout * 2) as resp:
                if resp.status in (200, 201):
                    data = json.loads(resp.read().decode("utf-8"))
                    analysis_id = data.get("data", {}).get("id")
                    if not analysis_id:
                        raise VTClientError(f"Upload response missing analysis ID: {data}")
                    logger.info("File upload accepted by VirusTotal. Analysis ID: %s", analysis_id)
                    return analysis_id
        except urllib.error.HTTPError as e:
            body_err = e.read().decode("utf-8", errors="replace")
            if e.code == 401:
                raise VTAuthError(f"Invalid VirusTotal API key on upload: {body_err}")
            elif e.code == 429:
                raise VTRateLimitError(f"VirusTotal quota exceeded on upload: {body_err}")
            raise VTClientError(f"VirusTotal upload failed (HTTP {e.code}): {body_err}")
        except urllib.error.URLError as e:
            raise VTClientError(f"Network error during VirusTotal upload: {e.reason}")

        raise VTClientError("Unexpected error uploading file to VirusTotal")

    def _get_large_file_upload_url(self) -> str:
        """Get specialized upload URL for files > 32MB."""
        url = f"{self.base_url}/files/upload_url"
        headers = self._get_headers()
        req = urllib.request.Request(url, headers=headers, method="GET")
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data.get("data")

    def poll_analysis(
        self,
        analysis_id: str,
        timeout: int = 180,
        interval: int = 10,
    ) -> VTAnalysisStats:
        """Poll VirusTotal analysis until status is completed.
        
        Args:
            analysis_id: Analysis ID returned from upload_file.
            timeout: Maximum time in seconds to wait.
            interval: Seconds to sleep between polling requests.
            
        Returns:
            VTAnalysisStats with analysis findings.
        """
        if self.mock:
            logger.info("[MOCK VT] Polling analysis %s -> returning clean stats", analysis_id)
            return VTAnalysisStats(malicious=0, suspicious=0, harmless=1, undetected=70)

        url = f"{self.base_url}/analyses/{analysis_id}"
        headers = self._get_headers()
        start_time = time.time()

        logger.info("Waiting for VirusTotal analysis to complete (Analysis ID: %s)...", analysis_id)
        while time.time() - start_time < timeout:
            req = urllib.request.Request(url, headers=headers, method="GET")
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    if resp.status == 200:
                        data = json.loads(resp.read().decode("utf-8"))
                        attributes = data.get("data", {}).get("attributes", {})
                        status = attributes.get("status")
                        logger.debug("Analysis %s status: %s", analysis_id, status)

                        if status == "completed":
                            stats_dict = attributes.get("stats", {})
                            logger.info("Analysis completed! Stats: %s", stats_dict)
                            return VTAnalysisStats.from_dict(stats_dict)
            except urllib.error.HTTPError as e:
                logger.warning("HTTP error %d polling analysis %s: %s", e.code, analysis_id, e.reason)
            except Exception as e:
                logger.warning("Error polling analysis %s: %s", analysis_id, e)

            time.sleep(interval)

        raise VTClientError(f"VirusTotal analysis timed out after {timeout} seconds (Analysis ID: {analysis_id})")

    def _encode_multipart_file(self, file_path: Path) -> Tuple[str, bytes]:
        """Encode a file into multipart/form-data payload."""
        boundary = f"----WebKitFormBoundary{uuid.uuid4().hex}"
        filename = file_path.name
        content_type = mimetypes.guess_type(filename)[0] or "application/octet-stream"

        file_bytes = file_path.read_bytes()

        parts = []
        parts.append(f"--{boundary}\r\n".encode("utf-8"))
        parts.append(
            f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'.encode("utf-8")
        )
        parts.append(f"Content-Type: {content_type}\r\n\r\n".encode("utf-8"))
        parts.append(file_bytes)
        parts.append(b"\r\n")
        parts.append(f"--{boundary}--\r\n".encode("utf-8"))

        body = b"".join(parts)
        header_content_type = f"multipart/form-data; boundary={boundary}"
        return header_content_type, body
