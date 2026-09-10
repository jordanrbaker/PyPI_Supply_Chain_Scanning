"""PyPI API client for fetching package release metadata and canonical SHA-256 hashes."""

import json
import logging
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

USER_AGENT = "PyPI-Supply-Chain-Scanner/1.0 (+https://github.com/pypi-supply-chain-scanning)"


class PyPIClient:
    """Client for interacting with the official PyPI JSON API."""

    def __init__(self, base_url: str = "https://pypi.org", timeout: int = 15):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def get_package_data(self, package_name: str, version: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Fetch package metadata from PyPI JSON API.
        
        Args:
            package_name: Name of the package on PyPI.
            version: Optional specific version string.
            
        Returns:
            Dict containing package JSON metadata, or None if not found / error.
        """
        clean_name = package_name.strip()
        if version:
            url = f"{self.base_url}/pypi/{clean_name}/{version.strip()}/json"
        else:
            url = f"{self.base_url}/pypi/{clean_name}/json"

        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8"))
                    return data
        except urllib.error.HTTPError as e:
            if e.code == 404:
                logger.warning("Package '%s' (version %s) not found on PyPI (404)", clean_name, version)
            else:
                logger.error("HTTP error %d fetching PyPI data for '%s': %s", e.code, clean_name, e.reason)
            return None
        except Exception as e:
            logger.error("Error contacting PyPI for '%s': %s", clean_name, e)
            return None

    def get_release_files(self, package_name: str, version: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get the list of release files (wheels, sdists) and their SHA-256 hashes.
        
        Args:
            package_name: Name of the package.
            version: Optional version. If None, uses latest release.
            
        Returns:
            List of file dicts containing 'filename', 'digests' {'sha256': ...}, 'url', etc.
        """
        data = self.get_package_data(package_name, version)
        if not data:
            return []

        # PyPI JSON API structure:
        # If version is specified in URL, data['urls'] contains the files for that version.
        # data['releases'] is a dict mapping version string -> list of files.
        if "urls" in data and data["urls"]:
            return data["urls"]

        target_version = version or data.get("info", {}).get("version")
        if target_version and "releases" in data and target_version in data["releases"]:
            return data["releases"][target_version]

        return []

    def get_sha256(self, package_name: str, version: str, filename: Optional[str] = None) -> Optional[str]:
        """Retrieve the canonical SHA-256 hash for a specific release artifact.
        
        Args:
            package_name: Name of package.
            version: Version string.
            filename: Exact filename if known (e.g. 'foo-1.0-py3-none-any.whl').
            
        Returns:
            64-character lowercase SHA-256 hex string, or None if not found.
        """
        files = self.get_release_files(package_name, version)
        if not files:
            return None

        # 1. Match by exact filename if provided
        if filename:
            clean_filename = filename.strip()
            for f in files:
                if f.get("filename") == clean_filename:
                    digests = f.get("digests", {})
                    if "sha256" in digests:
                        return digests["sha256"].lower()
                    if f.get("sha256"):
                        return f["sha256"].lower()

        # 2. Otherwise prefer wheel first, then sdist
        for f in files:
            packagetype = f.get("packagetype", "")
            if packagetype == "bdist_wheel":
                digests = f.get("digests", {})
                if "sha256" in digests:
                    return digests["sha256"].lower()

        for f in files:
            digests = f.get("digests", {})
            if "sha256" in digests:
                return digests["sha256"].lower()

        return None
