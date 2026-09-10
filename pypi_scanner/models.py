"""Data models and configuration for PyPI Supply Chain Scanner."""

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional


class ScanVerdict(str, Enum):
    """Scan verdict status."""
    CLEAN = "CLEAN"
    MALICIOUS = "MALICIOUS"
    SUSPICIOUS = "SUSPICIOUS"
    NOT_FOUND = "NOT_FOUND"
    BLOCKED = "BLOCKED"
    ERROR = "ERROR"


class UnknownMode(str, Enum):
    """Mode to execute when a SHA-256 hash is not found on VirusTotal."""
    BLOCK = "block"
    SANDBOX = "sandbox"

    @classmethod
    def from_str(cls, value: str) -> "UnknownMode":
        val = value.strip().lower()
        if val in ("block", "mode1", "1"):
            return cls.BLOCK
        elif val in ("sandbox", "mode2", "2"):
            return cls.SANDBOX
        raise ValueError(f"Invalid unknown mode: {value}. Expected 'block' or 'sandbox'.")


@dataclass
class VTAnalysisStats:
    """Statistics returned by VirusTotal analysis."""
    harmless: int = 0
    type_unsupported: int = 0
    suspicious: int = 0
    confirmed_timeout: int = 0
    timeout: int = 0
    failure: int = 0
    malicious: int = 0
    undetected: int = 0

    @classmethod
    def from_dict(cls, data: Optional[Dict[str, Any]]) -> "VTAnalysisStats":
        if not data:
            return cls()
        return cls(
            harmless=data.get("harmless", 0),
            type_unsupported=data.get("type-unsupported", 0),
            suspicious=data.get("suspicious", 0),
            confirmed_timeout=data.get("confirmed-timeout", 0),
            timeout=data.get("timeout", 0),
            failure=data.get("failure", 0),
            malicious=data.get("malicious", 0),
            undetected=data.get("undetected", 0),
        )

    def is_clean(self, max_malicious: int = 0, max_suspicious: int = 0) -> bool:
        """Check if scan stats are clean within allowed thresholds."""
        return self.malicious <= max_malicious and self.suspicious <= max_suspicious


@dataclass
class PackageTarget:
    """Represents a resolved package artifact to be inspected."""
    name: str
    version: str
    filename: Optional[str] = None
    sha256: Optional[str] = None
    download_url: Optional[str] = None
    is_direct: bool = False
    requires_python: Optional[str] = None

    @property
    def display_name(self) -> str:
        if self.version:
            return f"{self.name}=={self.version}"
        return self.name


@dataclass
class PackageScanResult:
    """Result of scanning a single package artifact."""
    target: PackageTarget
    verdict: ScanVerdict
    sha256: Optional[str] = None
    stats: Optional[VTAnalysisStats] = None
    details: str = ""
    sandbox_used: bool = False
    cached: bool = False
    vt_link: Optional[str] = None

    @property
    def is_passed(self) -> bool:
        return self.verdict == ScanVerdict.CLEAN


@dataclass
class ScannerConfig:
    """Configuration options for the scanner."""
    vt_api_key: Optional[str] = None
    unknown_mode: UnknownMode = UnknownMode.BLOCK
    max_malicious: int = 0
    max_suspicious: int = 0
    docker_image: str = "python:3.12-slim"
    docker_timeout: int = 120
    vt_poll_timeout: int = 180
    vt_poll_interval: int = 10
    cache_enabled: bool = True
    cache_ttl_hours: int = 168  # 7 days
    cache_db_path: Path = field(default_factory=lambda: Path.home() / ".pypi_scanner" / "cache.db")
    mock_vt: bool = False
