"""Local SQLite cache for storing package scan results and SHA-256 verdicts."""

import logging
import sqlite3
import time
from pathlib import Path
from typing import Optional

from pypi_scanner.models import PackageScanResult, PackageTarget, ScanVerdict, VTAnalysisStats

logger = logging.getLogger(__name__)


class ScanCache:
    """Thread-safe SQLite-backed cache for VirusTotal scan results."""

    def __init__(self, db_path: Optional[Path] = None):
        if db_path is None:
            default_dir = Path.home() / ".pypi_scanner"
            default_dir.mkdir(parents=True, exist_ok=True)
            db_path = default_dir / "cache.db"
        else:
            db_path.parent.mkdir(parents=True, exist_ok=True)

        self.db_path = db_path
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=10.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        """Initialize database schema."""
        conn = self._get_connection()
        try:
            with conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS scan_cache (
                        sha256 TEXT PRIMARY KEY,
                        package_name TEXT,
                        version TEXT,
                        verdict TEXT,
                        malicious INTEGER,
                        suspicious INTEGER,
                        undetected INTEGER,
                        harmless INTEGER,
                        details TEXT,
                        scanned_at REAL,
                        expires_at REAL
                    )
                    """
                )
                conn.execute("CREATE INDEX IF NOT EXISTS idx_cache_expires ON scan_cache(expires_at)")
        finally:
            conn.close()

    def get(self, sha256: str) -> Optional[PackageScanResult]:
        """Look up a cached scan result by SHA-256.
        
        Returns None if not found or if the cache entry has expired.
        """
        if not sha256:
            return None

        clean_hash = sha256.strip().lower()
        now = time.time()

        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT sha256, package_name, version, verdict,
                       malicious, suspicious, undetected, harmless,
                       details, scanned_at, expires_at
                FROM scan_cache
                WHERE sha256 = ?
                """,
                (clean_hash,),
            )
            row = cursor.fetchone()
            if not row:
                return None

            if row["expires_at"] and row["expires_at"] < now:
                logger.debug("Cache entry for %s expired, deleting", clean_hash)
                with conn:
                    conn.execute("DELETE FROM scan_cache WHERE sha256 = ?", (clean_hash,))
                return None

            stats = VTAnalysisStats(
                malicious=row["malicious"],
                suspicious=row["suspicious"],
                undetected=row["undetected"],
                harmless=row["harmless"],
            )
            target = PackageTarget(
                name=row["package_name"] or "",
                version=row["version"] or "",
                sha256=clean_hash,
            )
            return PackageScanResult(
                target=target,
                verdict=ScanVerdict(row["verdict"]),
                sha256=clean_hash,
                stats=stats,
                details=row["details"] or "Loaded from local cache",
                cached=True,
            )
        finally:
            conn.close()

    def set(self, result: PackageScanResult, ttl_hours: int = 168) -> None:
        """Store a scan result in cache with expiration TTL."""
        if not result.sha256:
            return

        clean_hash = result.sha256.strip().lower()
        now = time.time()
        expires_at = now + (ttl_hours * 3600)
        stats = result.stats or VTAnalysisStats()

        conn = self._get_connection()
        try:
            with conn:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO scan_cache (
                        sha256, package_name, version, verdict,
                        malicious, suspicious, undetected, harmless,
                        details, scanned_at, expires_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        clean_hash,
                        result.target.name,
                        result.target.version,
                        result.verdict.value,
                        stats.malicious,
                        stats.suspicious,
                        stats.undetected,
                        stats.harmless,
                        result.details,
                        now,
                        expires_at,
                    ),
                )
        finally:
            conn.close()

    def clear(self) -> None:
        """Clear all entries from the cache."""
        conn = self._get_connection()
        try:
            with conn:
                conn.execute("DELETE FROM scan_cache")
        finally:
            conn.close()

    def prune_expired(self) -> int:
        """Delete expired entries and return number of rows deleted."""
        now = time.time()
        conn = self._get_connection()
        try:
            with conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM scan_cache WHERE expires_at < ?", (now,))
                return cursor.rowcount
        finally:
            conn.close()
