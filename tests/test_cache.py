"""Unit tests for SQLite scan cache."""

import tempfile
import time
import unittest
from pathlib import Path

from pypi_scanner.cache import ScanCache
from pypi_scanner.models import (
    PackageScanResult,
    PackageTarget,
    ScanVerdict,
    VTAnalysisStats,
)


class TestScanCache(unittest.TestCase):

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp_dir.name) / "test_cache.db"
        self.cache = ScanCache(self.db_path)

    def tearDown(self):
        import gc
        gc.collect()
        try:
            self.tmp_dir.cleanup()
        except PermissionError:
            pass

    def test_cache_set_and_get(self):
        sha = "a" * 64
        target = PackageTarget(name="testpkg", version="1.0.0", sha256=sha)
        stats = VTAnalysisStats(harmless=10, undetected=60, suspicious=0, malicious=0)
        result = PackageScanResult(
            target=target,
            verdict=ScanVerdict.CLEAN,
            sha256=sha,
            stats=stats,
            details="Test clean package",
        )

        self.cache.set(result, ttl_hours=24)
        cached = self.cache.get(sha)

        self.assertIsNotNone(cached)
        self.assertEqual(cached.sha256, sha)
        self.assertEqual(cached.verdict, ScanVerdict.CLEAN)
        self.assertTrue(cached.cached)
        self.assertEqual(cached.stats.harmless, 10)
        self.assertEqual(cached.stats.undetected, 60)

    def test_cache_miss(self):
        cached = self.cache.get("b" * 64)
        self.assertIsNone(cached)

    def test_cache_expiration(self):
        sha = "c" * 64
        target = PackageTarget(name="expiredpkg", version="0.1.0", sha256=sha)
        result = PackageScanResult(
            target=target,
            verdict=ScanVerdict.CLEAN,
            sha256=sha,
        )

        # Set TTL to 0 hours (expires immediately)
        self.cache.set(result, ttl_hours=-1)
        cached = self.cache.get(sha)
        self.assertIsNone(cached)

    def test_cache_clear(self):
        sha = "d" * 64
        target = PackageTarget(name="clearpkg", version="1.2.0", sha256=sha)
        result = PackageScanResult(
            target=target,
            verdict=ScanVerdict.CLEAN,
            sha256=sha,
        )
        self.cache.set(result)
        self.assertIsNotNone(self.cache.get(sha))

        self.cache.clear()
        self.assertIsNone(self.cache.get(sha))


if __name__ == "__main__":
    unittest.main()
