"""Comprehensive workflow tests for ScannerEngine across all modes."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

from pypi_scanner.cache import ScanCache
from pypi_scanner.engine import ScannerEngine
from pypi_scanner.models import (
    PackageScanResult,
    PackageTarget,
    ScannerConfig,
    ScanVerdict,
    UnknownMode,
    VTAnalysisStats,
)
from pypi_scanner.pypi_client import PyPIClient
from pypi_scanner.sandbox import DockerSandbox
from pypi_scanner.vt_client import VirusTotalClient


class TestScannerEngine(unittest.TestCase):

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.cache_db = Path(self.tmp_dir.name) / "test_engine_cache.db"
        self.cache = ScanCache(self.cache_db)

        # Mock PyPI Client
        self.mock_pypi = MagicMock(spec=PyPIClient)
        self.mock_pypi.get_sha256.return_value = "e" * 64

        # Mock VirusTotal Client
        self.mock_vt = VirusTotalClient(api_key="mock", mock=True)

        # Mock Sandbox
        self.mock_sandbox = MagicMock(spec=DockerSandbox)

    def tearDown(self):
        import gc
        gc.collect()
        try:
            self.tmp_dir.cleanup()
        except PermissionError:
            pass

    def test_clean_hash_on_virustotal_passes(self):
        """Case 1: Hash is found on VT and is clean -> installation passes."""
        clean_sha = "1" * 64
        self.mock_vt.set_mock_hash_result(clean_sha, {
            "last_analysis_stats": {
                "harmless": 5,
                "undetected": 65,
                "suspicious": 0,
                "malicious": 0,
            }
        })

        config = ScannerConfig(
            cache_enabled=True,
            cache_db_path=self.cache_db,
            unknown_mode=UnknownMode.BLOCK,
            mock_vt=True,
        )
        engine = ScannerEngine(
            config=config,
            pypi_client=self.mock_pypi,
            vt_client=self.mock_vt,
            cache=self.cache,
            sandbox=self.mock_sandbox,
        )

        target = PackageTarget(name="requests", version="2.31.0", sha256=clean_sha)
        result = engine.scan_target(target)

        self.assertEqual(result.verdict, ScanVerdict.CLEAN)
        self.assertTrue(result.is_passed)
        self.assertFalse(result.sandbox_used)

        # Verify cached
        cached = self.cache.get(clean_sha)
        self.assertIsNotNone(cached)
        self.assertEqual(cached.verdict, ScanVerdict.CLEAN)

    def test_malicious_hash_on_virustotal_blocks(self):
        """Case 2: Hash is found on VT and flagged malicious -> installation is blocked."""
        mal_sha = "2" * 64
        self.mock_vt.set_mock_hash_result(mal_sha, {
            "last_analysis_stats": {
                "harmless": 0,
                "undetected": 40,
                "suspicious": 2,
                "malicious": 5,
            }
        })

        config = ScannerConfig(
            cache_enabled=True,
            cache_db_path=self.cache_db,
            unknown_mode=UnknownMode.BLOCK,
            mock_vt=True,
        )
        engine = ScannerEngine(
            config=config,
            pypi_client=self.mock_pypi,
            vt_client=self.mock_vt,
            cache=self.cache,
            sandbox=self.mock_sandbox,
        )

        target = PackageTarget(name="evil-package", version="1.0.0", sha256=mal_sha)
        result = engine.scan_target(target)

        self.assertEqual(result.verdict, ScanVerdict.MALICIOUS)
        self.assertFalse(result.is_passed)

    def test_unknown_hash_mode1_block(self):
        """Case 3: Hash NOT on VT + Mode 1 (block) -> immediately block download."""
        unknown_sha = "3" * 64
        self.mock_vt.set_mock_hash_result(unknown_sha, None)  # 404

        config = ScannerConfig(
            cache_enabled=True,
            cache_db_path=self.cache_db,
            unknown_mode=UnknownMode.BLOCK,
            mock_vt=True,
        )
        engine = ScannerEngine(
            config=config,
            pypi_client=self.mock_pypi,
            vt_client=self.mock_vt,
            cache=self.cache,
            sandbox=self.mock_sandbox,
        )

        target = PackageTarget(name="new-unindexed-pkg", version="0.0.1", sha256=unknown_sha)
        result = engine.scan_target(target)

        self.assertEqual(result.verdict, ScanVerdict.BLOCKED)
        self.assertFalse(result.is_passed)
        self.assertIn("not found on VirusTotal", result.details)
        # Verify sandbox was NOT called in Mode 1
        self.mock_sandbox.download_and_zip_package.assert_not_called()

    def test_unknown_hash_mode2_sandbox_clean(self):
        """Case 4: Hash NOT on VT + Mode 2 (sandbox) -> spin up container, zip, submit to VT, verified clean."""
        unknown_sha = "4" * 64
        self.mock_vt.set_mock_hash_result(unknown_sha, None)  # 404

        # Create dummy zip for sandbox
        dummy_zip = Path(self.tmp_dir.name) / "sandbox_out.zip"
        dummy_zip.write_bytes(b"PK\x03\x04test_zip_package")
        self.mock_sandbox.download_and_zip_package.return_value = dummy_zip

        config = ScannerConfig(
            cache_enabled=True,
            cache_db_path=self.cache_db,
            unknown_mode=UnknownMode.SANDBOX,
            mock_vt=True,
        )
        engine = ScannerEngine(
            config=config,
            pypi_client=self.mock_pypi,
            vt_client=self.mock_vt,
            cache=self.cache,
            sandbox=self.mock_sandbox,
        )

        target = PackageTarget(name="new-unindexed-pkg", version="0.0.1", sha256=unknown_sha)
        result = engine.scan_target(target)

        self.assertEqual(result.verdict, ScanVerdict.CLEAN)
        self.assertTrue(result.is_passed)
        self.assertTrue(result.sandbox_used)
        # Verify sandbox WAS called
        self.mock_sandbox.download_and_zip_package.assert_called_once_with(
            package_name="new-unindexed-pkg",
            version="0.0.1",
        )

    def test_unknown_hash_mode2_sandbox_malicious(self):
        """Case 5: Hash NOT on VT + Mode 2 (sandbox) -> submitted zip is flagged malicious -> block."""
        unknown_sha = "5" * 64
        self.mock_vt.set_mock_hash_result(unknown_sha, None)  # 404

        dummy_zip = Path(self.tmp_dir.name) / "sandbox_mal.zip"
        dummy_zip.write_bytes(b"PK\x03\x04test_mal_package")
        self.mock_sandbox.download_and_zip_package.return_value = dummy_zip

        # Override mock VT poll to return malicious stats
        mock_vt_mal = VirusTotalClient(api_key="mock", mock=True)
        mock_vt_mal.set_mock_hash_result(unknown_sha, None)
        mock_vt_mal.poll_analysis = MagicMock(
            return_value=VTAnalysisStats(malicious=3, suspicious=1, harmless=0, undetected=45)
        )

        config = ScannerConfig(
            cache_enabled=True,
            cache_db_path=self.cache_db,
            unknown_mode=UnknownMode.SANDBOX,
            mock_vt=True,
        )
        engine = ScannerEngine(
            config=config,
            pypi_client=self.mock_pypi,
            vt_client=mock_vt_mal,
            cache=self.cache,
            sandbox=self.mock_sandbox,
        )

        target = PackageTarget(name="trojan-pkg", version="1.0.0", sha256=unknown_sha)
        result = engine.scan_target(target)

        self.assertEqual(result.verdict, ScanVerdict.MALICIOUS)
        self.assertFalse(result.is_passed)
        self.assertTrue(result.sandbox_used)


if __name__ == "__main__":
    unittest.main()
