"""Unit tests for models and data structures."""

import unittest
from pypi_scanner.models import (
    PackageScanResult,
    PackageTarget,
    ScannerConfig,
    ScanVerdict,
    UnknownMode,
    VTAnalysisStats,
)


class TestModels(unittest.TestCase):

    def test_vt_analysis_stats_clean(self):
        stats = VTAnalysisStats(
            harmless=5,
            undetected=65,
            suspicious=0,
            malicious=0,
        )
        self.assertTrue(stats.is_clean(max_malicious=0, max_suspicious=0))

    def test_vt_analysis_stats_malicious(self):
        stats = VTAnalysisStats(
            harmless=0,
            undetected=50,
            suspicious=1,
            malicious=3,
        )
        self.assertFalse(stats.is_clean(max_malicious=0, max_suspicious=0))
        self.assertTrue(stats.is_clean(max_malicious=3, max_suspicious=1))

    def test_vt_analysis_stats_from_dict(self):
        raw = {
            "harmless": 2,
            "type-unsupported": 0,
            "suspicious": 1,
            "confirmed-timeout": 0,
            "timeout": 0,
            "failure": 0,
            "malicious": 4,
            "undetected": 60,
        }
        stats = VTAnalysisStats.from_dict(raw)
        self.assertEqual(stats.harmless, 2)
        self.assertEqual(stats.suspicious, 1)
        self.assertEqual(stats.malicious, 4)
        self.assertEqual(stats.undetected, 60)

    def test_unknown_mode_parsing(self):
        self.assertEqual(UnknownMode.from_str("block"), UnknownMode.BLOCK)
        self.assertEqual(UnknownMode.from_str("BLOCK"), UnknownMode.BLOCK)
        self.assertEqual(UnknownMode.from_str("sandbox"), UnknownMode.SANDBOX)
        self.assertEqual(UnknownMode.from_str("Mode2"), UnknownMode.SANDBOX)

        with self.assertRaises(ValueError):
            UnknownMode.from_str("invalid_mode")

    def test_package_target_display(self):
        target1 = PackageTarget(name="requests", version="2.31.0")
        self.assertEqual(target1.display_name, "requests==2.31.0")

        target2 = PackageTarget(name="urllib3", version="")
        self.assertEqual(target2.display_name, "urllib3")

    def test_package_scan_result_passed(self):
        target = PackageTarget(name="flask", version="3.0.0")
        res_clean = PackageScanResult(target=target, verdict=ScanVerdict.CLEAN)
        self.assertTrue(res_clean.is_passed)

        res_malicious = PackageScanResult(target=target, verdict=ScanVerdict.MALICIOUS)
        self.assertFalse(res_malicious.is_passed)

        res_blocked = PackageScanResult(target=target, verdict=ScanVerdict.BLOCKED)
        self.assertFalse(res_blocked.is_passed)


if __name__ == "__main__":
    unittest.main()
