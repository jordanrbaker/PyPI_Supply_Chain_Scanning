"""Unit tests for CLI interface and shim management."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pypi_scanner.cli import build_scanner_config
from pypi_scanner.models import UnknownMode
from pypi_scanner.shim import PipShimManager


class TestCLI(unittest.TestCase):

    def test_build_scanner_config_cli_overrides(self):
        cfg = build_scanner_config(
            cli_api_key="cli_test_key",
            cli_unknown_mode="sandbox",
            cli_mock_vt=True,
            cli_no_cache=True,
            cli_agent_instruction="Ask human operator before proceeding",
        )
        self.assertEqual(cfg.vt_api_key, "cli_test_key")
        self.assertEqual(cfg.unknown_mode, UnknownMode.SANDBOX)
        self.assertTrue(cfg.mock_vt)
        self.assertFalse(cfg.cache_enabled)
        self.assertEqual(cfg.agent_fallback_instruction, "Ask human operator before proceeding")

    def test_shim_installation_in_temp_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            target_dir = Path(tmpdir)
            PipShimManager.install_shim(target_dir)

            # Check that files were created
            created_files = [p.name for p in target_dir.iterdir()]
            self.assertTrue(
                "safe-pip.cmd" in created_files or "safe-pip" in created_files or "safe-pip.ps1" in created_files
            )


if __name__ == "__main__":
    unittest.main()
