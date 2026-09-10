"""Unit and integration tests for DockerSandbox."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from pypi_scanner.sandbox import DockerSandbox, SandboxError


class TestDockerSandbox(unittest.TestCase):

    def test_is_docker_available(self):
        # Should return boolean without crashing
        avail = DockerSandbox.is_docker_available()
        self.assertIsInstance(avail, bool)

    @patch("subprocess.run")
    def test_mocked_download_and_zip(self, mock_run):
        # 1. docker info -> success
        mock_info = MagicMock(returncode=0)
        # 2. docker run -> success
        mock_run_container = MagicMock(returncode=0, stdout="[+] Successfully bundled 1 file(s)", stderr="")
        # 3. docker cp -> success
        mock_cp = MagicMock(returncode=0)
        # 4. docker rm -> success
        mock_rm = MagicMock(returncode=0)

        mock_run.side_effect = [mock_info, mock_run_container, mock_cp, mock_rm]

        sandbox = DockerSandbox()
        with tempfile.TemporaryDirectory() as tmpdir:
            dest_dir = Path(tmpdir)
            # Pre-create the dummy file that docker cp would create
            dummy_zip = dest_dir / "testpkg_1.0.zip"
            dummy_zip.write_bytes(b"PK\x03\x04test")

            result_path = sandbox.download_and_zip_package("testpkg", "1.0", destination_dir=dest_dir)
            self.assertTrue(result_path.exists())
            self.assertEqual(result_path.name, "testpkg_1.0.zip")

    def test_real_docker_sandbox_execution(self):
        """Integration test with real Docker daemon if available."""
        if not DockerSandbox.is_docker_available():
            self.skipTest("Docker daemon not available, skipping integration test.")

        sandbox = DockerSandbox(timeout=60)
        with tempfile.TemporaryDirectory() as tmpdir:
            dest_dir = Path(tmpdir)
            # Test with a lightweight package: cowsay 6.1
            zip_path = sandbox.download_and_zip_package("cowsay", "6.1", destination_dir=dest_dir)

            self.assertTrue(zip_path.exists())
            self.assertGreater(zip_path.stat().st_size, 1000)  # > 1KB
            self.assertTrue(zip_path.name.endswith(".zip"))


if __name__ == "__main__":
    unittest.main()
