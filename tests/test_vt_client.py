"""Unit tests for VirusTotal API client."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch
import urllib.error

from pypi_scanner.vt_client import (
    VirusTotalClient,
    VTAuthError,
    VTClientError,
    VTRateLimitError,
)


class TestVirusTotalClient(unittest.TestCase):

    def test_missing_api_key_raises_auth_error(self):
        client = VirusTotalClient(api_key=None, mock=False)
        with patch.dict("os.environ", {}, clear=True):
            client.api_key = None
            with self.assertRaises(VTAuthError):
                client.lookup_file_hash("a" * 64)

    def test_mock_client_lookup_clean(self):
        client = VirusTotalClient(api_key="mock", mock=True)
        sha = "1" * 64
        client.set_mock_hash_result(sha, {
            "last_analysis_stats": {
                "harmless": 2,
                "undetected": 68,
                "malicious": 0,
                "suspicious": 0,
            }
        })
        stats = client.lookup_file_hash(sha)
        self.assertIsNotNone(stats)
        self.assertTrue(stats.is_clean())
        self.assertEqual(stats.undetected, 68)

    def test_mock_client_lookup_404_not_found(self):
        client = VirusTotalClient(api_key="mock", mock=True)
        sha_unknown = "2" * 64
        client.set_mock_hash_result(sha_unknown, None)
        stats = client.lookup_file_hash(sha_unknown)
        self.assertIsNone(stats)

    @patch("urllib.request.urlopen")
    def test_live_lookup_404_handling(self, mock_urlopen):
        client = VirusTotalClient(api_key="test_key", mock=False)
        err = urllib.error.HTTPError(
            url="https://www.virustotal.com/api/v3/files/123",
            code=404,
            msg="Not Found",
            hdrs={},
            fp=None,
        )
        mock_urlopen.side_effect = err
        stats = client.lookup_file_hash("3" * 64)
        self.assertIsNone(stats)

    def test_mock_upload_and_poll(self):
        client = VirusTotalClient(api_key="mock", mock=True)
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as f:
            f.write(b"PK\x03\x04test_zip_content")
            zip_path = Path(f.name)

        try:
            analysis_id = client.upload_file(zip_path)
            self.assertTrue(analysis_id.startswith("mock_analysis_"))
            stats = client.poll_analysis(analysis_id, timeout=10, interval=1)
            self.assertIsNotNone(stats)
            self.assertTrue(stats.is_clean())
        finally:
            zip_path.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
