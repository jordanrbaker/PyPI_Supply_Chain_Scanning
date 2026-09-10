"""Unit tests for PyPI client."""

import unittest
from unittest.mock import MagicMock, patch
from pypi_scanner.pypi_client import PyPIClient


class TestPyPIClient(unittest.TestCase):

    def setUp(self):
        self.client = PyPIClient()

    @patch("urllib.request.urlopen")
    def test_get_package_data_success(self, mock_urlopen):
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.read.return_value = b'{"info": {"name": "cowsay", "version": "6.1"}}'
        mock_urlopen.return_value.__enter__.return_value = mock_response

        data = self.client.get_package_data("cowsay", "6.1")
        self.assertIsNotNone(data)
        self.assertEqual(data["info"]["name"], "cowsay")
        self.assertEqual(data["info"]["version"], "6.1")

    @patch("urllib.request.urlopen")
    def test_get_sha256_by_filename(self, mock_urlopen):
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.read.return_value = (
            b'{"urls": ['
            b'  {"filename": "cowsay-6.1-py3-none-any.whl", "packagetype": "bdist_wheel", "digests": {"sha256": "abc123sha"}},'
            b'  {"filename": "cowsay-6.1.tar.gz", "packagetype": "sdist", "digests": {"sha256": "xyz789sha"}}'
            b']}'
        )
        mock_urlopen.return_value.__enter__.return_value = mock_response

        # Match exact filename
        sha = self.client.get_sha256("cowsay", "6.1", filename="cowsay-6.1-py3-none-any.whl")
        self.assertEqual(sha, "abc123sha")

        # Fallback to wheel if filename not specified
        sha_default = self.client.get_sha256("cowsay", "6.1")
        self.assertEqual(sha_default, "abc123sha")


if __name__ == "__main__":
    unittest.main()
