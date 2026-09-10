"""Unit tests for package resolver."""

import tempfile
import unittest
from pathlib import Path

from pypi_scanner.resolver import PackageResolver


class TestPackageResolver(unittest.TestCase):

    def setUp(self):
        self.resolver = PackageResolver()

    def test_extract_specs_from_args(self):
        args = ["requests", "flask==3.0.0", "--index-url", "https://custom.repo", "cowsay>=6.0", "-v"]
        specs = self.resolver._extract_specs_from_args(args)
        spec_dict = dict(specs)

        self.assertIn("requests", spec_dict)
        self.assertIn("flask", spec_dict)
        self.assertEqual(spec_dict["flask"], "3.0.0")
        self.assertIn("cowsay", spec_dict)
        self.assertEqual(spec_dict["cowsay"], "6.0")

    def test_parse_requirements_file(self):
        with tempfile.NamedTemporaryFile(suffix=".txt", mode="w+", delete=False, encoding="utf-8") as f:
            f.write("# comment\nrequests==2.31.0\nurllib3>=2.0\n# another comment\npytest\n")
            req_path = Path(f.name)

        try:
            specs = self.resolver._parse_requirements_file(str(req_path))
            spec_dict = dict(specs)
            self.assertEqual(spec_dict.get("requests"), "2.31.0")
            self.assertEqual(spec_dict.get("urllib3"), "2.0")
            self.assertIn("pytest", spec_dict)
        finally:
            req_path.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
