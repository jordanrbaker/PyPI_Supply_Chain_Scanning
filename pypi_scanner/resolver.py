"""Package and dependency resolver that extracts target packages and SHA-256 hashes."""

import json
import logging
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import List, Optional, Tuple

from pypi_scanner.models import PackageTarget
from pypi_scanner.pypi_client import PyPIClient

logger = logging.getLogger(__name__)


class PackageResolver:
    """Resolves package requirements into concrete PackageTarget objects with SHA-256 hashes."""

    def __init__(self, pypi_client: Optional[PyPIClient] = None):
        self.pypi_client = pypi_client or PyPIClient()

    def resolve_install_args(self, install_args: List[str]) -> List[PackageTarget]:
        """Resolve pip install arguments into a list of targets with SHA-256 hashes.
        
        Args:
            install_args: Arguments passed to 'pip install' (e.g. ['requests', 'flask==3.0', '-r', 'requirements.txt']).
            
        Returns:
            List of PackageTarget objects.
        """
        # First attempt: pip install --dry-run --report
        targets = self._resolve_via_pip_report(install_args)
        if targets:
            logger.info("Successfully resolved %d package(s) via pip dry-run report", len(targets))
            return targets

        # Fallback: direct requirement parsing + PyPI JSON API
        logger.info("Falling back to direct requirement spec parsing + PyPI API lookup")
        return self._resolve_via_pypi_api(install_args)

    def _resolve_via_pip_report(self, install_args: List[str]) -> List[PackageTarget]:
        """Use pip's native dry-run report feature to resolve packages and hashes."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            tmp_report_path = tmp.name

        try:
            # We add --ignore-installed so pip resolves all dependencies even if currently present
            cmd = [
                sys.executable,
                "-m",
                "pip",
                "install",
                "--dry-run",
                "--ignore-installed",
                "--report",
                tmp_report_path,
            ] + install_args

            logger.debug("Running pip dry-run command: %s", " ".join(cmd))
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=90,
            )

            if proc.returncode != 0:
                logger.warning("pip dry-run exited with code %d: %s", proc.returncode, proc.stderr)
                return []

            if not os.path.exists(tmp_report_path) or os.path.getsize(tmp_report_path) == 0:
                return []

            with open(tmp_report_path, "r", encoding="utf-8") as f:
                report = json.load(f)

            targets: List[PackageTarget] = []
            install_list = report.get("install", [])
            for item in install_list:
                meta = item.get("metadata", {})
                name = meta.get("name", "")
                version = meta.get("version", "")
                download_info = item.get("download_info", {})
                url = download_info.get("url", "")
                
                # Extract hash
                archive_info = download_info.get("archive_info", {})
                hashes = archive_info.get("hashes", {})
                sha256 = hashes.get("sha256")
                if not sha256 and archive_info.get("hash"):
                    h_val = archive_info.get("hash")
                    if h_val.startswith("sha256="):
                        sha256 = h_val[7:]

                # Extract filename from URL
                filename = None
                if url:
                    filename = url.split("/")[-1].split("?")[0].split("#")[0]

                # If SHA256 was not in report, fetch from PyPI API
                if not sha256 and name and version:
                    sha256 = self.pypi_client.get_sha256(name, version, filename)

                if name:
                    targets.append(
                        PackageTarget(
                            name=name,
                            version=version,
                            filename=filename,
                            sha256=sha256.lower() if sha256 else None,
                            download_url=url,
                            is_direct=item.get("is_direct", False),
                            requires_python=meta.get("requires_python"),
                        )
                    )

            return targets

        except Exception as e:
            logger.warning("Failed to generate pip dry-run report: %s", e)
            return []
        finally:
            if os.path.exists(tmp_report_path):
                try:
                    os.remove(tmp_report_path)
                except OSError:
                    pass

    def _resolve_via_pypi_api(self, install_args: List[str]) -> List[PackageTarget]:
        """Fallback resolver that parses requirements and queries the PyPI JSON API."""
        specs = self._extract_specs_from_args(install_args)
        targets: List[PackageTarget] = []

        for name, ver in specs:
            pkg_data = self.pypi_client.get_package_data(name, ver)
            if not pkg_data:
                logger.warning("Could not find package '%s' on PyPI", name)
                targets.append(PackageTarget(name=name, version=ver or "latest"))
                continue

            info = pkg_data.get("info", {})
            actual_name = info.get("name", name)
            actual_version = info.get("version", ver or "")
            sha256 = self.pypi_client.get_sha256(actual_name, actual_version)

            targets.append(
                PackageTarget(
                    name=actual_name,
                    version=actual_version,
                    sha256=sha256,
                    download_url=info.get("package_url"),
                    requires_python=info.get("requires_python"),
                )
            )

        return targets

    def _extract_specs_from_args(self, args: List[str]) -> List[Tuple[str, Optional[str]]]:
        """Extract (package_name, version) pairs from CLI arguments, ignoring options."""
        specs: List[Tuple[str, Optional[str]]] = []
        skip_next = False

        # Options that take an argument
        opts_with_arg = {
            "-r", "--requirement",
            "-f", "--find-links",
            "-i", "--index-url",
            "--extra-index-url",
            "-t", "--target",
            "-b", "--build",
            "-c", "--constraint",
            "--prefix",
            "--root",
            "--trusted-host",
            "--platform",
            "--python-version",
            "--implementation",
            "--abi",
        }

        i = 0
        while i < len(args):
            arg = args[i]
            if skip_next:
                skip_next = False
                i += 1
                continue

            if arg in opts_with_arg:
                if arg in ("-r", "--requirement") and i + 1 < len(args):
                    req_file = args[i + 1]
                    specs.extend(self._parse_requirements_file(req_file))
                skip_next = True
                i += 1
                continue

            if arg.startswith("-r") or arg.startswith("--requirement="):
                req_file = arg.split("=", 1)[1] if "=" in arg else arg[2:]
                specs.extend(self._parse_requirements_file(req_file))
                i += 1
                continue

            if arg.startswith("-"):
                i += 1
                continue

            # It's a package specification like 'requests', 'cowsay>=6.0', 'flask==3.0.0'
            parsed = self._parse_single_spec(arg)
            if parsed:
                specs.append(parsed)
            i += 1

        return specs

    def _parse_single_spec(self, spec_str: str) -> Optional[Tuple[str, Optional[str]]]:
        """Parse a single requirement string into (name, version)."""
        clean = spec_str.strip()
        if not clean or clean.startswith("#"):
            return None

        # Remove environment markers or extras: e.g. "requests[security]>=2.0; python_version>'3'"
        clean = clean.split(";")[0].strip()
        clean = re.sub(r"\[.*?\]", "", clean).strip()

        # Check for explicit equality version ==
        match_eq = re.match(r"^([A-Za-z0-9_.\-]+)\s*==\s*([A-Za-z0-9_.\-+]+)$", clean)
        if match_eq:
            return match_eq.group(1), match_eq.group(2)

        # Other operators (>=, <=, ~=, <, >)
        match_other = re.match(r"^([A-Za-z0-9_.\-]+)", clean)
        if match_other:
            pkg_name = match_other.group(1)
            # Try to grab version number if present
            ver_match = re.search(r"[><=~!]=?\s*([0-9A-Za-z_.\-+]+)", clean)
            ver = ver_match.group(1) if ver_match else None
            return pkg_name, ver

        return clean, None

    def _parse_requirements_file(self, file_path_str: str) -> List[Tuple[str, Optional[str]]]:
        """Parse requirement entries from a requirements.txt file."""
        path = Path(file_path_str)
        if not path.exists():
            logger.warning("Requirements file not found: %s", file_path_str)
            return []

        specs: List[Tuple[str, Optional[str]]] = []
        try:
            for line in path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("-"):
                    continue
                parsed = self._parse_single_spec(line)
                if parsed:
                    specs.append(parsed)
        except Exception as e:
            logger.error("Error reading requirements file %s: %s", file_path_str, e)

        return specs
