"""Docker sandboxing engine for downloading and zipping packages in isolation."""

import logging
import os
import shutil
import subprocess
import tempfile
import uuid
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


class SandboxError(Exception):
    """Exception raised for sandbox execution errors."""
    pass


class DockerSandbox:
    """Manages an isolated ephemeral Docker container to download and zip packages."""

    def __init__(
        self,
        image: str = "python:3.12-slim",
        timeout: int = 120,
    ):
        self.image = image
        self.timeout = timeout

    @staticmethod
    def is_docker_available() -> bool:
        """Check if Docker CLI and daemon are accessible."""
        try:
            res = subprocess.run(
                ["docker", "info"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            return res.returncode == 0
        except Exception:
            return False

    def download_and_zip_package(
        self,
        package_name: str,
        version: Optional[str] = None,
        destination_dir: Optional[Path] = None,
    ) -> Path:
        """Spin up a sandboxed Docker container, download the package, zip it, and destroy the container.
        
        Args:
            package_name: Name of the PyPI package.
            version: Optional package version.
            destination_dir: Local directory to store the extracted .zip file.
            
        Returns:
            Path to the zipped package artifact on the host.
            
        Raises:
            SandboxError: If download, zipping, or container execution fails.
        """
        if not self.is_docker_available():
            raise SandboxError("Docker daemon is not reachable. Ensure Docker Desktop is running.")

        container_name = f"pypi_sb_{uuid.uuid4().hex[:10]}"
        spec = f"{package_name}=={version}" if version else package_name

        if destination_dir is None:
            temp_workdir = Path(tempfile.mkdtemp(prefix="pypi_sb_"))
        else:
            destination_dir.mkdir(parents=True, exist_ok=True)
            temp_workdir = destination_dir

        host_zip_path = temp_workdir / f"{package_name}_{version or 'latest'}.zip"

        # Python script to run inside container:
        # 1. pip download --no-deps package_spec into /sandbox/download
        # 2. zip all downloaded files into /sandbox/library.zip
        container_script = (
            "import os, sys, subprocess, zipfile\n"
            "os.makedirs('/sandbox/download', exist_ok=True)\n"
            f"spec = {repr(spec)}\n"
            "print(f'[*] Sandboxed download of {spec}...')\n"
            "res = subprocess.run([sys.executable, '-m', 'pip', 'download', '--no-deps', spec, '-d', '/sandbox/download'], capture_output=True, text=True)\n"
            "if res.returncode != 0:\n"
            "    print(f'[!] pip download error: {res.stderr}', file=sys.stderr)\n"
            "    sys.exit(res.returncode)\n"
            "files = [os.path.join('/sandbox/download', f) for f in os.listdir('/sandbox/download')]\n"
            "if not files:\n"
            "    print('[!] No files downloaded', file=sys.stderr)\n"
            "    sys.exit(1)\n"
            "with zipfile.ZipFile('/sandbox/library.zip', 'w', compression=zipfile.ZIP_DEFLATED) as zf:\n"
            "    for f in files:\n"
            "        zf.write(f, os.path.basename(f))\n"
            "print(f'[+] Successfully bundled {len(files)} file(s) into /sandbox/library.zip')\n"
        )

        docker_cmd = [
            "docker",
            "run",
            "--name",
            container_name,
            "--memory=512m",
            "--cpus=1.0",
            "--security-opt=no-new-privileges",
            self.image,
            "python",
            "-c",
            container_script,
        ]

        logger.info("Spreading ephemeral sandbox container: %s for package %s", container_name, spec)

        try:
            # 1. Run container and download/zip
            proc = subprocess.run(
                docker_cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )

            if proc.returncode != 0:
                logger.error("Sandbox execution failed for %s:\n%s\n%s", spec, proc.stdout, proc.stderr)
                raise SandboxError(f"Container download/zip failed: {proc.stderr or proc.stdout}")

            logger.info("Container stdout:\n%s", proc.stdout.strip())

            # 2. Copy the zipped archive out of the container to the host
            cp_cmd = ["docker", "cp", f"{container_name}:/sandbox/library.zip", str(host_zip_path)]
            cp_proc = subprocess.run(cp_cmd, capture_output=True, text=True, timeout=30)
            if cp_proc.returncode != 0:
                raise SandboxError(f"Failed to copy archive from container: {cp_proc.stderr}")

            if not host_zip_path.exists() or host_zip_path.stat().st_size == 0:
                raise SandboxError(f"Retrieved zip file is empty or missing: {host_zip_path}")

            logger.info("Retrieved sandboxed archive: %s (%.2f KB)", host_zip_path.name, host_zip_path.stat().st_size / 1024.0)
            return host_zip_path

        finally:
            # 3. Always destroy the container
            logger.info("Destroying sandboxed container: %s", container_name)
            rm_proc = subprocess.run(
                ["docker", "rm", "-f", container_name],
                capture_output=True,
                text=True,
                timeout=20,
            )
            if rm_proc.returncode != 0:
                logger.warning("Failed to cleanly remove container %s: %s", container_name, rm_proc.stderr)
            else:
                logger.info("Container %s successfully destroyed", container_name)
