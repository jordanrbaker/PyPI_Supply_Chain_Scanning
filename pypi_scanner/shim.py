"""Environment shim installer to transparently intercept standard 'pip' commands."""

import logging
import os
import sys
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

WINDOWS_BAT_TEMPLATE = """@echo off
"{python_exe}" -m pypi_scanner.cli %*
"""

WINDOWS_PS1_TEMPLATE = """& "{python_exe}" -m pypi_scanner.cli $args
"""

UNIX_SH_TEMPLATE = """#!/usr/bin/env sh
exec "{python_exe}" -m pypi_scanner.cli "$@"
"""


class PipShimManager:
    """Manages installation and removal of the pip interceptor shim."""

    @staticmethod
    def get_default_scripts_dir() -> Path:
        """Find the default Scripts (Windows) or bin (Unix) directory for the current python environment."""
        if hasattr(sys, "real_prefix") or (hasattr(sys, "base_prefix") and sys.base_prefix != sys.prefix):
            # In a virtualenv
            if os.name == "nt":
                return Path(sys.prefix) / "Scripts"
            return Path(sys.prefix) / "bin"
        else:
            # User scripts dir
            if os.name == "nt":
                return Path(sys.prefix) / "Scripts"
            return Path(sys.prefix) / "bin"

    @classmethod
    def install_shim(cls, target_dir: Optional[Path] = None) -> None:
        """Install safe-pip shim scripts into target_dir."""
        dest_dir = target_dir or cls.get_default_scripts_dir()
        dest_dir.mkdir(parents=True, exist_ok=True)
        py_exe = sys.executable

        if os.name == "nt":
            # Windows: safe-pip.cmd and safe-pip.ps1
            safe_pip_bat = dest_dir / "safe-pip.cmd"
            safe_pip_ps1 = dest_dir / "safe-pip.ps1"
            safe_pip_bat.write_text(WINDOWS_BAT_TEMPLATE.format(python_exe=py_exe), encoding="utf-8")
            safe_pip_ps1.write_text(WINDOWS_PS1_TEMPLATE.format(python_exe=py_exe), encoding="utf-8")
            logger.info("Installed Windows shim scripts: %s, %s", safe_pip_bat, safe_pip_ps1)
        else:
            safe_pip_sh = dest_dir / "safe-pip"
            safe_pip_sh.write_text(UNIX_SH_TEMPLATE.format(python_exe=py_exe), encoding="utf-8")
            safe_pip_sh.chmod(0o755)
            logger.info("Installed Unix shim script: %s", safe_pip_sh)

    @classmethod
    def install_as_pip_override(cls, target_dir: Optional[Path] = None) -> None:
        """Install shim directly as 'pip' (backing up original if needed)."""
        dest_dir = target_dir or cls.get_default_scripts_dir()
        dest_dir.mkdir(parents=True, exist_ok=True)
        py_exe = sys.executable

        if os.name == "nt":
            pip_bat = dest_dir / "pip.cmd"
            pip_ps1 = dest_dir / "pip.ps1"
            pip_bat.write_text(WINDOWS_BAT_TEMPLATE.format(python_exe=py_exe), encoding="utf-8")
            pip_ps1.write_text(WINDOWS_PS1_TEMPLATE.format(python_exe=py_exe), encoding="utf-8")
            logger.info("Installed pip interceptor shims in %s", dest_dir)
        else:
            pip_sh = dest_dir / "pip"
            pip_sh.write_text(UNIX_SH_TEMPLATE.format(python_exe=py_exe), encoding="utf-8")
            pip_sh.chmod(0o755)
            logger.info("Installed pip interceptor shim in %s", dest_dir)
