"""Command-line interface and safe-pip interceptor wrapper."""

import argparse
import json
import logging
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from pypi_scanner.engine import ScannerEngine
from pypi_scanner.models import (
    PackageScanResult,
    ScannerConfig,
    ScanVerdict,
    UnknownMode,
)
from pypi_scanner.sandbox import DockerSandbox
from pypi_scanner.shim import PipShimManager

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("pypi_scanner")


def load_env_file(env_path: Path) -> None:
    """Load key-value pairs from a .env file into os.environ if not already set."""
    if not env_path.is_file():
        return
    try:
        for line in env_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, val = line.split("=", 1)
            key = key.strip()
            val = val.strip().strip("'\"")
            if key not in os.environ:
                os.environ[key] = val
    except Exception as e:
        logger.debug("Failed reading .env file %s: %s", env_path, e)


def load_config_file(config_path: Path) -> Dict[str, Any]:
    """Load configuration from a JSON file."""
    if not config_path.is_file():
        return {}
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        logger.warning("Error reading config file %s: %s", config_path, e)
        return {}


def build_scanner_config(
    cli_api_key: Optional[str] = None,
    cli_unknown_mode: Optional[str] = None,
    cli_no_cache: bool = False,
    cli_mock_vt: bool = False,
    cli_docker_image: Optional[str] = None,
) -> ScannerConfig:
    """Resolve ScannerConfig from CLI flags, environment variables, .env, and config.json."""
    # 1. Load .env if present
    load_env_file(Path(".env"))
    load_env_file(Path.cwd() / ".env")

    # 2. Load config.json if present
    cfg_data: Dict[str, Any] = {}
    local_cfg = Path("config.json")
    user_cfg = Path.home() / ".pypi_scanner" / "config.json"
    if local_cfg.is_file():
        cfg_data = load_config_file(local_cfg)
    elif user_cfg.is_file():
        cfg_data = load_config_file(user_cfg)

    # 3. Resolve VT API Key
    vt_key = (
        cli_api_key
        or os.environ.get("VIRUSTOTAL_API_KEY")
        or os.environ.get("VT_API_KEY")
        or cfg_data.get("virustotal_api_key")
    )

    # 4. Resolve Unknown Mode (block or sandbox)
    mode_str = (
        cli_unknown_mode
        or os.environ.get("PYPI_SCANNER_UNKNOWN_MODE")
        or cfg_data.get("unknown_mode", "block")
    )
    unknown_mode = UnknownMode.from_str(mode_str)

    # 5. Resolve Docker Image
    docker_image = (
        cli_docker_image
        or os.environ.get("PYPI_SCANNER_DOCKER_IMAGE")
        or cfg_data.get("docker_image", "python:3.12-slim")
    )

    # 6. Resolve Mock VT
    mock_vt = (
        cli_mock_vt
        or os.environ.get("PYPI_SCANNER_MOCK_VT", "").lower() in ("true", "1", "yes")
        or cfg_data.get("mock_vt", False)
    )

    # 7. Cache settings
    cache_enabled = not cli_no_cache and cfg_data.get("cache_enabled", True)

    return ScannerConfig(
        vt_api_key=vt_key,
        unknown_mode=unknown_mode,
        docker_image=docker_image,
        mock_vt=mock_vt,
        cache_enabled=cache_enabled,
        max_malicious=int(cfg_data.get("max_malicious", 0)),
        max_suspicious=int(cfg_data.get("max_suspicious", 0)),
    )


def print_banner() -> None:
    banner = """
======================================================================
  PyPI Supply Chain Security Scanner & VirusTotal Gatekeeper
======================================================================
"""
    print(banner)


def print_results_table(results: List[PackageScanResult]) -> None:
    """Print formatted summary table of scan results."""
    print("\n" + "=" * 80)
    print(f"{'PACKAGE':<30} {'VERDICT':<12} {'SHA-256 (PREFIX)':<18} {'DETAILS'}")
    print("-" * 80)
    for r in results:
        pkg_str = r.target.display_name[:28]
        verdict_str = r.verdict.value
        sha_str = (r.sha256[:16] + "...") if r.sha256 else "N/A"
        details_str = r.details[:50]
        print(f"{pkg_str:<30} {verdict_str:<12} {sha_str:<18} {details_str}")
    print("=" * 80 + "\n")


def run_install_interceptor(args: List[str]) -> int:
    """Intercept 'pip install' command, scan packages, and gate installation."""
    print_banner()

    # Extract scanner-specific flags if present before or mixed in args
    cli_api_key = None
    cli_unknown_mode = None
    cli_mock_vt = False
    cli_no_cache = False
    filtered_pip_args: List[str] = []

    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "--vt-api-key" and i + 1 < len(args):
            cli_api_key = args[i + 1]
            i += 2
            continue
        elif arg.startswith("--vt-api-key="):
            cli_api_key = arg.split("=", 1)[1]
            i += 1
            continue
        elif arg == "--on-unknown" and i + 1 < len(args):
            cli_unknown_mode = args[i + 1]
            i += 2
            continue
        elif arg.startswith("--on-unknown="):
            cli_unknown_mode = arg.split("=", 1)[1]
            i += 1
            continue
        elif arg == "--mock-vt":
            cli_mock_vt = True
            i += 1
            continue
        elif arg == "--no-cache":
            cli_no_cache = True
            i += 1
            continue
        else:
            filtered_pip_args.append(arg)
            i += 1

    config = build_scanner_config(
        cli_api_key=cli_api_key,
        cli_unknown_mode=cli_unknown_mode,
        cli_mock_vt=cli_mock_vt,
        cli_no_cache=cli_no_cache,
    )

    print(f"[*] Unknown Mode: {config.unknown_mode.value.upper()}")
    print(f"[*] Cache Enabled: {config.cache_enabled}")
    if config.mock_vt:
        print("[*] Mock VirusTotal Mode: ACTIVE")
    elif not config.vt_api_key:
        print("[!] WARNING: No VirusTotal API key found. Live API queries will fail unless configured or run with --mock-vt.")

    print(f"[*] Resolving packages and holding download for: {' '.join(filtered_pip_args)}")

    engine = ScannerEngine(config=config)
    passed, results = engine.scan_pip_install_targets(filtered_pip_args)

    if results:
        print_results_table(results)

    if not passed:
        print("\n[!!!] SECURITY GATE BLOCKED: One or more packages failed verification!")
        print("[!!!] Pip download and installation have been HALTED to protect your environment.\n")
        return 1

    print("[+] All packages verified CLEAN. Releasing hold and continuing installation...\n")
    return engine.execute_real_pip_install(filtered_pip_args)


def main() -> None:
    """Main CLI entry point for safe-pip and pypi-scanner."""
    raw_args = sys.argv[1:]

    # 1. If no args, print usage or forward to pip
    if not raw_args:
        print_banner()
        print("Usage:")
        print("  safe-pip install <package_spec> [options]")
        print("  pypi-scanner scan <package_spec>")
        print("  pypi-scanner setup-shim")
        print("  pypi-scanner status")
        sys.exit(0)

    cmd = raw_args[0]

    # 2. Intercept 'install' command
    if cmd == "install":
        exit_code = run_install_interceptor(raw_args[1:])
        sys.exit(exit_code)

    # 3. Direct scanning command without installing: 'scan'
    elif cmd == "scan":
        parser = argparse.ArgumentParser(description="Scan package(s) or requirements file against VirusTotal")
        parser.add_argument("target", help="Package specification (e.g. cowsay==6.1) or requirements file")
        parser.add_argument("--on-unknown", choices=["block", "sandbox"], default="block", help="Mode when SHA not found on VT")
        parser.add_argument("--vt-api-key", help="VirusTotal API key")
        parser.add_argument("--mock-vt", action="store_true", help="Simulate VirusTotal API responses")
        parser.add_argument("--no-cache", action="store_true", help="Bypass local cache")
        parsed = parser.parse_args(raw_args[1:])

        config = build_scanner_config(
            cli_api_key=parsed.vt_api_key,
            cli_unknown_mode=parsed.on_unknown,
            cli_mock_vt=parsed.mock_vt,
            cli_no_cache=parsed.no_cache,
        )
        print_banner()
        engine = ScannerEngine(config=config)
        install_args = ["-r", parsed.target] if Path(parsed.target).is_file() else [parsed.target]
        passed, results = engine.scan_pip_install_targets(install_args)
        if results:
            print_results_table(results)
        sys.exit(0 if passed else 1)

    # 4. Setup shim command: 'setup-shim'
    elif cmd == "setup-shim":
        parser = argparse.ArgumentParser(description="Install pip interception shims into environment Scripts/bin")
        parser.add_argument("--as-pip", action="store_true", help="Install directly as 'pip' (overriding default pip)")
        parser.add_argument("--dir", type=Path, help="Explicit target directory for shims")
        parsed = parser.parse_args(raw_args[1:])

        if parsed.as_pip:
            PipShimManager.install_as_pip_override(parsed.dir)
            print("[+] Installed interceptor as 'pip' override.")
        else:
            PipShimManager.install_shim(parsed.dir)
            print("[+] Installed 'safe-pip' shim.")
        sys.exit(0)

    # 5. Status command: 'status'
    elif cmd == "status":
        print_banner()
        cfg = build_scanner_config()
        print("Configuration Status:")
        print(f"  - VT API Key Present: {'Yes' if cfg.vt_api_key else 'No'}")
        print(f"  - Unknown Mode: {cfg.unknown_mode.value.upper()}")
        print(f"  - Docker Sandbox Reachable: {'Yes' if DockerSandbox.is_docker_available() else 'No'}")
        print(f"  - Docker Image: {cfg.docker_image}")
        print(f"  - Cache DB Path: {cfg.cache_db_path}")
        print(f"  - Cache Enabled: {cfg.cache_enabled}")
        sys.exit(0)

    # 6. Pass through any other pip command transparently (list, show, uninstall, cache, etc.)
    else:
        # Non-install pip command: pass directly through to real pip
        cmd_line = [sys.executable, "-m", "pip"] + raw_args
        res = subprocess.run(cmd_line)
        sys.exit(res.returncode)


if __name__ == "__main__":
    main()
