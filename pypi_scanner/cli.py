"""Command-line interface and safe-pip interceptor wrapper standardized for agentic development."""

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
    cli_agent_instruction: Optional[str] = None,
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

    # 8. User / Agent custom fallback instruction
    agent_instruction = (
        cli_agent_instruction
        or os.environ.get("PYPI_SCANNER_AGENT_INSTRUCTION")
        or cfg_data.get("agent_fallback_instruction")
    )

    return ScannerConfig(
        vt_api_key=vt_key,
        unknown_mode=unknown_mode,
        docker_image=docker_image,
        mock_vt=mock_vt,
        cache_enabled=cache_enabled,
        max_malicious=int(cfg_data.get("max_malicious", 0)),
        max_suspicious=int(cfg_data.get("max_suspicious", 0)),
        agent_fallback_instruction=agent_instruction,
    )


def print_agent_header(config: ScannerConfig, targets: List[str]) -> None:
    """Print structured operational header formatted for agentic parser visibility."""
    print("=" * 80)
    print(">>> AGENT_SECURITY_GATE: HOLDING_DOWNLOAD & RESOLVING_DEPENDENCIES")
    print("=" * 80)
    print(f"[AGENT_POLICY] Unknown Mode: {config.unknown_mode.value.upper()} (Fail-closed on unindexed packages)")
    print(f"[AGENT_POLICY] Cache Status: {'ENABLED' if config.cache_enabled else 'DISABLED'}")
    print(f"[AGENT_POLICY] Transitive Dependency Analysis: ENABLED")
    if config.mock_vt:
        print("[AGENT_POLICY] VirusTotal Mock Mode: ACTIVE")
    print(f"[AGENT_TARGETS] Target Arguments: {' '.join(targets)}")
    print("=" * 80 + "\n")


def print_agent_results_table(results: List[PackageScanResult]) -> None:
    """Print structured evaluation table of all analyzed package artifacts."""
    print("\n" + "=" * 80)
    print(">>> AGENT_SECURITY_GATE: EVALUATION REPORT")
    print("=" * 80)
    print(f"{'PACKAGE':<30} {'VERDICT':<12} {'SHA-256 (PREFIX)':<18} {'ANALYSIS DETAILS'}")
    print("-" * 80)
    for r in results:
        pkg_str = r.target.display_name[:28]
        verdict_str = r.verdict.value
        sha_str = (r.sha256[:16] + "...") if r.sha256 else "N/A"
        details_str = r.details[:50]
        print(f"{pkg_str:<30} {verdict_str:<12} {sha_str:<18} {details_str}")
    print("=" * 80)


def print_agent_rejection(failed_results: List[PackageScanResult], custom_instruction: Optional[str] = None) -> None:
    """Print structured rejection report with actionable self-correction instructions for AI agents."""
    print("\n" + "=" * 80)
    print(">>> AGENT_SECURITY_GATE: STATUS = BLOCKED")
    print("=" * 80)
    print("[AGENT_DECISION] INSTALLATION HALTED. No packages were downloaded or executed.\n")
    print("FAILED PACKAGE ARTIFACTS:")
    for r in failed_results:
        print(f"  * Package: {r.target.display_name}")
        print(f"    SHA-256: {r.sha256 or 'N/A'}")
        print(f"    Verdict: {r.verdict.value}")
        print(f"    Reason:  {r.details}")
        if r.verdict == ScanVerdict.BLOCKED:
            print("    Threat:  Unindexed package on VirusTotal. High probability of AI hallucination ('slopsquatting') or untrusted supply chain payload.")
        elif r.verdict in (ScanVerdict.MALICIOUS, ScanVerdict.SUSPICIOUS):
            print("    Threat:  CONFIRMED MALICIOUS/SUSPICIOUS signatures flagged by security engines.")
        print()

    print("=" * 80)
    print("ACTIONABLE INSTRUCTIONS FOR THE AGENT (SELF-CORRECTION REQUIRED):")
    print("=" * 80)
    print("1. DO NOT retry installing the blocked package name(s). The gatekeeper will reject it again.")
    print("2. VERIFY if you hallucinated this package name or misspelled a standard library.")
    print("3. REPLACE this package with a reputable, verified alternative from the Python standard library or top established PyPI packages.")
    if custom_instruction:
        print(f"4. IF NO TRUSTED PACKAGE EXISTS: {custom_instruction}")
    else:
        print("4. IF NO TRUSTED PACKAGE EXISTS: Write the required functionality directly in Python code rather than relying on obscure third-party tools.")
    print("=" * 80 + "\n")


def print_agent_approval() -> None:
    """Print structured pass block for agent visibility."""
    print("\n" + "=" * 80)
    print(">>> AGENT_SECURITY_GATE: STATUS = PASSED")
    print("=" * 80)
    print("[AGENT_DECISION] All resolved packages and transitive dependencies verified clean against VirusTotal.")
    print("[AGENT_DECISION] Releasing hold and continuing pip installation...\n")


def run_install_interceptor(args: List[str]) -> int:
    """Intercept 'pip install' command, scan packages, and gate installation."""
    # Extract scanner-specific flags if present before or mixed in args
    cli_api_key = None
    cli_unknown_mode = None
    cli_mock_vt = False
    cli_no_cache = False
    cli_agent_instruction = None
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
        elif arg == "--agent-instruction" and i + 1 < len(args):
            cli_agent_instruction = args[i + 1]
            i += 2
            continue
        elif arg.startswith("--agent-instruction="):
            cli_agent_instruction = arg.split("=", 1)[1]
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
        cli_agent_instruction=cli_agent_instruction,
    )

    print_agent_header(config, filtered_pip_args)

    engine = ScannerEngine(config=config)
    passed, results = engine.scan_pip_install_targets(filtered_pip_args)

    if results:
        print_agent_results_table(results)

    if not passed:
        failed_targets = [r for r in results if not r.is_passed]
        print_agent_rejection(failed_targets, custom_instruction=config.agent_fallback_instruction)
        return 1

    print_agent_approval()
    return engine.execute_real_pip_install(filtered_pip_args)


def main() -> None:
    """Main CLI entry point for safe-pip and pypi-scanner."""
    raw_args = sys.argv[1:]

    # 1. If no args, print usage
    if not raw_args:
        print("=" * 80)
        print(">>> AGENT_SECURITY_GATE: CLI USAGE")
        print("=" * 80)
        print("Commands:")
        print("  safe-pip install <package_spec> [options]")
        print("  pypi-scanner scan <package_spec> [options]")
        print("  pypi-scanner setup-shim [--as-pip]")
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
        parser.add_argument("--agent-instruction", help="Custom directive injected to the agent if package is rejected")
        parsed = parser.parse_args(raw_args[1:])

        config = build_scanner_config(
            cli_api_key=parsed.vt_api_key,
            cli_unknown_mode=parsed.on_unknown,
            cli_mock_vt=parsed.mock_vt,
            cli_no_cache=parsed.no_cache,
            cli_agent_instruction=parsed.agent_instruction,
        )
        print_agent_header(config, [parsed.target])
        engine = ScannerEngine(config=config)
        install_args = ["-r", parsed.target] if Path(parsed.target).is_file() else [parsed.target]
        passed, results = engine.scan_pip_install_targets(install_args)
        if results:
            print_agent_results_table(results)

        if not passed:
            failed_targets = [r for r in results if not r.is_passed]
            print_agent_rejection(failed_targets, custom_instruction=config.agent_fallback_instruction)
            sys.exit(1)
        else:
            print_agent_approval()
            sys.exit(0)

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
        cfg = build_scanner_config()
        print("=" * 80)
        print(">>> AGENT_SECURITY_GATE: ENVIRONMENT CONFIGURATION STATUS")
        print("=" * 80)
        print(f"  - VT API Key Present: {'Yes' if cfg.vt_api_key else 'No'}")
        print(f"  - Unknown Mode: {cfg.unknown_mode.value.upper()}")
        print(f"  - Docker Sandbox Reachable: {'Yes' if DockerSandbox.is_docker_available() else 'No'}")
        print(f"  - Docker Image: {cfg.docker_image}")
        print(f"  - Cache DB Path: {cfg.cache_db_path}")
        print(f"  - Cache Enabled: {cfg.cache_enabled}")
        print(f"  - Agent Fallback Directive: {cfg.agent_fallback_instruction or 'None (default)'}")
        print("=" * 80)
        sys.exit(0)

    # 6. Pass through any other pip command transparently (list, show, uninstall, cache, etc.)
    else:
        cmd_line = [sys.executable, "-m", "pip"] + raw_args
        res = subprocess.run(cmd_line)
        sys.exit(res.returncode)


if __name__ == "__main__":
    main()
