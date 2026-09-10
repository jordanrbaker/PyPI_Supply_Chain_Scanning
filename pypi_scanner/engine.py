"""Core scanning engine orchestrating PyPI resolution, VirusTotal checks, and Docker sandboxing."""

import logging
import os
import subprocess
import sys
from pathlib import Path
from typing import List, Optional, Tuple

from pypi_scanner.cache import ScanCache
from pypi_scanner.models import (
    PackageScanResult,
    PackageTarget,
    ScannerConfig,
    ScanVerdict,
    UnknownMode,
    VTAnalysisStats,
)
from pypi_scanner.pypi_client import PyPIClient
from pypi_scanner.resolver import PackageResolver
from pypi_scanner.sandbox import DockerSandbox, SandboxError
from pypi_scanner.vt_client import (
    VirusTotalClient,
    VTAuthError,
    VTClientError,
    VTRateLimitError,
)

logger = logging.getLogger(__name__)


class ScannerEngine:
    """Security gatekeeper that inspects pip packages before download or installation."""

    def __init__(
        self,
        config: Optional[ScannerConfig] = None,
        pypi_client: Optional[PyPIClient] = None,
        vt_client: Optional[VirusTotalClient] = None,
        cache: Optional[ScanCache] = None,
        sandbox: Optional[DockerSandbox] = None,
        resolver: Optional[PackageResolver] = None,
    ):
        self.config = config or ScannerConfig()
        self.pypi_client = pypi_client or PyPIClient()
        self.vt_client = vt_client or VirusTotalClient(
            api_key=self.config.vt_api_key,
            mock=self.config.mock_vt,
        )
        self.cache = cache or (ScanCache(self.config.cache_db_path) if self.config.cache_enabled else None)
        self.sandbox = sandbox or DockerSandbox(
            image=self.config.docker_image,
            timeout=self.config.docker_timeout,
        )
        self.resolver = resolver or PackageResolver(pypi_client=self.pypi_client)

    def scan_pip_install_targets(self, install_args: List[str]) -> Tuple[bool, List[PackageScanResult]]:
        """Resolve and scan all targets from pip install arguments.
        
        Args:
            install_args: Arguments passed to pip install.
            
        Returns:
            Tuple of (all_passed: bool, results: List[PackageScanResult]).
        """
        logger.info("Resolving package targets for args: %s", install_args)
        targets = self.resolver.resolve_install_args(install_args)

        if not targets:
            logger.warning("No discrete packages could be resolved from install arguments.")
            return True, []

        results: List[PackageScanResult] = []
        all_passed = True

        for target in targets:
            result = self.scan_target(target)
            results.append(result)
            if not result.is_passed:
                all_passed = False

        return all_passed, results

    def scan_target(self, target: PackageTarget) -> PackageScanResult:
        """Scan a single package target against VirusTotal.
        
        Evaluates SHA-256 on VirusTotal. If not found, branches into:
        - Mode 1: Block download
        - Mode 2: Sandboxed Docker container download, zip, submit, and destroy container.
        """
        logger.info("--- Scanning package: %s ---", target.display_name)

        # 1. Resolve SHA-256 if not already populated
        sha256 = target.sha256
        if not sha256:
            sha256 = self.pypi_client.get_sha256(target.name, target.version, target.filename)
            target.sha256 = sha256

        # 2. Check local SQLite cache
        if sha256 and self.cache:
            cached_result = self.cache.get(sha256)
            if cached_result:
                logger.info("[CACHE HIT] %s (SHA: %s...) -> Verdict: %s", target.name, sha256[:12], cached_result.verdict.value)
                cached_result.target = target
                return cached_result

        # 3. If SHA-256 is present, look it up on VirusTotal
        if sha256:
            try:
                stats = self.vt_client.lookup_file_hash(sha256)
            except VTAuthError as e:
                logger.error("Authentication Error: %s", e)
                return PackageScanResult(
                    target=target,
                    verdict=ScanVerdict.ERROR,
                    sha256=sha256,
                    details=str(e),
                )
            except VTRateLimitError as e:
                logger.error("Rate Limit Error: %s", e)
                return PackageScanResult(
                    target=target,
                    verdict=ScanVerdict.ERROR,
                    sha256=sha256,
                    details=str(e),
                )
            except VTClientError as e:
                logger.error("VirusTotal API error: %s", e)
                return PackageScanResult(
                    target=target,
                    verdict=ScanVerdict.ERROR,
                    sha256=sha256,
                    details=str(e),
                )

            if stats is not None:
                # File hash FOUND on VirusTotal
                return self._evaluate_vt_stats(target, sha256, stats)

        # 4. SHA-256 NOT found on VirusTotal (or not available on PyPI)
        logger.warning("SHA-256 for %s (%s) NOT found on VirusTotal.", target.display_name, sha256 or "Unknown SHA")
        return self._handle_unknown_target(target, sha256)

    def _evaluate_vt_stats(self, target: PackageTarget, sha256: str, stats: VTAnalysisStats) -> PackageScanResult:
        """Evaluate VirusTotal stats against security thresholds."""
        vt_url = f"https://www.virustotal.com/gui/file/{sha256}"
        if stats.is_clean(self.config.max_malicious, self.config.max_suspicious):
            logger.info("[CLEAN] %s verified clean on VirusTotal (Malicious: %d, Suspicious: %d, Undetected: %d)",
                        target.display_name, stats.malicious, stats.suspicious, stats.undetected)
            result = PackageScanResult(
                target=target,
                verdict=ScanVerdict.CLEAN,
                sha256=sha256,
                stats=stats,
                details=f"Clean on VirusTotal ({stats.undetected + stats.harmless} engines clean, 0 malicious)",
                vt_link=vt_url,
            )
            if self.cache:
                self.cache.set(result, self.config.cache_ttl_hours)
            return result
        else:
            verdict = ScanVerdict.MALICIOUS if stats.malicious > self.config.max_malicious else ScanVerdict.SUSPICIOUS
            logger.error("[THREAT DETECTED] %s flagged by VirusTotal! Malicious: %d, Suspicious: %d",
                         target.display_name, stats.malicious, stats.suspicious)
            result = PackageScanResult(
                target=target,
                verdict=verdict,
                sha256=sha256,
                stats=stats,
                details=f"SECURITY ALERT: {stats.malicious} engine(s) flagged malicious, {stats.suspicious} suspicious!",
                vt_link=vt_url,
            )
            if self.cache:
                self.cache.set(result, self.config.cache_ttl_hours)
            return result

    def _handle_unknown_target(self, target: PackageTarget, sha256: Optional[str]) -> PackageScanResult:
        """Execute configured mode when SHA is not found on VirusTotal."""
        mode = self.config.unknown_mode
        logger.info("Executing Unknown Mode: %s for package %s", mode.value.upper(), target.display_name)

        # MODE 1: Block the download
        if mode == UnknownMode.BLOCK:
            msg = f"Package {target.display_name} (SHA: {sha256 or 'N/A'}) not found on VirusTotal. Unknown mode set to BLOCK. Installation blocked."
            logger.error("[BLOCKED] %s", msg)
            return PackageScanResult(
                target=target,
                verdict=ScanVerdict.BLOCKED,
                sha256=sha256,
                details=msg,
            )

        # MODE 2: Spin up sandboxed docker container, download library, zip it, submit to VT, destroy container
        elif mode == UnknownMode.SANDBOX:
            logger.info("[MODE 2: SANDBOX] Spinning up sandboxed Docker container for %s...", target.display_name)
            zip_path: Optional[Path] = None
            try:
                # 1. Download & zip in Docker sandbox, then destroy container
                zip_path = self.sandbox.download_and_zip_package(
                    package_name=target.name,
                    version=target.version if target.version != "latest" else None,
                )

                # 2. Submit zip file to VirusTotal
                logger.info("Submitting sandboxed archive %s to VirusTotal API...", zip_path.name)
                analysis_id = self.vt_client.upload_file(zip_path)

                # 3. Poll analysis until complete
                stats = self.vt_client.poll_analysis(
                    analysis_id=analysis_id,
                    timeout=self.config.vt_poll_timeout,
                    interval=self.config.vt_poll_interval,
                )

                # 4. Evaluate stats
                if stats.is_clean(self.config.max_malicious, self.config.max_suspicious):
                    logger.info("[SANDBOX CLEAN] %s passed VirusTotal analysis after sandbox packaging!", target.display_name)
                    result = PackageScanResult(
                        target=target,
                        verdict=ScanVerdict.CLEAN,
                        sha256=sha256,
                        stats=stats,
                        details=f"Sandboxed archive submitted and verified clean by VirusTotal ({stats.undetected} clean)",
                        sandbox_used=True,
                    )
                    if self.cache and sha256:
                        self.cache.set(result, self.config.cache_ttl_hours)
                    return result
                else:
                    verdict = ScanVerdict.MALICIOUS if stats.malicious > self.config.max_malicious else ScanVerdict.SUSPICIOUS
                    logger.error("[SANDBOX THREAT] %s flagged as %s after VirusTotal sandbox scan!", target.display_name, verdict.value)
                    result = PackageScanResult(
                        target=target,
                        verdict=verdict,
                        sha256=sha256,
                        stats=stats,
                        details=f"SECURITY ALERT: Sandboxed package flagged with {stats.malicious} malicious detections!",
                        sandbox_used=True,
                    )
                    if self.cache and sha256:
                        self.cache.set(result, self.config.cache_ttl_hours)
                    return result

            except SandboxError as e:
                logger.error("Sandbox error for %s: %s", target.display_name, e)
                return PackageScanResult(
                    target=target,
                    verdict=ScanVerdict.ERROR,
                    sha256=sha256,
                    details=f"Sandbox execution error: {e}",
                    sandbox_used=True,
                )
            except Exception as e:
                logger.error("Error during sandboxed VT analysis: %s", e)
                return PackageScanResult(
                    target=target,
                    verdict=ScanVerdict.ERROR,
                    sha256=sha256,
                    details=f"Sandboxed analysis error: {e}",
                    sandbox_used=True,
                )
            finally:
                if zip_path and zip_path.exists():
                    try:
                        # Clean up temp host file
                        os.remove(zip_path)
                        if zip_path.parent.name.startswith("pypi_sb_"):
                            import shutil
                            shutil.rmtree(zip_path.parent, ignore_errors=True)
                    except Exception:
                        pass

        return PackageScanResult(
            target=target,
            verdict=ScanVerdict.BLOCKED,
            sha256=sha256,
            details=f"Unknown mode '{mode}' unsupported.",
        )

    def execute_real_pip_install(self, pip_args: List[str]) -> int:
        """Run the real pip install command after security validation has succeeded."""
        logger.info("Security checks PASSED. Continuing with pip install: %s", " ".join(pip_args))
        cmd = [sys.executable, "-m", "pip", "install"] + pip_args
        proc = subprocess.run(cmd)
        return proc.returncode
