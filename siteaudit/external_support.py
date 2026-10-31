"""Shared helpers for optional upstream scanner adapters."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence
from urllib.parse import urlsplit


MAX_ENGINE_OUTPUT_BYTES = 16_000_000


class EngineUnavailable(RuntimeError):
    """Raised when an explicitly requested scanner executable is missing."""


class EngineRunError(RuntimeError):
    """Raised when an upstream scanner fails or exceeds local limits."""

    def __init__(
        self,
        message: str,
        *,
        partial_stdout: str = "",
        partial_stderr: str = "",
        duration_seconds: float | None = None,
    ) -> None:
        super().__init__(message)
        self.partial_stdout = partial_stdout
        self.partial_stderr = partial_stderr
        self.duration_seconds = duration_seconds


@dataclass(frozen=True, slots=True)
class ProcessOutput:
    returncode: int
    stdout: str
    stderr: str
    duration_seconds: float


def find_executable(*names: str) -> str:
    engine_home = get_engine_home()
    search_roots = (
        engine_home,
        engine_home / "bin",
        engine_home / "nuclei",
        engine_home / "nikto" / "program",
        engine_home / "wapiti" / "Scripts",
        engine_home / "wapiti" / "bin",
        engine_home / "perl" / "perl" / "bin",
    )
    suffixes = ("", ".exe", ".bat", ".cmd") if os.name == "nt" else ("",)
    for name in names:
        for root in search_roots:
            for suffix in suffixes:
                candidate = root / f"{name}{suffix}"
                try:
                    if candidate.is_file():
                        return str(candidate)
                except OSError:
                    continue
    for name in names:
        resolved = shutil.which(name)
        if resolved:
            return resolved
    shown = ", ".join(names)
    raise EngineUnavailable(
        f"Required executable not found in PATH or the managed engine directory "
        f"{engine_home} (tried: {shown})"
    )


def get_engine_home() -> Path:
    """Return the per-user directory reserved for explicitly installed engines."""
    configured = os.environ.get("SITEAUDIT_ENGINE_HOME")
    if configured:
        return Path(configured).expanduser()
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA")
        return Path(base) / "SiteAudit" / "engines" if base else Path.home() / "AppData" / "Local" / "SiteAudit" / "engines"
    data_home = os.environ.get("XDG_DATA_HOME")
    return (Path(data_home) if data_home else Path.home() / ".local" / "share") / "siteaudit" / "engines"


def run_command(
    command: Sequence[str],
    *,
    timeout: float,
    cwd: str | Path | None = None,
    output_limit: int = MAX_ENGINE_OUTPUT_BYTES,
    monitored_paths: Sequence[str | Path] = (),
    env: Mapping[str, str] | None = None,
) -> ProcessOutput:
    """Run one known scanner command without a shell and cap its captured output."""
    if not command or any(not isinstance(part, str) or "\x00" in part for part in command):
        raise EngineRunError("Invalid external scanner command")
    if timeout <= 0 or output_limit < 1:
        raise EngineRunError("Invalid external scanner process limits")

    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="siteaudit-engine-") as temp_dir:
        stdout_path = Path(temp_dir) / "stdout.bin"
        stderr_path = Path(temp_dir) / "stderr.bin"
        creation_flags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) if os.name == "nt" else 0
        try:
            with stdout_path.open("wb") as stdout_file, stderr_path.open("wb") as stderr_file:
                process = subprocess.Popen(
                    list(command),
                    stdin=subprocess.DEVNULL,
                    stdout=stdout_file,
                    stderr=stderr_file,
                    cwd=str(cwd) if cwd is not None else None,
                    env=dict(env) if env is not None else None,
                    shell=False,
                    close_fds=True,
                    creationflags=creation_flags,
                )
                while process.poll() is None:
                    elapsed = time.monotonic() - started
                    output_size = stdout_path.stat().st_size + stderr_path.stat().st_size
                    for monitored_path in monitored_paths:
                        output_size += _path_size(Path(monitored_path))
                    if output_size > output_limit:
                        process.kill()
                        process.wait()
                        raise EngineRunError(
                            f"External scanner output exceeded {output_limit} bytes",
                            partial_stdout=_capture_output(stdout_path, output_limit),
                            partial_stderr=_capture_output(stderr_path, output_limit),
                            duration_seconds=round(time.monotonic() - started, 3),
                        )
                    if elapsed > timeout:
                        process.kill()
                        process.wait()
                        raise EngineRunError(
                            f"External scanner exceeded the {timeout:g}-second time limit",
                            partial_stdout=_capture_output(stdout_path, output_limit),
                            partial_stderr=_capture_output(stderr_path, output_limit),
                            duration_seconds=round(time.monotonic() - started, 3),
                        )
                    time.sleep(0.05)
                output_size = stdout_path.stat().st_size + stderr_path.stat().st_size
                for monitored_path in monitored_paths:
                    output_size += _path_size(Path(monitored_path))
                if output_size > output_limit:
                    raise EngineRunError(
                        f"External scanner output exceeded {output_limit} bytes",
                        partial_stdout=_capture_output(stdout_path, output_limit),
                        partial_stderr=_capture_output(stderr_path, output_limit),
                        duration_seconds=round(time.monotonic() - started, 3),
                    )
            stdout = stdout_path.read_bytes().decode("utf-8", errors="replace")
            stderr = stderr_path.read_bytes().decode("utf-8", errors="replace")
        except FileNotFoundError as exc:
            raise EngineUnavailable(f"Could not start external scanner: {command[0]}") from exc
        except OSError as exc:
            raise EngineRunError(f"Could not run external scanner: {exc}") from exc

    return ProcessOutput(
        returncode=process.returncode,
        stdout=stdout,
        stderr=stderr,
        duration_seconds=round(time.monotonic() - started, 3),
    )


def _capture_output(path: Path, byte_limit: int) -> str:
    try:
        return path.read_bytes()[:byte_limit].decode("utf-8", errors="replace")
    except OSError:
        return ""


def scoped_url(ctx: Any, value: Any) -> str | None:
    if not isinstance(value, str) or not value or len(value) > 4096:
        return None
    try:
        ctx._check_scope(value)
        parts = urlsplit(value)
        if parts.username or parts.password:
            return None
    except (TypeError, ValueError, UnicodeError):
        return None
    return value


def add_engine_finding(
    ctx: Any,
    *,
    engine: str,
    issue_id: Any,
    title: Any,
    severity: Any,
    url: Any,
    evidence: Any,
    recommendation: Any = None,
    references: Any = None,
    confidence: str = "medium",
) -> bool:
    scoped = scoped_url(ctx, ctx.base_url) if url is None or url == "" else scoped_url(ctx, url)
    if scoped is None:
        return False

    safe_id = re.sub(r"[^A-Za-z0-9._-]", "_", str(issue_id or "finding"))[:120] or "finding"
    safe_title = _bounded_text(title, 240) or f"{engine} finding"
    safe_severity = str(severity or "info").strip().lower()
    if safe_severity not in {"critical", "high", "medium", "low", "info"}:
        safe_severity = "info"
    safe_confidence = confidence if confidence in {"high", "medium", "low"} else "medium"
    safe_evidence = _bounded_text(evidence, 1000) or f"{engine} reported a matching signature."
    safe_recommendation = _bounded_text(recommendation, 1000) or "Review the matched resource and remediate if it is not intentionally exposed."

    safe_references: list[str] = []
    candidate_references = [references] if isinstance(references, str) else references
    if isinstance(candidate_references, (list, tuple)):
        for reference in candidate_references[:5]:
            if isinstance(reference, str) and reference.startswith("https://") and len(reference) <= 500:
                safe_references.append(reference)

    ctx.add_finding(
        id=f"external.{engine}.{safe_id}",
        title=safe_title,
        severity=safe_severity,
        confidence=safe_confidence,
        url=scoped,
        evidence=safe_evidence,
        recommendation=safe_recommendation,
        category=f"external-{engine}",
        references=safe_references,
    )
    return True


def _bounded_text(value: Any, maximum: int) -> str:
    if not isinstance(value, str):
        return ""
    return " ".join(value.split())[:maximum]


def _path_size(path: Path) -> int:
    """Return the current size of a monitored output file or directory tree."""
    try:
        if path.is_file():
            return path.stat().st_size
        if path.is_dir():
            return sum(item.stat().st_size for item in path.rglob("*") if item.is_file())
    except FileNotFoundError:
        return 0
    return 0
