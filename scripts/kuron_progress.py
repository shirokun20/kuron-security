"""Harness-neutral scan progress: append-only events + a safe one-line renderer.

The event stream is the source of truth. Renderers are projections: a terminal
line on stderr when a real TTY exists, plain milestone lines otherwise. There
is deliberately no alternate-screen and no keyboard input — agent harnesses
often capture stdout, close stdin, and run without a TTY.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import signal
import sys
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

try:  # POSIX advisory locking
    import fcntl
except ImportError:  # pragma: no cover - platform dependent
    fcntl = None
try:  # Windows advisory locking
    import msvcrt
except ImportError:  # pragma: no cover - platform dependent
    msvcrt = None

ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
NON_INTERACTIVE_ENV = ("CI", "GITHUB_ACTIONS", "NO_COLOR", "KURON_NO_TTY")


def sanitize(value: object, limit: int = 80) -> str:
    """Strip ANSI escapes and control characters from untrusted text."""
    text = ANSI_RE.sub("", str(value if value is not None else ""))
    text = CONTROL_RE.sub("", text)
    return " ".join(text.split())[:limit]


def detect_terminal(stream: object = None, env: dict | None = None) -> dict:
    """Return {mode, tty, columns, term}; mode is live, append, or file.

    isatty() alone is not enough: TERM=dumb, CI, and zero-column terminals all
    report a TTY while still breaking escape sequences.
    """
    target = stream if stream is not None else sys.stderr
    environ = os.environ if env is None else env
    is_tty = bool(getattr(target, "isatty", lambda: False)())
    term = str(environ.get("TERM", "") or "")
    non_interactive = any(environ.get(key) for key in NON_INTERACTIVE_ENV)
    columns = shutil.get_terminal_size(fallback=(0, 0)).columns
    if is_tty and term.lower() not in ("", "dumb") and not non_interactive and columns >= 40:
        mode = "live"
    elif is_tty and not non_interactive:
        mode = "append"
    else:
        mode = "file"
    return {"mode": mode, "tty": is_tty, "columns": columns, "term": term}


def elapsed_text(milliseconds: object) -> str:
    try:
        total = max(0, int(milliseconds or 0))
    except (TypeError, ValueError):
        return "0s"
    minutes, seconds = divmod(total // 1000, 60)
    return f"{minutes}m{seconds:02d}s" if minutes else f"{seconds}s"


def progress_line(event: dict, width: int = 0) -> str:
    """Build one ASCII-only line; never let untrusted text change its shape."""
    label = sanitize(event.get("label") or "unverified-single-pass", 24).encode("ascii", "replace").decode("ascii")
    phase = sanitize(event.get("phase") or "-", 8)
    phase_total = sanitize(event.get("phase_total") or "-", 8)
    try:
        done = int(event.get("done") or 0)
        total = int(event.get("total") or 0)
    except (TypeError, ValueError):
        done = total = 0
    message = sanitize(event.get("message") or "", 40).encode("ascii", "replace").decode("ascii")
    parts = [
        f"[KURON] {done}/{total}",
        f"phase {phase}/{phase_total}",
        elapsed_text(event.get("elapsed_ms")),
        label,
    ]
    if message:
        parts.append(message)
    line = " | ".join(parts)
    limit = width - 1 if width >= 20 else 120
    return line[:limit]


@contextmanager
def _exclusive_lock(lock_path: Path):
    """Cross-platform exclusive advisory lock around the read-seq/write-append window."""
    with lock_path.open("a+b") as handle:
        if fcntl is not None:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        elif msvcrt is not None:  # pragma: no cover - platform dependent
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
        try:
            yield
        finally:
            if fcntl is not None:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            elif msvcrt is not None:  # pragma: no cover - platform dependent
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)


def append_event(run_dir: str, event: dict) -> dict:
    """Append one progress event with a caller-supplied trace_id (never synthetic)."""
    directory = Path(run_dir)
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / "progress.jsonl"
    with _exclusive_lock(directory / ".progress.lock"):
        seq = 1
        if target.exists():
            for raw in target.read_text(encoding="utf-8", errors="replace").splitlines():
                try:
                    seq = max(seq, int(json.loads(raw).get("seq", 0)) + 1)
                except (ValueError, TypeError, AttributeError):
                    continue
        record = dict(event)
        record["seq"] = seq
        record["ts"] = datetime.now(timezone.utc).isoformat()
        # Fail closed: an event with no real trace id stays empty and is reported
        # as unverifiable by validate_projection instead of inventing "local-N".
        record["trace_id"] = str(record.get("trace_id") or "")
        with target.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=True, sort_keys=True) + "\n")
            handle.flush()
    return record


def validate_projection(run_dir: str) -> tuple[bool, list[str]]:
    """Every progress event must reference a real trace event; absence fails closed."""
    directory = Path(run_dir)
    progress = directory / "progress.jsonl"
    if not progress.exists():
        return False, ["no progress events"]
    raw_progress = progress.read_text(encoding="utf-8", errors="replace").splitlines()
    if not raw_progress:
        return False, ["empty progress stream"]

    trace = directory / "trace.jsonl"
    trace_ids: set[str] = set()
    if trace.exists():
        for raw in trace.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                value = json.loads(raw).get("trace_id")
                if value:
                    trace_ids.add(str(value))
            except (ValueError, TypeError, AttributeError):
                continue

    missing: list[str] = []
    for raw in raw_progress:
        try:
            record = json.loads(raw)
        except (ValueError, TypeError):
            missing.append("unreadable progress line")
            continue
        trace_id = str(record.get("trace_id") or "")
        if not trace_id:
            missing.append("<missing trace_id>")
        elif trace_id not in trace_ids:
            missing.append(trace_id)
    return (not missing), missing


class ProgressRenderer:
    """Write a throttled one-line projection; never touch alternate-screen."""

    def __init__(
        self,
        stream: object = None,
        mode: str | None = None,
        min_interval_ms: int = 150,
        width: int | None = None,
    ) -> None:
        self.stream = stream if stream is not None else sys.stderr
        detected = detect_terminal(self.stream)
        self.mode = mode or detected["mode"]
        self.width = width if width is not None else detected["columns"]
        self.min_interval_ms = min_interval_ms
        self._last = 0.0
        self._active = False
        self._final: str | None = None

    def render(self, event: dict, force: bool = False) -> str:
        now = time.monotonic()
        if not force and (now - self._last) * 1000 < self.min_interval_ms:
            return ""
        self._last = now
        line = progress_line(event, self.width)
        if self.mode == "live":
            self.stream.write("\r\x1b[2K" + line)
            self.stream.flush()
            self._active = True
        elif self.mode == "append":
            self.stream.write(line + "\n")
            self.stream.flush()
        return line

    def finish(self, text: str, aborted: bool = False) -> str:
        line = sanitize(text, 120)
        if aborted:
            line = "ABORTED " + line
        if self.mode == "live" and self._active:
            self.stream.write("\r\x1b[2K")
        self.stream.write(line + "\n")
        self.stream.flush()
        self._active = False
        self._final = line
        return line

    def __enter__(self) -> "ProgressRenderer":
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> bool:
        if self._active:
            self.finish("interrupted", aborted=True)
        return False


def install_signal_handlers(renderer: ProgressRenderer, final_text: str = "interrupted") -> None:
    """Clean up the live line on SIGINT/SIGTERM (call from a CLI only)."""

    def handler(signum, _frame):
        renderer.finish(final_text, aborted=True)
        raise SystemExit(130 if signum == signal.SIGINT else 143)

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, handler)
        except (ValueError, OSError):
            pass
