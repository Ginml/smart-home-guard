"""Real-time network capture service.

Spawns tcpdump in a child process to roll a temporary pcap every 10 seconds,
then drains each closed file through the existing feature-extraction +
LightGBM inference pipeline and inserts the results into Supabase.

Single-session by design: one CaptureService per process, one tcpdump child
at a time. Concurrent `start()` calls return an error.
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd

from backend.models.enums import ClassLabel
from backend.services.feature_service import FeatureService
from backend.services.ml_service import MLService
from backend.services.supabase_client import make_user_client

logger = logging.getLogger(__name__)

INTERFACE_RE = re.compile(r"^[a-zA-Z0-9_-]{1,32}$")
ROTATE_SECONDS = 10
RING_FILES = 6
FILE_SETTLE_SECONDS = 2.0  # a pcap older than this and not the newest is "closed"


def _compute_alert_severity(category: ClassLabel, confidence: float) -> str:
    """Map an ML prediction to an alert severity for the `alerts` table.

    Returns one of: 'critical' | 'high' | 'medium' | 'info'.
    """
    if confidence < 0.6:
        return "info"
    base = {
        ClassLabel.BRUTE_FORCE: "critical",
        ClassLabel.SPOOFING: "high",
        ClassLabel.RECON: "medium",
    }.get(category, "info")
    if confidence < 0.8:
        return {"critical": "high", "high": "medium", "medium": "info"}.get(base, base)
    return base



class CaptureAlreadyRunningError(RuntimeError):
    pass


class CaptureNotRunningError(RuntimeError):
    pass


class TcpdumpUnavailableError(RuntimeError):
    pass


class CaptureService:
    """Single-session live packet capture pipeline."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._proc: subprocess.Popen | None = None
        self._tmpdir: Path | None = None
        self._state: dict[str, Any] = self._fresh_state()

    @staticmethod
    def _fresh_state() -> dict[str, Any]:
        return {
            "running": False,
            "session_id": None,
            "interface": None,
            "flows_captured": 0,
            "threats": 0,
            "last_update": None,
            "error": None,
        }

    # ------------------------------------------------------------------ public

    def start(
        self,
        *,
        interface: str,
        session_id: str,
        user_id: str,
        jwt: str,
        feature_service: FeatureService,
        ml_service: MLService,
    ) -> None:
        if not INTERFACE_RE.match(interface):
            raise ValueError(f"invalid interface name: {interface!r}")

        if shutil.which("tcpdump") is None:
            raise TcpdumpUnavailableError(
                "tcpdump not installed; install via `apt-get install -y tcpdump` "
                "and grant the backend CAP_NET_RAW (or run as root)."
            )

        with self._lock:
            if self._state["running"]:
                raise CaptureAlreadyRunningError(
                    f"capture already running for session {self._state['session_id']}"
                )

            self._stop_event = threading.Event()
            self._tmpdir = Path(tempfile.mkdtemp(prefix="smhg_capture_"))
            self._state = self._fresh_state()
            self._state.update({
                "running": True,
                "session_id": session_id,
                "interface": interface,
                "last_update": datetime.now(timezone.utc).isoformat(),
            })

            self._proc = self._spawn_tcpdump(interface, self._tmpdir)
            self._thread = threading.Thread(
                target=self._run,
                name=f"capture-{session_id}",
                args=(session_id, user_id, jwt, feature_service, ml_service),
                daemon=True,
            )
            self._thread.start()

        logger.info("CaptureService started for session=%s interface=%s", session_id, interface)

    def stop(self) -> dict[str, Any]:
        with self._lock:
            if not self._state["running"]:
                raise CaptureNotRunningError("no capture session is running")

            self._stop_event.set()
            proc = self._proc
            thread = self._thread

        # Terminate tcpdump first so the worker drains any final files.
        if proc is not None and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()

        if thread is not None:
            thread.join(timeout=15)

        with self._lock:
            final = dict(self._state)
            self._state = self._fresh_state()
            self._proc = None
            self._thread = None
            if self._tmpdir is not None and self._tmpdir.exists():
                shutil.rmtree(self._tmpdir, ignore_errors=True)
            self._tmpdir = None

        logger.info("CaptureService stopped — flows=%d threats=%d",
                    final.get("flows_captured", 0), final.get("threats", 0))
        return final

    def get_status(self) -> dict[str, Any]:
        with self._lock:
            return dict(self._state)

    # ----------------------------------------------------------------- worker

    def _spawn_tcpdump(self, interface: str, outdir: Path) -> subprocess.Popen:
        # Ring of RING_FILES files cycling every ROTATE_SECONDS seconds.
        # No shell=True; args list is hardcoded apart from the regex-validated
        # interface name and the temp directory we created.
        template = str(outdir / "cap.pcap")
        cmd = [
            "tcpdump",
            "-i", interface,
            "-G", str(ROTATE_SECONDS),
            "-W", str(RING_FILES),
            "-w", template,
            "-U",  # flush each packet → file mtime updates promptly
            "-n",  # no DNS lookups
        ]
        logger.info("Spawning tcpdump: %s", " ".join(cmd))
        return subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )

    def _run(
        self,
        session_id: str,
        user_id: str,
        jwt: str,
        feature_service: FeatureService,
        ml_service: MLService,
    ) -> None:
        """Worker thread: poll for closed pcap files, process, insert, repeat."""
        try:
            supabase = make_user_client(jwt)
        except Exception as exc:
            logger.exception("CaptureService failed to build Supabase client")
            self._set_error(f"supabase init failed: {exc}")
            return

        processed: set[str] = set()

        try:
            while not self._stop_event.is_set():
                # Bail early if tcpdump died unexpectedly
                if self._proc is not None and self._proc.poll() is not None:
                    rc = self._proc.returncode
                    if rc != 0 and not self._stop_event.is_set():
                        stderr = self._proc.stderr.read().decode(errors="replace") if self._proc.stderr else ""
                        self._set_error(f"tcpdump exited rc={rc}: {stderr.strip()[:200]}")
                        return

                self._drain_closed_files(
                    processed=processed,
                    session_id=session_id,
                    user_id=user_id,
                    supabase=supabase,
                    feature_service=feature_service,
                    ml_service=ml_service,
                )
                # Poll cadence: short relative to ROTATE_SECONDS so we pick up
                # rotations promptly without busy-spinning.
                self._stop_event.wait(timeout=1.0)

            # Final drain after stop signal.
            self._drain_closed_files(
                processed=processed,
                session_id=session_id,
                user_id=user_id,
                supabase=supabase,
                feature_service=feature_service,
                ml_service=ml_service,
                final=True,
            )
        except Exception as exc:  # noqa: BLE001 — never let the thread die silently
            logger.exception("CaptureService worker crashed")
            self._set_error(str(exc))

    def _drain_closed_files(
        self,
        *,
        processed: set[str],
        session_id: str,
        user_id: str,
        supabase,
        feature_service: FeatureService,
        ml_service: MLService,
        final: bool = False,
    ) -> None:
        if self._tmpdir is None:
            return

        candidates = sorted(self._tmpdir.glob("cap.pcap*"), key=lambda p: p.stat().st_mtime)
        if not candidates:
            return

        # Skip the most recent file unless we're in the final drain — tcpdump
        # is likely still appending to it.
        targets = candidates if final else candidates[:-1]
        now = time.time()

        for path in targets:
            if str(path) in processed:
                continue
            try:
                stat = path.stat()
            except FileNotFoundError:
                continue
            if not final and (now - stat.st_mtime) < FILE_SETTLE_SECONDS:
                continue
            if stat.st_size == 0:
                processed.add(str(path))
                path.unlink(missing_ok=True)
                continue

            try:
                self._process_file(
                    path=path,
                    session_id=session_id,
                    user_id=user_id,
                    supabase=supabase,
                    feature_service=feature_service,
                    ml_service=ml_service,
                )
            except Exception as exc:  # noqa: BLE001
                logger.exception("Failed to process capture file %s", path)
                self._set_error(f"file {path.name}: {exc}")
            finally:
                processed.add(str(path))
                path.unlink(missing_ok=True)

    def _process_file(
        self,
        *,
        path: Path,
        session_id: str,
        user_id: str,
        supabase,
        feature_service: FeatureService,
        ml_service: MLService,
    ) -> None:
        # Reuse the synchronous extractors directly — we are already on a
        # worker thread, so we don't need the asyncio executor wrappers.
        from backend.services.feature_service import (  # local import to avoid cycles
            _sync_extract,
            _sync_extract_connectivity,
            _chunked_mode_identity,
        )

        features_df: pd.DataFrame = _sync_extract(str(path))
        if features_df.empty:
            return

        connectivity_rows = _sync_extract_connectivity(str(path))
        connectivity_df = pd.DataFrame(
            connectivity_rows,
            columns=["src_ip", "dst_ip", "src_port", "dst_port", "protocol_name", "timestamp"],
        )
        identity_df = _chunked_mode_identity(connectivity_df, len(features_df), packets_per_flow=10)

        if not ml_service.is_loaded:
            logger.warning("ML model not loaded; skipping file %s", path)
            return

        predictions = ml_service.predict(features_df)

        flow_rows: list[dict[str, Any]] = []
        alert_rows: list[dict[str, Any]] = []
        threats_in_batch = 0

        captured_at = datetime.now(timezone.utc).isoformat()

        for i, pred in enumerate(predictions):
            identity = identity_df.iloc[i].to_dict() if i < len(identity_df) else {}
            features_row = features_df.iloc[i].to_dict()
            features_json = {k: (v.item() if hasattr(v, "item") else v) for k, v in features_row.items()}

            category: ClassLabel = pred["predicted_category"]
            flow_id = str(uuid.uuid4())
            flow_rows.append({
                "id": flow_id,
                "session_id": session_id,
                "user_id": user_id,
                "captured_at": captured_at,
                "source_ip": identity.get("src_ip", "UNKNOWN"),
                "destination_ip": identity.get("dst_ip", "UNKNOWN"),
                "source_port": int(identity.get("src_port", 0) or 0),
                "destination_port": int(identity.get("dst_port", 0) or 0),
                "protocol_name": identity.get("protocol_name", "UNKNOWN"),
                "protocol_type": int(features_json.get("protocol_type", 0) or 0),
                "predicted_category": category.value,
                "confidence": pred["confidence"],
                "features_json": features_json,
            })

            if category != ClassLabel.BENIGN:
                threats_in_batch += 1
                alert_rows.append({
                    "id": str(uuid.uuid4()),
                    "session_id": session_id,
                    "user_id": user_id,
                    "flow_id": flow_id,
                    "severity": _compute_alert_severity(category, pred["confidence"]),
                    "category": category.value,
                    "source_ip": identity.get("src_ip", "UNKNOWN"),
                    "destination_ip": identity.get("dst_ip", "UNKNOWN"),
                    "message": f"{category.value} detected (confidence {pred['confidence']:.2f})",
                    "acknowledged": False,
                })

        if flow_rows:
            supabase.table("flow_events").insert(flow_rows).execute()
        if alert_rows:
            supabase.table("alerts").insert(alert_rows).execute()

        with self._lock:
            self._state["flows_captured"] += len(flow_rows)
            self._state["threats"] += threats_in_batch
            self._state["last_update"] = datetime.now(timezone.utc).isoformat()
            new_total = self._state["flows_captured"]
            new_threats = self._state["threats"]

        # Bump the session counters so the dashboard sees progress in realtime.
        try:
            supabase.table("scan_sessions").update({
                "total_flows": new_total,
                "threat_count": new_threats,
            }).eq("id", session_id).execute()
        except Exception:
            logger.exception("Failed to update scan_sessions counters for %s", session_id)

    def _set_error(self, msg: str) -> None:
        with self._lock:
            self._state["error"] = msg
            self._state["last_update"] = datetime.now(timezone.utc).isoformat()


# Process-wide singleton — a second start() while running raises.
capture_service = CaptureService()
