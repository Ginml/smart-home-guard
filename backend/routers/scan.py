"""Scan endpoints — interface discovery + real-time capture lifecycle."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, Header, HTTPException, Request

from backend.middleware.auth import verify_token
from backend.models.schemas import (
    ScanStartRequest,
    ScanStartResponse,
    ScanStatusResponse,
    ScanStopRequest,
    ScanStopResponse,
)
from backend.services.capture_service import (
    CaptureAlreadyRunningError,
    CaptureNotRunningError,
    TcpdumpUnavailableError,
    capture_service,
)
from backend.services.supabase_client import make_user_client

logger = logging.getLogger(__name__)

router = APIRouter()


def _bearer_from_header(authorization: str | None) -> str:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")
    return authorization.split(None, 1)[1].strip()


def _read_interfaces() -> list[dict]:
    try:
        lines = Path("/proc/net/dev").read_text().splitlines()
    except OSError:
        raise HTTPException(status_code=503, detail="Interface discovery not available on this platform")

    interfaces = []
    for line in lines[2:]:  # skip 2-line header
        name = line.split(":")[0].strip()
        if not name or name == "lo":
            continue

        name_lower = name.lower()
        if any(k in name_lower for k in ("wlan", "wifi", "wlp")):
            description = "Wireless"
        elif any(k in name_lower for k in ("eth", "enp", "eno", "ens")):
            description = "Ethernet"
        elif any(k in name_lower for k in ("docker", "br-", "veth", "virbr")):
            description = "Virtual/Docker"
        else:
            description = "Network Interface"

        interfaces.append({"name": name, "description": description})

    return interfaces


@router.get("/scan/interfaces")
async def list_interfaces(
    authorization: str | None = Header(default=None),
    claims: dict = Depends(verify_token),
) -> list[dict]:
    return _read_interfaces()


@router.post("/scan/start", response_model=ScanStartResponse)
async def start_scan(
    payload: ScanStartRequest,
    request: Request,
    authorization: str | None = Header(default=None),
    claims: dict = Depends(verify_token),
) -> ScanStartResponse:
    """Begin a real-time capture session on `interface`.

    Inserts a new `scan_sessions` row with mode='realtime', status='scanning',
    spawns the CaptureService background thread, and returns the session id.
    """
    user_id = claims["sub"]
    if payload.user_id != user_id:
        # The frontend supplies user_id for ergonomic parity with /analyze, but
        # we trust the JWT, not the request body.
        raise HTTPException(status_code=403, detail="user_id does not match token")

    user_jwt = _bearer_from_header(authorization)
    supabase = make_user_client(user_jwt)

    session_insert = supabase.table("scan_sessions").insert({
        "user_id": user_id,
        "mode": "realtime",
        "status": "scanning",
        "interface_name": payload.interface,
        "started_at": datetime.now(timezone.utc).isoformat(),
    }).execute()

    if not session_insert.data:
        raise HTTPException(status_code=500, detail="Failed to create scan session")

    session_id = session_insert.data[0]["id"]

    try:
        capture_service.start(
            interface=payload.interface,
            session_id=session_id,
            user_id=user_id,
            jwt=user_jwt,
            feature_service=request.app.state.feature_service,
            ml_service=request.app.state.ml_service,
        )
    except CaptureAlreadyRunningError as exc:
        # Roll back the session row we just created.
        supabase.table("scan_sessions").update({
            "status": "error",
            "ended_at": datetime.now(timezone.utc).isoformat(),
            "summary_json": {"error": str(exc)},
        }).eq("id", session_id).execute()
        raise HTTPException(status_code=409, detail=str(exc))
    except TcpdumpUnavailableError as exc:
        supabase.table("scan_sessions").update({
            "status": "error",
            "ended_at": datetime.now(timezone.utc).isoformat(),
            "summary_json": {"error": str(exc)},
        }).eq("id", session_id).execute()
        raise HTTPException(status_code=503, detail=str(exc))
    except ValueError as exc:
        supabase.table("scan_sessions").update({
            "status": "error",
            "ended_at": datetime.now(timezone.utc).isoformat(),
            "summary_json": {"error": str(exc)},
        }).eq("id", session_id).execute()
        raise HTTPException(status_code=400, detail=str(exc))

    return ScanStartResponse(session_id=session_id, status="scanning")


@router.post("/scan/stop", response_model=ScanStopResponse)
async def stop_scan(
    payload: ScanStopRequest,
    authorization: str | None = Header(default=None),
    claims: dict = Depends(verify_token),
) -> ScanStopResponse:
    """Stop the running capture and finalise the session row."""
    user_jwt = _bearer_from_header(authorization)

    try:
        final_state = capture_service.stop()
    except CaptureNotRunningError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    # Defensive: confirm the session id matches what's actually running so a
    # stale frontend can't accidentally finalise a different scan.
    running_session = final_state.get("session_id")
    if running_session and running_session != payload.session_id:
        logger.warning("stop_scan session mismatch: client=%s actual=%s",
                       payload.session_id, running_session)

    supabase = make_user_client(user_jwt)
    ended_at = datetime.now(timezone.utc)
    update_payload: dict = {
        "status": "error" if final_state.get("error") else "completed",
        "ended_at": ended_at.isoformat(),
        "total_flows": final_state.get("flows_captured", 0),
        "threat_count": final_state.get("threats", 0),
    }
    if final_state.get("error"):
        update_payload["summary_json"] = {"error": final_state["error"]}

    target_id = running_session or payload.session_id
    supabase.table("scan_sessions").update(update_payload).eq("id", target_id).execute()

    return ScanStopResponse(
        session_id=target_id,
        total_flows=final_state.get("flows_captured", 0),
        threat_count=final_state.get("threats", 0),
        ended_at=ended_at,
        error=final_state.get("error"),
    )


@router.get("/scan/status", response_model=ScanStatusResponse)
async def scan_status(
    claims: dict = Depends(verify_token),
) -> ScanStatusResponse:
    state = capture_service.get_status()
    return ScanStatusResponse(
        running=state.get("running", False),
        session_id=state.get("session_id"),
        interface=state.get("interface"),
        flows_captured=state.get("flows_captured", 0),
        threats=state.get("threats", 0),
        last_update=state.get("last_update"),
        error=state.get("error"),
    )
