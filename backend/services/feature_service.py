"""PCAP feature extraction service wrapping the existing pcap2csv pipeline."""

from __future__ import annotations

import asyncio
import logging
import sys
import tempfile
import threading
from pathlib import Path
from typing import AsyncIterator

import dpkt
import pandas as pd

logger = logging.getLogger(__name__)

_PCAP2CSV_DIR = str(Path(__file__).resolve().parent.parent.parent / "utils" / "pcap2csv")
if _PCAP2CSV_DIR not in sys.path:
    sys.path.insert(0, _PCAP2CSV_DIR)


MODEL_FEATURES: list[str] = [
    "flow_duration", "header_length", "protocol_type", "duration", "rate",
    "srate", "drate", "fin_flag_number", "syn_flag_number", "rst_flag_number",
    "psh_flag_number", "ack_flag_number", "ece_flag_number", "cwr_flag_number",
    "ack_count", "syn_count", "fin_count", "urg_count", "rst_count",
    "http", "https", "dns", "telnet", "smtp", "ssh", "irc",
    "tcp", "udp", "dhcp", "arp", "icmp", "ipv", "llc",
    "tot_sum", "min", "max", "avg", "std", "tot_size",
    "iat", "number", "magnitue", "radius", "covariance", "variance", "weight",
]


def _sync_extract(pcap_path: str) -> pd.DataFrame:
    """Run the legacy Feature_extraction pipeline synchronously.

    Returns a DataFrame with columns lowercased and underscored,
    filtered to the 46 model features.
    """
    from Feature_extraction import Feature_extraction  # noqa: N813

    fe = Feature_extraction()

    # The pipeline writes a CSV to disk; use a temp file.
    with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as tmp:
        csv_stem = tmp.name.removesuffix(".csv")  # pcap_evaluation appends .csv

    fe.pcap_evaluation(pcap_path, csv_stem)
    csv_path = csv_stem + ".csv"

    df = pd.read_csv(csv_path)
    Path(csv_path).unlink(missing_ok=True)

    # Normalise column names to match training data conventions
    df.columns = [c.lower().replace(" ", "_") for c in df.columns]

    # Select exactly the 46 features the scaler expects (add zeros for any missing)
    for col in MODEL_FEATURES:
        if col not in df.columns:
            df[col] = 0
    df = df[MODEL_FEATURES]

    df = df.fillna(0)
    return df


class FeatureService:
    """Async wrapper around the pcap2csv feature extraction pipeline."""

    async def extract_features(self, pcap_path: str) -> pd.DataFrame:
        """Extract and normalise features from a PCAP file.

        Runs the CPU-heavy extraction in a thread pool so the FastAPI
        event loop stays responsive.
        """
        loop = asyncio.get_running_loop()
        df = await loop.run_in_executor(None, _sync_extract, pcap_path)
        logger.info("Extracted %d flows with %d features from %s", len(df), len(df.columns), pcap_path)
        return df

    async def extract_features_from_buffer(self, pcap_bytes: bytes) -> pd.DataFrame:
        """Extract the 46-feature DataFrame from an in-memory PCAP buffer.

        The legacy extractor only accepts file paths, so we persist the buffer
        to a temp file, run the existing pipeline, and unlink. Callers can
        treat the buffer as ephemeral.
        """
        loop = asyncio.get_running_loop()

        def _run() -> pd.DataFrame:
            with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
                tmp.write(pcap_bytes)
                tmp_path = tmp.name
            try:
                return _sync_extract(tmp_path)
            finally:
                Path(tmp_path).unlink(missing_ok=True)

        return await loop.run_in_executor(None, _run)

    async def extract_connectivity_info(self, pcap_path: str) -> pd.DataFrame:
        """Lightweight per-packet pass to get IP/port identity data.

        Returns one row per packet with: src_ip, dst_ip, src_port,
        dst_port, protocol_name, timestamp.  This is used to attribute
        ML predictions back to specific IPs for the summary.
        """
        loop = asyncio.get_running_loop()
        rows = await loop.run_in_executor(None, _sync_extract_connectivity, pcap_path)
        return pd.DataFrame(rows, columns=[
            "src_ip", "dst_ip", "src_port", "dst_port", "protocol_name", "timestamp",
        ])

    async def stream_flows(self, pcap_path: str) -> AsyncIterator[dict]:
        """Yield {features, identity} dicts one at a time as flows complete.

        Bridges the synchronous `pcap_evaluation_stream` generator (runs in a
        worker thread) to the asyncio event loop via an `asyncio.Queue`. The
        producer thread puts each flow onto the queue; the async consumer
        awaits `queue.get()` and yields. A `None` sentinel marks end-of-stream.
        Exceptions from the producer thread are re-raised on the consumer side.
        """
        from Feature_extraction import Feature_extraction  # noqa: N813

        loop = asyncio.get_running_loop()
        queue: asyncio.Queue = asyncio.Queue(maxsize=128)
        SENTINEL = object()

        def _producer() -> None:
            fe = Feature_extraction()
            try:
                for flow in fe.pcap_evaluation_stream(pcap_path):
                    asyncio.run_coroutine_threadsafe(queue.put(flow), loop).result()
            except Exception as exc:
                asyncio.run_coroutine_threadsafe(queue.put(exc), loop).result()
            finally:
                asyncio.run_coroutine_threadsafe(queue.put(SENTINEL), loop).result()

        thread = threading.Thread(target=_producer, name="pcap-stream", daemon=True)
        thread.start()

        try:
            while True:
                item = await queue.get()
                if item is SENTINEL:
                    break
                if isinstance(item, Exception):
                    raise item
                yield item
        finally:
            thread.join(timeout=5)

    async def aggregate_connectivity_per_flow(
        self, pcap_path: str, flow_count: int, packets_per_flow: int = 10
    ) -> pd.DataFrame:
        """Per-flow identity DataFrame aligned 1:1 with extract_features().

        The legacy pipeline aggregates every `packets_per_flow` (default 10)
        packets into one flow row. This helper reads the raw per-packet
        connectivity info and reduces each window to one representative
        row using the column mode — robust to outlier packets and a few
        dropped frames.
        """
        connectivity = await self.extract_connectivity_info(pcap_path)
        return _chunked_mode_identity(connectivity, flow_count, packets_per_flow)


def _mode_or_default(series: pd.Series, default):
    """Return the first mode of a Series, falling back to `default` if empty."""
    modes = series.dropna().mode()
    if not modes.empty:
        return modes.iloc[0]
    non_null = series.dropna()
    if not non_null.empty:
        return non_null.iloc[0]
    return default


def _chunked_mode_identity(
    connectivity: pd.DataFrame, flow_count: int, packets_per_flow: int
) -> pd.DataFrame:
    """Reduce per-packet connectivity to one representative row per flow."""
    rows = []
    for i in range(flow_count):
        chunk = connectivity.iloc[i * packets_per_flow : (i + 1) * packets_per_flow]

        if chunk.empty:
            rows.append({
                "src_ip": "UNKNOWN", "dst_ip": "UNKNOWN",
                "src_port": 0, "dst_port": 0, "protocol_name": "UNKNOWN",
            })
            continue

        src_ip = _mode_or_default(chunk["src_ip"], "UNKNOWN")
        dst_ip = _mode_or_default(chunk["dst_ip"], "UNKNOWN")
        protocol_name = _mode_or_default(chunk["protocol_name"], "UNKNOWN")

        src_port_series = chunk.loc[chunk["src_ip"] == src_ip, "src_port"]
        dst_port_series = chunk.loc[chunk["dst_ip"] == dst_ip, "dst_port"]
        src_port = _mode_or_default(src_port_series, 0)
        dst_port = _mode_or_default(dst_port_series, 0)

        rows.append({
            "src_ip": src_ip, "dst_ip": dst_ip,
            "src_port": int(src_port) if pd.notna(src_port) else 0,
            "dst_port": int(dst_port) if pd.notna(dst_port) else 0,
            "protocol_name": protocol_name,
        })

    return pd.DataFrame(rows, columns=["src_ip", "dst_ip", "src_port", "dst_port", "protocol_name"])


def _sync_extract_connectivity(pcap_path: str) -> list[list]:
    """Parse PCAP with dpkt to extract per-packet connection identity."""
    import socket

    rows: list[list] = []
    with open(pcap_path, "rb") as f:
        try:
            pcap = dpkt.pcap.Reader(f)
        except ValueError:
            pcap = dpkt.pcapng.Reader(f)

        for timestamp, buf in pcap:
                try:
                    eth = dpkt.ethernet.Ethernet(buf)
                    if isinstance(eth.data, dpkt.ip.IP):
                        ip = eth.data
                        src_ip = socket.inet_ntoa(ip.src)
                        dst_ip = socket.inet_ntoa(ip.dst)
                        protocol_name = {6: "TCP", 17: "UDP"}.get(ip.p, "OTHER")
                        src_port = dst_port = None
        
                        if protocol_name == "TCP":
                            tcp = ip.data
                            src_port = tcp.sport
                            dst_port = tcp.dport
                        elif protocol_name == "UDP":
                            udp = ip.data
                            src_port = udp.sport
                            dst_port = udp.dport
        
                        rows.append([src_ip, dst_ip, src_port, dst_port, protocol_name, timestamp])

                except Exception as e:
                    logger.warning("Failed to parse packet in %s: %s", pcap_path, e)

    return rows
