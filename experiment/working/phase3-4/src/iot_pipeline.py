from __future__ import annotations

import ast
import csv
import gzip
import json
import math
import os
import random
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence

import joblib
import numpy as np
import pandas as pd
import torch
from scipy.optimize import minimize_scalar
from sklearn.base import clone
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    average_precision_score,
    fbeta_score,
    precision_recall_curve,
    precision_recall_fscore_support,
    precision_score,
    recall_score,
)
from sklearn.multiclass import OneVsRestClassifier
from sklearn.preprocessing import StandardScaler
from torch import nn
from torch.utils.data import DataLoader, TensorDataset
from tqdm.auto import tqdm


SEED = 42
LABEL_TZ = "America/New_York"
WINDOWS = (5, 10, 20, 30)
STRIDE_SECONDS = 2
FAMILIES = (
    "camera",
    "doorbell",
    "lock",
    "motion_sensor",
    "contact_sensor",
    "water_sensor",
    "light",
    "outlet",
    "security_hub",
)
EVENTS = (
    "motion",
    "sound",
    "on",
    "off",
    "record",
    "unlock",
    "lock",
    "arm",
    "disarm",
    "person",
    "ring",
    "restart",
    "open",
    "close",
    "move",
    "water",
)
TELEMETRY_EVENTS = {"temp", "rssi", "lqi", "batt"}
TSHARK = Path("/Applications/Wireshark.app/Contents/MacOS/tshark")
CAPINFOS = Path("/Applications/Wireshark.app/Contents/MacOS/capinfos")

PACKET_COLUMNS = [
    "timestamp_epoch",
    "frame_len",
    "eth_src",
    "eth_dst",
    "ip_src",
    "ip_dst",
    "ipv6_src",
    "ipv6_dst",
    "ip_proto",
    "tcp_srcport",
    "tcp_dstport",
    "udp_srcport",
    "udp_dstport",
    "tcp_flags",
    "eth_type",
    "dns_response",
    "tls_content_type",
    "tls_handshake_type",
    "tcp_retransmission",
]
TSHARK_FIELDS = [
    "frame.time_epoch",
    "frame.len",
    "eth.src",
    "eth.dst",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "ip.proto",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    "tcp.flags",
    "eth.type",
    "dns.flags.response",
    "tls.record.content_type",
    "tls.handshake.type",
    "tcp.analysis.retransmission",
]

ADDITIVE_SECOND_COLUMNS = [
    "packet_count",
    "byte_sum",
    "byte_sq_sum",
    "inbound_packets",
    "outbound_packets",
    "unknown_packets",
    "inbound_bytes",
    "outbound_bytes",
    "tcp_packets",
    "udp_packets",
    "icmp_packets",
    "arp_packets",
    "dns_packets",
    "tls_packets",
    "retransmissions",
    "tcp_syn",
    "tcp_fin",
    "tcp_rst",
    "tcp_psh",
    "len_le_79",
    "len_80_159",
    "len_160_319",
    "len_320_639",
    "len_640_1279",
    "len_ge_1280",
    "port_dns",
    "port_ntp",
    "port_http",
    "port_https",
    "port_mqtt",
    "remote_unique_approx",
    "direction_changes",
    "iat_sum",
    "iat_sq_sum",
]


def seed_everything(seed: int = SEED) -> None:
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)


def load_registry(dataset_root: Path) -> tuple[dict, dict]:
    text = (dataset_root / "devices" / "devices.py").read_text()
    devices = ast.literal_eval(text.split("devices =", 1)[1].split("\nhubs =", 1)[0].strip())
    hubs = ast.literal_eval(text.split("hubs =", 1)[1].strip())
    return devices, hubs


def _local_endpoint_overrides() -> dict[str, dict[str, str]]:
    return {
        "hub-02": {
            "registry_id": "august-hub-02",
            "address": "192.168.1.37",
            "ether": "b8:b7:f1:05:15:39",
            "description": "August Connect bridge carrying yale-lock-02",
        },
        "simplisafe-hub-01": {
            "registry_id": "simplisafe-hub-01",
            "address": "192.168.1.36",
            "ether": "cc:50:e3:a2:99:60",
            "description": "SimpliSafe hub (derived from capture)",
        },
    }


def capture_manifest(dataset_root: Path) -> pd.DataFrame:
    devices, _ = load_registry(dataset_root)
    overrides = _local_endpoint_overrides()
    rows = []
    for pcap in sorted((dataset_root / "pcaps").glob("*.pcap")):
        capture_id = pcap.stem
        entry = dict(devices.get(capture_id, {}))
        entry.update(overrides.get(capture_id, {}))
        rows.append(
            {
                "capture_id": capture_id,
                "pcap_path": str(pcap),
                "pcap_size_bytes": pcap.stat().st_size,
                "registry_id": entry.get("registry_id", capture_id),
                "description": entry.get("description", "Unregistered endpoint"),
                "local_ip": entry.get("address", ""),
                "local_mac": entry.get("ether", "").lower(),
            }
        )
    return pd.DataFrame(rows)


def export_pcap_csv(pcap_path: Path, output_path: Path, force: bool = False) -> Path:
    """Stream packet metadata to gzip CSV. No payload fields are requested."""
    if output_path.exists() and output_path.stat().st_size > 100 and not force:
        with output_path.open("rb") as check:
            if check.read(2) == b"\x1f\x8b":
                return output_path
    output_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = output_path.with_suffix(output_path.suffix + ".partial")
    cmd = [
        str(TSHARK),
        "-n",
        "-r",
        str(pcap_path),
        "-T",
        "fields",
        "-E",
        "separator=,",
        "-E",
        "quote=d",
        "-E",
        "occurrence=f",
    ]
    for field in TSHARK_FIELDS:
        cmd.extend(["-e", field])
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert proc.stdout is not None
    with gzip.open(tmp_path, "wb") as out:
        out.write((",".join(PACKET_COLUMNS) + "\n").encode())
        while chunk := proc.stdout.read(1024 * 1024):
            out.write(chunk)
    stderr = proc.stderr.read().decode(errors="replace") if proc.stderr is not None else ""
    returncode = proc.wait()
    if returncode:
        tmp_path.unlink(missing_ok=True)
        raise RuntimeError(f"tshark failed for {pcap_path.name}: {stderr[-2000:]}")
    os.replace(tmp_path, output_path)
    return output_path


def export_all_pcaps(manifest: pd.DataFrame, output_dir: Path, force: bool = False) -> list[Path]:
    outputs = []
    for row in tqdm(manifest.itertuples(index=False), total=len(manifest), desc="PCAP → CSV.gz"):
        outputs.append(
            export_pcap_csv(Path(row.pcap_path), output_dir / f"{row.capture_id}.csv.gz", force=force)
        )
    return outputs


def _numeric(series: pd.Series) -> pd.Series:
    return pd.to_numeric(series, errors="coerce").fillna(0)


def _hex_flags(series: pd.Series) -> np.ndarray:
    def parse(value: object) -> int:
        if pd.isna(value) or value == "":
            return 0
        try:
            return int(str(value).split(",", 1)[0], 0)
        except ValueError:
            return 0
    return series.map(parse).to_numpy(np.int64)


def aggregate_packet_csv(
    csv_path: Path,
    output_path: Path,
    local_ip: str,
    local_mac: str,
    chunksize: int = 300_000,
    force: bool = False,
) -> pd.DataFrame:
    if output_path.exists() and not force:
        return pd.read_parquet(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    partials: list[pd.DataFrame] = []
    last_ts: float | None = None
    for chunk in pd.read_csv(csv_path, chunksize=chunksize, low_memory=False):
        ts = _numeric(chunk["timestamp_epoch"]).to_numpy(float)
        valid = ts > 0
        if not valid.any():
            continue
        chunk = chunk.loc[valid].reset_index(drop=True)
        ts = ts[valid]
        frame_len = _numeric(chunk["frame_len"]).to_numpy(float)
        second = np.floor(ts).astype(np.int64)
        eth_src = chunk["eth_src"].fillna("").astype(str).str.lower().to_numpy()
        eth_dst = chunk["eth_dst"].fillna("").astype(str).str.lower().to_numpy()
        ip_src = chunk["ip_src"].fillna(chunk["ipv6_src"]).fillna("").astype(str).to_numpy()
        ip_dst = chunk["ip_dst"].fillna(chunk["ipv6_dst"]).fillna("").astype(str).to_numpy()
        outbound = (eth_src == local_mac) | ((local_ip != "") & (ip_src == local_ip))
        inbound = (eth_dst == local_mac) | ((local_ip != "") & (ip_dst == local_ip))
        direction = np.where(outbound, 1, np.where(inbound, -1, 0))
        remote_ip = np.where(outbound, ip_dst, np.where(inbound, ip_src, ""))

        tcp_src = _numeric(chunk["tcp_srcport"]).to_numpy(np.int64)
        tcp_dst = _numeric(chunk["tcp_dstport"]).to_numpy(np.int64)
        udp_src = _numeric(chunk["udp_srcport"]).to_numpy(np.int64)
        udp_dst = _numeric(chunk["udp_dstport"]).to_numpy(np.int64)
        ip_proto = _numeric(chunk["ip_proto"]).to_numpy(np.int64)
        eth_type = chunk["eth_type"].fillna("").astype(str).to_numpy()
        flags = _hex_flags(chunk["tcp_flags"])
        is_tcp = (tcp_src > 0) | (tcp_dst > 0)
        is_udp = (udp_src > 0) | (udp_dst > 0)
        is_icmp = np.isin(ip_proto, [1, 58])
        is_arp = np.char.find(eth_type.astype(str), "0806") >= 0
        ports = np.column_stack([tcp_src, tcp_dst, udp_src, udp_dst])

        iat = np.diff(ts, prepend=last_ts if last_ts is not None else ts[0])
        iat = np.clip(iat, 0, 300)
        last_ts = float(ts[-1])
        direction_change = np.r_[False, direction[1:] != direction[:-1]]
        if len(direction_change) and len(partials):
            direction_change[0] = False

        work = pd.DataFrame(
            {
                "second_epoch": second,
                "packet_count": 1,
                "byte_sum": frame_len,
                "byte_sq_sum": frame_len**2,
                "byte_min": frame_len,
                "byte_max": frame_len,
                "inbound_packets": inbound.astype(np.int16),
                "outbound_packets": outbound.astype(np.int16),
                "unknown_packets": (~(inbound | outbound)).astype(np.int16),
                "inbound_bytes": frame_len * inbound,
                "outbound_bytes": frame_len * outbound,
                "tcp_packets": is_tcp.astype(np.int16),
                "udp_packets": is_udp.astype(np.int16),
                "icmp_packets": is_icmp.astype(np.int16),
                "arp_packets": is_arp.astype(np.int16),
                "dns_packets": (ports == 53).any(axis=1).astype(np.int16),
                "tls_packets": (
                    chunk["tls_content_type"].notna() | chunk["tls_handshake_type"].notna()
                ).astype(np.int16),
                "retransmissions": chunk["tcp_retransmission"].notna().astype(np.int16),
                "tcp_syn": ((flags & 0x02) > 0).astype(np.int16),
                "tcp_fin": ((flags & 0x01) > 0).astype(np.int16),
                "tcp_rst": ((flags & 0x04) > 0).astype(np.int16),
                "tcp_psh": ((flags & 0x08) > 0).astype(np.int16),
                "len_le_79": (frame_len <= 79).astype(np.int16),
                "len_80_159": ((frame_len >= 80) & (frame_len <= 159)).astype(np.int16),
                "len_160_319": ((frame_len >= 160) & (frame_len <= 319)).astype(np.int16),
                "len_320_639": ((frame_len >= 320) & (frame_len <= 639)).astype(np.int16),
                "len_640_1279": ((frame_len >= 640) & (frame_len <= 1279)).astype(np.int16),
                "len_ge_1280": (frame_len >= 1280).astype(np.int16),
                "port_dns": (ports == 53).any(axis=1).astype(np.int16),
                "port_ntp": (ports == 123).any(axis=1).astype(np.int16),
                "port_http": (ports == 80).any(axis=1).astype(np.int16),
                "port_https": (ports == 443).any(axis=1).astype(np.int16),
                "port_mqtt": np.isin(ports, [1883, 8883]).any(axis=1).astype(np.int16),
                "remote_ip": remote_ip,
                "direction_changes": direction_change.astype(np.int16),
                "iat_sum": iat,
                "iat_sq_sum": iat**2,
                "iat_max": iat,
            }
        )
        grouped = work.groupby("second_epoch", sort=True).agg(
            {**{c: "sum" for c in ADDITIVE_SECOND_COLUMNS if c != "remote_unique_approx"},
             "byte_min": "min", "byte_max": "max", "iat_max": "max", "remote_ip": "nunique"}
        )
        grouped = grouped.rename(columns={"remote_ip": "remote_unique_approx"}).reset_index()
        partials.append(grouped)

    if not partials:
        result = pd.DataFrame(columns=["second_epoch", *ADDITIVE_SECOND_COLUMNS, "byte_min", "byte_max", "iat_max"])
    else:
        combined = pd.concat(partials, ignore_index=True)
        agg = {c: "sum" for c in ADDITIVE_SECOND_COLUMNS}
        agg.update({"byte_min": "min", "byte_max": "max", "iat_max": "max"})
        result = combined.groupby("second_epoch", as_index=False).agg(agg)
    result.to_parquet(output_path, index=False)
    return result


def aggregate_all_packet_csvs(
    manifest: pd.DataFrame,
    packet_dir: Path,
    second_dir: Path,
    force: bool = False,
) -> pd.DataFrame:
    summaries = []
    for row in tqdm(manifest.itertuples(index=False), total=len(manifest), desc="CSV.gz → 1-second features"):
        second = aggregate_packet_csv(
            packet_dir / f"{row.capture_id}.csv.gz",
            second_dir / f"{row.capture_id}.parquet",
            row.local_ip,
            row.local_mac,
            force=force,
        )
        summaries.append(
            {
                "capture_id": row.capture_id,
                "packet_count": int(second["packet_count"].sum()) if len(second) else 0,
                "start_epoch": int(second["second_epoch"].min()) if len(second) else np.nan,
                "end_epoch": int(second["second_epoch"].max()) if len(second) else np.nan,
                "active_seconds": len(second),
            }
        )
    return manifest.merge(pd.DataFrame(summaries), on="capture_id", how="left")


def device_family(device_id: str, description: str = "") -> str | None:
    text = f"{device_id} {description}".lower()
    if "doorbell" in text or device_id == "simplisafe-d1":
        return "doorbell"
    if "camera" in text or "-cam-" in device_id or "awarecam" in device_id or device_id == "simplisafe-d2":
        return "camera"
    if "lock" in text or "deadbolt" in text:
        return "lock"
    if "motion" in device_id:
        return "motion_sensor"
    if "contact" in device_id or "multi" in device_id:
        return "contact_sensor"
    if "water" in device_id:
        return "water_sensor"
    if "light" in device_id:
        return "light"
    if "outlet" in device_id:
        return "outlet"
    if "hub" in device_id:
        return "security_hub"
    return None


def normalize_event(raw_event: str) -> str:
    event = raw_event.removeprefix("event_").lower()
    for base in ("motion", "sound", "person", "water"):
        if event in {f"{base}start", f"{base}end"}:
            return base
    return {"timeoutunlock": "unlock"}.get(event, event)


def canonicalize_labels(dataset_root: Path, manifest: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    devices, hubs = load_registry(dataset_root)
    capture_ids = set(manifest["capture_id"])
    parent = {child: hub for hub, children in hubs.items() for child in children}
    parent["yale-lock-02"] = "hub-02"
    rows = []
    for path in sorted((dataset_root / "labels").glob("*.csv")):
        source = path.stem
        precision = "minute" if source.startswith("ifttt") else "second"
        weak = source == "ifttt-events"
        with path.open(newline="") as handle:
            for timestamp, source_device_id, raw_event in csv.reader(handle):
                capture_id = source_device_id if source_device_id in capture_ids else parent.get(source_device_id)
                description = devices.get(source_device_id, {}).get("description", "")
                family = device_family(source_device_id, description)
                event = normalize_event(raw_event)
                rows.append(
                    {
                        "timestamp_local_text": timestamp,
                        "capture_id": capture_id,
                        "source_device_id": source_device_id,
                        "device_family": family,
                        "event_type": event,
                        "label_source": source,
                        "timestamp_precision": precision,
                        "is_weak_label": weak,
                        "is_telemetry": event in TELEMETRY_EVENTS,
                        "has_capture": capture_id in capture_ids,
                    }
                )
    labels = pd.DataFrame(rows)
    naive = pd.to_datetime(
        labels["timestamp_local_text"],
        format="mixed",
        errors="coerce",
    )
    localized = naive.dt.tz_localize(LABEL_TZ, ambiguous="NaT", nonexistent="NaT")
    labels["timestamp_utc"] = localized.dt.tz_convert("UTC")
    labels["dst_valid"] = labels["timestamp_utc"].notna()
    labels["date_eastern"] = localized.dt.date.astype("string")
    labels["is_semantic"] = labels["event_type"].isin(EVENTS)
    usable = labels[
        labels["has_capture"]
        & labels["dst_valid"]
        & labels["device_family"].isin(FAMILIES)
    ].copy()
    dedup_cols = [
        "timestamp_utc",
        "capture_id",
        "source_device_id",
        "device_family",
        "event_type",
        "label_source",
    ]
    usable = usable.drop_duplicates(dedup_cols).sort_values("timestamp_utc").reset_index(drop=True)
    return labels, usable


def precise_semantic_labels(labels: pd.DataFrame) -> pd.DataFrame:
    return labels[labels["is_semantic"] & ~labels["is_weak_label"]].copy()


def horizons_for_window(window: int) -> list[int]:
    return sorted({h for h in (2, 5, 10, 20, window) if h <= window})


def _dense_second_matrix(second_df: pd.DataFrame, start: int, end: int) -> tuple[np.ndarray, np.ndarray]:
    seconds = np.arange(start, end + 1, dtype=np.int64)
    indexed = second_df.set_index("second_epoch")
    columns = [*ADDITIVE_SECOND_COLUMNS, "byte_min", "byte_max", "iat_max"]
    dense = indexed.reindex(seconds)[columns]
    dense[ADDITIVE_SECOND_COLUMNS] = dense[ADDITIVE_SECOND_COLUMNS].fillna(0)
    dense[["byte_min", "byte_max", "iat_max"]] = dense[["byte_min", "byte_max", "iat_max"]].fillna(0)
    return seconds, dense.to_numpy(np.float64)


def feature_names_for_window(window: int) -> list[str]:
    names = []
    for h in horizons_for_window(window):
        names.extend(f"{c}__{h}s" for c in ADDITIVE_SECOND_COLUMNS)
        names.extend(
            [
                f"byte_max__{h}s",
                f"iat_max__{h}s",
                f"byte_mean__{h}s",
                f"byte_std__{h}s",
                f"iat_mean__{h}s",
                f"iat_std__{h}s",
                f"inbound_ratio__{h}s",
                f"packets_per_second__{h}s",
                f"bytes_per_second__{h}s",
            ]
        )
    return names


def compute_window_features(
    second_df: pd.DataFrame,
    end_epochs: np.ndarray,
    window: int,
) -> np.ndarray:
    if len(end_epochs) == 0:
        return np.empty((0, len(feature_names_for_window(window))), dtype=np.float32)
    start = int(end_epochs.min()) - window - 1
    end = int(end_epochs.max())
    seconds, dense = _dense_second_matrix(second_df, start, end)
    col_index = {c: i for i, c in enumerate([*ADDITIVE_SECOND_COLUMNS, "byte_min", "byte_max", "iat_max"])}
    additive = dense[:, : len(ADDITIVE_SECOND_COLUMNS)]
    prefix = np.vstack([np.zeros((1, additive.shape[1])), np.cumsum(additive, axis=0)])
    end_idx = np.searchsorted(seconds, end_epochs)
    blocks = []
    packet_i = ADDITIVE_SECOND_COLUMNS.index("packet_count")
    byte_i = ADDITIVE_SECOND_COLUMNS.index("byte_sum")
    byte_sq_i = ADDITIVE_SECOND_COLUMNS.index("byte_sq_sum")
    in_i = ADDITIVE_SECOND_COLUMNS.index("inbound_packets")
    iat_i = ADDITIVE_SECOND_COLUMNS.index("iat_sum")
    iat_sq_i = ADDITIVE_SECOND_COLUMNS.index("iat_sq_sum")
    for h in horizons_for_window(window):
        left = end_idx - h + 1
        sums = prefix[end_idx + 1] - prefix[left]
        byte_max_full = pd.Series(dense[:, col_index["byte_max"]]).rolling(h, min_periods=1).max().to_numpy()
        iat_max_full = pd.Series(dense[:, col_index["iat_max"]]).rolling(h, min_periods=1).max().to_numpy()
        byte_max = byte_max_full[end_idx]
        iat_max = iat_max_full[end_idx]
        packets = np.maximum(sums[:, packet_i], 1)
        byte_mean = sums[:, byte_i] / packets
        byte_var = np.maximum(sums[:, byte_sq_i] / packets - byte_mean**2, 0)
        iat_count = np.maximum(sums[:, packet_i] - 1, 1)
        iat_mean = sums[:, iat_i] / iat_count
        iat_var = np.maximum(sums[:, iat_sq_i] / iat_count - iat_mean**2, 0)
        derived = np.column_stack(
            [
                byte_max,
                iat_max,
                byte_mean,
                np.sqrt(byte_var),
                iat_mean,
                np.sqrt(iat_var),
                sums[:, in_i] / packets,
                sums[:, packet_i] / h,
                sums[:, byte_i] / h,
            ]
        )
        blocks.extend([sums, derived])
    return np.hstack(blocks).astype(np.float32)


def _event_end_map(labels: pd.DataFrame, window: int, stride: int = STRIDE_SECONDS) -> dict[int, list[tuple[str, str]]]:
    mapping: dict[int, list[tuple[str, str]]] = {}
    for row in labels.itertuples(index=False):
        epoch = int(row.timestamp_utc.timestamp())
        first = epoch if epoch % stride == 0 else epoch + (stride - epoch % stride)
        for end in range(first, epoch + window + 1, stride):
            mapping.setdefault(end, []).append((row.device_family, row.event_type))
    return mapping


def build_window_dataset(
    second_dir: Path,
    manifest: pd.DataFrame,
    labels: pd.DataFrame,
    window: int,
    start_utc: pd.Timestamp,
    end_utc: pd.Timestamp,
    mode: str = "sampled",
    background_ratio: int = 3,
    seed: int = SEED,
) -> tuple[pd.DataFrame, np.ndarray, np.ndarray, np.ndarray, list[str]]:
    """Build causal windows. mode='all' returns the entire two-second stream."""
    rng = np.random.default_rng(seed)
    feature_frames = []
    metadata_frames = []
    family_targets = []
    pair_targets = []
    feature_names = feature_names_for_window(window)
    start_epoch = int(start_utc.timestamp())
    end_epoch = int(end_utc.timestamp())
    for capture_id in tqdm(manifest["capture_id"], desc=f"Build {window}s {mode} windows", leave=False):
        second_path = second_dir / f"{capture_id}.parquet"
        if not second_path.exists():
            continue
        seconds_df = pd.read_parquet(second_path)
        if seconds_df.empty:
            continue
        lo = max(start_epoch, int(seconds_df["second_epoch"].min()) + window)
        hi = min(end_epoch, int(seconds_df["second_epoch"].max()))
        lo += (-lo) % STRIDE_SECONDS
        if lo > hi:
            continue
        all_ends = np.arange(lo, hi + 1, STRIDE_SECONDS, dtype=np.int64)
        label_epoch = labels["timestamp_utc"].map(lambda value: int(value.timestamp()))
        cap_labels = labels[
            (labels["capture_id"] == capture_id)
            & (label_epoch >= lo - window)
            & (label_epoch <= hi)
        ]
        semantic = cap_labels[cap_labels["is_semantic"] & ~cap_labels["is_weak_label"]]
        telemetry = cap_labels[cap_labels["is_telemetry"] & ~cap_labels["is_weak_label"]]
        event_map = _event_end_map(semantic, window)
        telemetry_map = _event_end_map(telemetry.assign(device_family="camera", event_type="motion"), window)
        positive = np.array(sorted(set(all_ends).intersection(event_map)), dtype=np.int64)
        if mode == "all":
            chosen = all_ends
            background_kind = np.full(len(chosen), "stream", dtype=object)
        else:
            hard = np.array(sorted(set(all_ends).intersection(telemetry_map) - set(positive)), dtype=np.int64)
            blocked = set()
            for e in event_map:
                blocked.update(range(e - window, e + window + 1, STRIDE_SECONDS))
            pool = np.array([e for e in all_ends if e not in blocked and e not in set(hard)], dtype=np.int64)
            desired = min(len(pool), max(background_ratio * max(len(positive), 1), 100))
            random_bg = rng.choice(pool, size=desired, replace=False) if desired else np.array([], dtype=np.int64)
            hard = hard[: min(len(hard), max(len(positive), 100))]
            chosen = np.unique(np.r_[positive, hard, random_bg]).astype(np.int64)
            kind = {int(e): "event" for e in positive}
            kind.update({int(e): "telemetry" for e in hard})
            background_kind = np.array([kind.get(int(e), "random") for e in chosen], dtype=object)
        if len(chosen) == 0:
            continue
        X = compute_window_features(seconds_df, chosen, window)
        yf = np.zeros((len(chosen), len(FAMILIES)), dtype=np.float32)
        yp = np.zeros((len(chosen), len(FAMILIES), len(EVENTS)), dtype=np.float32)
        label_lists = []
        for i, end in enumerate(chosen):
            pairs = sorted(set(event_map.get(int(end), [])))
            label_lists.append("|".join(f"{d}:{e}" for d, e in pairs))
            for family, event in pairs:
                if family in FAMILIES and event in EVENTS:
                    fi, ei = FAMILIES.index(family), EVENTS.index(event)
                    yf[i, fi] = 1
                    yp[i, fi, ei] = 1
        metadata_frames.append(
            pd.DataFrame(
                {
                    "window_end_utc": pd.to_datetime(chosen, unit="s", utc=True),
                    "capture_id": capture_id,
                    "is_event": (yf.sum(axis=1) > 0).astype(np.int8),
                    "background_kind": background_kind,
                    "labels": label_lists,
                }
            )
        )
        feature_frames.append(X)
        family_targets.append(yf)
        pair_targets.append(yp)
    if not feature_frames:
        return pd.DataFrame(), np.empty((0, len(feature_names))), np.empty((0, len(FAMILIES))), np.empty((0, len(FAMILIES), len(EVENTS))), feature_names
    return (
        pd.concat(metadata_frames, ignore_index=True),
        np.vstack(feature_frames),
        np.vstack(family_targets),
        np.vstack(pair_targets),
        feature_names,
    )


def fit_phase1(X: np.ndarray, y: np.ndarray) -> HistGradientBoostingClassifier:
    if len(y) > 50_000:
        rng = np.random.default_rng(SEED)
        positive = np.where(y == 1)[0]
        negative = np.where(y == 0)[0]
        positive_keep = rng.choice(positive, size=min(len(positive), 25_000), replace=False)
        remaining = 50_000 - len(positive_keep)
        negative_keep = rng.choice(negative, size=min(len(negative), remaining), replace=False)
        keep = np.r_[positive_keep, negative_keep]
        X, y = X[keep], y[keep]
    positives = max(int(y.sum()), 1)
    negatives = max(len(y) - positives, 1)
    weights = np.where(y == 1, len(y) / (2 * positives), len(y) / (2 * negatives))
    model = HistGradientBoostingClassifier(
        learning_rate=0.05,
        max_iter=50,
        max_leaf_nodes=15,
        l2_regularization=1.0,
        early_stopping=True,
        random_state=SEED,
    )
    model.fit(X, y, sample_weight=weights)
    return model


def threshold_for_recall(y_true: np.ndarray, prob: np.ndarray, target: float = 0.95) -> float:
    candidates = np.unique(np.r_[0.0, prob, 1.0])
    eligible = [t for t in candidates if recall_score(y_true, prob >= t, zero_division=0) >= target]
    return float(max(eligible)) if eligible else 0.0


def binary_metrics(y_true: np.ndarray, prob: np.ndarray, threshold: float) -> dict[str, float]:
    pred = prob >= threshold
    return {
        "threshold": float(threshold),
        "precision": precision_score(y_true, pred, zero_division=0),
        "recall": recall_score(y_true, pred, zero_division=0),
        "f2": fbeta_score(y_true, pred, beta=2, zero_division=0),
        "pr_auc": average_precision_score(y_true, prob),
        "positive_rate": float(pred.mean()),
    }


def select_window(results: pd.DataFrame) -> tuple[int, bool]:
    eligible = results[results["recall"] >= 0.95]
    if len(eligible):
        best = eligible["f2"].max()
        selected = int(eligible[eligible["f2"] >= best - 0.01]["window"].min())
        return selected, True
    best = results["f2"].max()
    selected = int(results[results["f2"] >= best - 0.01]["window"].min())
    return selected, False


class JointFamilyEventModel(nn.Module):
    def __init__(self, input_dim: int, n_families: int = len(FAMILIES), n_events: int = len(EVENTS)):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 128),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(128, 64),
            nn.ReLU(),
            nn.Dropout(0.2),
        )
        self.family_head = nn.Linear(64, n_families)
        self.event_head = nn.Linear(64, n_families * n_events)
        self.n_families = n_families
        self.n_events = n_events

    def forward(self, x: torch.Tensor) -> tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        h = self.encoder(x)
        family_logits = self.family_head(h)
        event_logits = self.event_head(h).view(-1, self.n_families, self.n_events)
        family_prob = torch.sigmoid(family_logits)
        conditional_prob = torch.sigmoid(event_logits)
        joint_prob = family_prob.unsqueeze(-1) * conditional_prob
        return family_logits, event_logits, joint_prob


@dataclass
class JointTrainingResult:
    model: JointFamilyEventModel
    scaler: StandardScaler
    history: pd.DataFrame
    compatibility: np.ndarray


def fit_joint_model(
    X_train: np.ndarray,
    y_family_train: np.ndarray,
    y_pair_train: np.ndarray,
    X_val: np.ndarray,
    y_family_val: np.ndarray,
    y_pair_val: np.ndarray,
    max_epochs: int = 100,
    patience: int = 10,
    batch_size: int = 512,
) -> JointTrainingResult:
    seed_everything()
    scaler = StandardScaler().fit(X_train)
    Xtr = scaler.transform(X_train).astype(np.float32)
    Xv = scaler.transform(X_val).astype(np.float32)
    compatibility = (y_pair_train.sum(axis=0) > 0).astype(np.float32)
    family_pos = np.clip((len(y_family_train) - y_family_train.sum(0)) / np.maximum(y_family_train.sum(0), 1), 1, 20)
    pair_flat = y_pair_train.reshape(len(y_pair_train), -1)
    pair_pos = np.clip((len(pair_flat) - pair_flat.sum(0)) / np.maximum(pair_flat.sum(0), 1), 1, 20)
    model = JointFamilyEventModel(Xtr.shape[1])
    optimizer = torch.optim.AdamW(model.parameters(), lr=1e-3, weight_decay=1e-4)
    family_loss_fn = nn.BCEWithLogitsLoss(pos_weight=torch.tensor(family_pos, dtype=torch.float32))
    pair_pos_t = torch.tensor(pair_pos.reshape(len(FAMILIES), len(EVENTS)), dtype=torch.float32)
    compatibility_t = torch.tensor(compatibility, dtype=torch.float32)
    loader = DataLoader(
        TensorDataset(torch.tensor(Xtr), torch.tensor(y_family_train), torch.tensor(y_pair_train)),
        batch_size=batch_size,
        shuffle=True,
    )
    best_state = None
    best_loss = math.inf
    stale = 0
    history = []
    xv_t = torch.tensor(Xv)
    yfv_t = torch.tensor(y_family_val)
    ypv_t = torch.tensor(y_pair_val)
    for epoch in range(max_epochs):
        model.train()
        train_losses = []
        for xb, yfb, ypb in loader:
            optimizer.zero_grad()
            family_logits, _, joint = model(xb)
            family_loss = family_loss_fn(family_logits, yfb)
            joint = joint.clamp(1e-6, 1 - 1e-6)
            pair_bce = -(pair_pos_t * ypb * torch.log(joint) + (1 - ypb) * torch.log(1 - joint))
            pair_loss = (pair_bce * compatibility_t).sum() / compatibility_t.sum().clamp_min(1)
            loss = family_loss + pair_loss
            loss.backward()
            optimizer.step()
            train_losses.append(float(loss.detach()))
        model.eval()
        with torch.no_grad():
            family_logits, _, joint = model(xv_t)
            val_family = family_loss_fn(family_logits, yfv_t)
            joint = joint.clamp(1e-6, 1 - 1e-6)
            val_pair_bce = -(pair_pos_t * ypv_t * torch.log(joint) + (1 - ypv_t) * torch.log(1 - joint))
            val_pair = (val_pair_bce * compatibility_t).sum() / compatibility_t.sum().clamp_min(1)
            val_loss = float(val_family + val_pair)
        history.append({"epoch": epoch + 1, "train_loss": np.mean(train_losses), "val_loss": val_loss})
        if val_loss < best_loss - 1e-4:
            best_loss = val_loss
            best_state = {k: v.detach().clone() for k, v in model.state_dict().items()}
            stale = 0
        else:
            stale += 1
            if stale >= patience:
                break
    if best_state is not None:
        model.load_state_dict(best_state)
    return JointTrainingResult(model, scaler, pd.DataFrame(history), compatibility)


def joint_predict(result: JointTrainingResult, X: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    result.model.eval()
    scaled = result.scaler.transform(X).astype(np.float32)
    family_batches, joint_batches = [], []
    with torch.no_grad():
        for start in range(0, len(scaled), 8192):
            family_logits, _, joint = result.model(torch.tensor(scaled[start : start + 8192]))
            family_batches.append(torch.sigmoid(family_logits).numpy())
            joint_batches.append(joint.numpy())
    return np.vstack(family_batches), np.vstack(joint_batches)


def gradient_feedback_check(result: JointTrainingResult, X: np.ndarray, y_pair: np.ndarray) -> float:
    result.model.zero_grad()
    xb = torch.tensor(result.scaler.transform(X[: min(64, len(X))]).astype(np.float32))
    target = torch.tensor(y_pair[: len(xb)])
    _, _, joint = result.model(xb)
    loss = nn.functional.binary_cross_entropy(joint.clamp(1e-6, 1 - 1e-6), target)
    loss.backward()
    return float(result.model.family_head.weight.grad.abs().sum())


def fit_independent_baselines(
    X: np.ndarray, y_family: np.ndarray, y_pair: np.ndarray
) -> tuple[StandardScaler, OneVsRestClassifier, OneVsRestClassifier]:
    scaler = StandardScaler().fit(X)
    xs = scaler.transform(X)
    base = LogisticRegression(max_iter=1000, class_weight="balanced", random_state=SEED)
    family_model = OneVsRestClassifier(base).fit(xs, y_family)
    pair_model = OneVsRestClassifier(clone(base)).fit(xs, y_pair.reshape(len(y_pair), -1))
    return scaler, family_model, pair_model


def family_threshold_for_coverage(
    y_true: np.ndarray,
    prob: np.ndarray,
    target: float = 0.95,
    max_candidates: int = 5,
) -> tuple[float, float, float]:
    positives = y_true.sum(axis=1) > 0
    thresholds = np.unique(np.r_[0.0, np.quantile(prob.ravel(), np.linspace(0, 1, 201)), 1.0])
    best = 0.0
    best_coverage = 0.0
    best_size = float(max_candidates)
    for threshold in thresholds:
        pred = prob >= threshold
        top = np.argsort(-prob, axis=1)[:, :max_candidates]
        capped = np.zeros_like(pred)
        for i in range(len(pred)):
            keep = [j for j in top[i] if pred[i, j]][:max_candidates]
            if not keep:
                keep = [top[i, 0]]
            capped[i, keep] = True
        coverage = np.mean(np.all(~y_true[positives].astype(bool) | capped[positives], axis=1)) if positives.any() else 1.0
        if coverage >= target and threshold >= best:
            best = float(threshold)
            best_coverage = float(coverage)
            best_size = float(capped[positives].sum(axis=1).mean()) if positives.any() else 1.0
    return best, best_coverage, best_size


def candidate_mask(prob: np.ndarray, threshold: float, max_candidates: int = 5) -> np.ndarray:
    mask = np.zeros_like(prob, dtype=bool)
    order = np.argsort(-prob, axis=1)
    for i in range(len(prob)):
        keep = [j for j in order[i, :max_candidates] if prob[i, j] >= threshold]
        if not keep:
            keep = [int(order[i, 0])]
        mask[i, keep] = True
    return mask


def best_multilabel_threshold(y_true: np.ndarray, prob: np.ndarray, beta: float = 2.0) -> float:
    candidates = np.linspace(0.05, 0.95, 91)
    scores = [fbeta_score(y_true.ravel(), (prob >= t).ravel(), beta=beta, zero_division=0) for t in candidates]
    return float(candidates[int(np.argmax(scores))])


def multilabel_metrics(y_true: np.ndarray, prob: np.ndarray, threshold: float) -> dict[str, float]:
    pred = prob >= threshold
    return {
        "micro_precision": precision_score(y_true, pred, average="micro", zero_division=0),
        "micro_recall": recall_score(y_true, pred, average="micro", zero_division=0),
        "micro_f1": fbeta_score(y_true, pred, beta=1, average="micro", zero_division=0),
        "macro_f1": fbeta_score(y_true, pred, beta=1, average="macro", zero_division=0),
        "micro_average_precision": average_precision_score(y_true, prob, average="micro"),
    }


def apply_temperature(prob: np.ndarray, temperature: float) -> np.ndarray:
    clipped = np.clip(prob, 1e-6, 1 - 1e-6)
    logits = np.log(clipped / (1 - clipped)) / max(float(temperature), 1e-3)
    return 1 / (1 + np.exp(-logits))


def fit_temperature(prob: np.ndarray, y_true: np.ndarray) -> float:
    p = np.asarray(prob, dtype=float).ravel()
    y = np.asarray(y_true, dtype=float).ravel()
    if len(np.unique(y)) < 2:
        return 1.0
    def objective(temp: float) -> float:
        calibrated = np.clip(apply_temperature(p, temp), 1e-7, 1 - 1e-7)
        return float(-np.mean(y * np.log(calibrated) + (1 - y) * np.log(1 - calibrated)))
    result = minimize_scalar(objective, bounds=(0.25, 5.0), method="bounded")
    return float(result.x)


def save_artifacts(
    model_dir: Path,
    phase1: HistGradientBoostingClassifier,
    joint: JointTrainingResult,
    metadata: dict,
) -> None:
    model_dir.mkdir(parents=True, exist_ok=True)
    joblib.dump(phase1, model_dir / "phase1.joblib")
    joblib.dump(joint.scaler, model_dir / "feature_scaler.joblib")
    torch.save(joint.model.state_dict(), model_dir / "phase23_state.pt")
    payload = dict(metadata)
    payload.update(
        {
            "families": list(FAMILIES),
            "events": list(EVENTS),
            "compatibility": joint.compatibility.tolist(),
            "model_input_dim": joint.model.encoder[0].in_features,
        }
    )
    (model_dir / "metadata.json").write_text(json.dumps(payload, indent=2))


class IoTEventPredictor:
    def __init__(self, model_dir: Path):
        self.model_dir = model_dir
        self.phase1 = joblib.load(model_dir / "phase1.joblib")
        self.scaler = joblib.load(model_dir / "feature_scaler.joblib")
        self.metadata = json.loads((model_dir / "metadata.json").read_text())
        self.joint = JointFamilyEventModel(self.metadata["model_input_dim"])
        self.joint.load_state_dict(torch.load(model_dir / "phase23_state.pt", map_location="cpu", weights_only=True))
        self.joint.eval()

    def predict_window(self, features: np.ndarray, timestamp_utc: str | pd.Timestamp) -> dict:
        x = np.asarray(features, dtype=np.float32).reshape(1, -1)
        event_probability = float(self.phase1.predict_proba(x)[0, 1])
        is_event = event_probability >= self.metadata["phase1_threshold"]
        output = {
            "timestamp_utc": str(pd.Timestamp(timestamp_utc)),
            "event_probability": event_probability,
            "is_event": bool(is_event),
            "candidates": [],
            "abstained": False,
        }
        if not is_event:
            return output
        with torch.no_grad():
            family_logits, _, joint = self.joint(torch.tensor(self.scaler.transform(x).astype(np.float32)))
            family_prob = apply_temperature(
                torch.sigmoid(family_logits).numpy(), self.metadata.get("family_temperature", 1.0)
            )[0]
            joint_prob = apply_temperature(
                joint.numpy(), self.metadata.get("pair_temperature", 1.0)
            )[0]
        mask = candidate_mask(family_prob[None, :], self.metadata["family_threshold"], 5)[0]
        pair_threshold = self.metadata["pair_threshold"]
        for fi in np.where(mask)[0]:
            events = [
                {"event": EVENTS[ei], "probability": float(joint_prob[fi, ei])}
                for ei in range(len(EVENTS))
                if self.metadata["compatibility"][fi][ei] and joint_prob[fi, ei] >= pair_threshold
            ]
            output["candidates"].append(
                {"device_family": FAMILIES[fi], "probability": float(family_prob[fi]), "events": events}
            )
        output["abstained"] = not any(c["events"] for c in output["candidates"])
        return output
