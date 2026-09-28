from __future__ import annotations

import json
import os
import shutil
from pathlib import Path
from collections import Counter

import duckdb
import numpy as np


# ============================================================
# CONFIGURATION
# ============================================================

DATASET_FOLDER = "../../../dataset/processed-data"

DEVICE_MAPPING_FOLDER = (
    DATASET_FOLDER
    + "/device-mapping"
)

INPUT_FOLDER = (
    DATASET_FOLDER
    + "/input-data"
)

DATASET3 = "dataset3"

EXTRACTED_DATA_FOLDER = (
    INPUT_FOLDER
    + "/"
    + DATASET3
    + "/yourthings_raw.parquet"
)

DEVICE_TO_BE_INCLUDE = (
    DEVICE_MAPPING_FOLDER
    + "/"
    + DATASET3
    + "/device_to_be_include.json"
)

EXPORTED_FEATURE_FOLDER = (
    "dataset3-feature-window"
)


# ============================================================
# SAME SPLIT SETTINGS AS NOTEBOOK
# ============================================================

KSPLITS = 5
RANDOM_SEED = 42


# ============================================================
# DuckDB settings
#
# Your kernel was dying because pandas was consuming too much
# memory. Keep DuckDB below total system RAM and let it spill
# temporary data to disk.
# ============================================================

DUCKDB_THREADS = min(
    6,
    os.cpu_count() or 4,
)

DUCKDB_MEMORY_LIMIT = "6GB"


# ============================================================
# Base aggregation window
#
# Every window in your notebook is divisible by 2, so we can
# compute 2-second features once and exactly aggregate those
# features into every larger window.
# ============================================================

BASE_WINDOW = 2


# ============================================================
# SAME WINDOW LIST AS NOTEBOOK
# ============================================================

WINDOW_SIZES = [
    2,
    4,
    8,
    16,
    32,
    64,
    128,
    256,
]

while WINDOW_SIZES[-1] < 10800:
    WINDOW_SIZES.append(
        WINDOW_SIZES[-1] + 256
    )


# ============================================================
# SQL helper
# ============================================================

def sql_quote(value: str | Path) -> str:
    """
    Safely quote a string/path for DuckDB SQL.
    """

    value = str(value)

    return (
        "'"
        + value.replace(
            "'",
            "''",
        )
        + "'"
    )


# ============================================================
# Load device mapping
# ============================================================

def load_device_mapping() -> dict:

    with open(
        DEVICE_TO_BE_INCLUDE,
        "r",
    ) as f:

        device_dict = json.load(f)

    if not device_dict:
        raise ValueError(
            "Device mapping is empty."
        )

    return device_dict


# ============================================================
# Create MAC SQL list
# ============================================================

def build_device_sql(
    devices: set[str],
) -> str:

    return ", ".join(
        sql_quote(mac)
        for mac in sorted(devices)
    )


# ============================================================
# Validate paths
# ============================================================

def validate_inputs() -> None:

    raw_path = Path(
        EXTRACTED_DATA_FOLDER
    )

    mapping_path = Path(
        DEVICE_TO_BE_INCLUDE
    )

    if not raw_path.exists():

        raise FileNotFoundError(
            f"Raw parquet does not exist:\n"
            f"{raw_path}"
        )

    if not mapping_path.exists():

        raise FileNotFoundError(
            f"Device mapping does not exist:\n"
            f"{mapping_path}"
        )


# ============================================================
# Configure DuckDB
# ============================================================

def create_connection(
    temp_directory: Path,
):

    temp_directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    con = duckdb.connect(
        database=":memory:"
    )

    con.execute(
        f"SET threads = {DUCKDB_THREADS}"
    )

    con.execute(
        f"SET memory_limit = "
        f"{sql_quote(DUCKDB_MEMORY_LIMIT)}"
    )

    con.execute(
        f"SET temp_directory = "
        f"{sql_quote(temp_directory)}"
    )

    # We explicitly ORDER BY when output order matters.
    # Therefore DuckDB does not have to preserve insertion
    # order internally during the expensive aggregations.
    con.execute(
        "SET preserve_insertion_order = false"
    )

    return con


# ============================================================
# Build capture metadata
#
# This reproduces:
#
# capture_start =
#     capture_df["frame.time_epoch"].min()
#
# from the original build_feature().
# ============================================================

def build_capture_metadata(
    con,
    raw_parquet_path: Path,
) -> None:

    print()
    print("=" * 80)
    print("BUILDING CAPTURE METADATA")
    print("=" * 80)

    raw_sql = sql_quote(
        raw_parquet_path
    )

    con.execute(
        f"""
        CREATE OR REPLACE TEMP TABLE
            capture_metadata
        AS

        SELECT
            capture_id,

            CAST(
                MIN("frame.time_epoch")
                AS DOUBLE
            ) AS capture_start

        FROM read_parquet(
            {raw_sql}
        )

        WHERE
            capture_id IS NOT NULL
            AND "frame.time_epoch" IS NOT NULL
            AND "frame.time_epoch" > 0

        GROUP BY capture_id
        """
    )

    captures = con.execute(
        """
        SELECT
            capture_id,
            capture_start

        FROM capture_metadata

        ORDER BY
            capture_start,
            capture_id
        """
    ).fetchall()

    print(
        f"Captures found: {len(captures)}"
    )

    for (
        capture_id,
        capture_start,
    ) in captures:

        print(
            f"  {capture_id}: "
            f"{capture_start}"
        )

# ============================================================
# Build exact 2-second base features
#
# This replaces the expensive pandas operations:
#
#     raw_df.copy()
#     capture_df.copy()
#     outgoing groupby
#     incoming groupby
#     outer merge
#
# The resulting internal file contains:
#
#     capture_id
#     window
#     mac
#     outgoing_packet_count
#     outgoing_total_bytes
#     incoming_packet_count
#     incoming_total_bytes
#     first_active_timestamp
#     last_active_timestamp
#     capture_start
#
# Completely inactive device-windows are NOT created,
# matching the notebook.
# ============================================================

def build_base_features(
    con,
    raw_parquet_path: Path,
    base_feature_path: Path,
    device_sql: str,
) -> None:

    print()
    print("=" * 80)
    print(
        f"BUILDING {BASE_WINDOW}-SECOND BASE FEATURES"
    )
    print("=" * 80)

    raw_sql = sql_quote(
        raw_parquet_path
    )

    base_sql = sql_quote(
        base_feature_path
    )

    if base_feature_path.exists():
        base_feature_path.unlink()

    query = f"""
    COPY (

        WITH outgoing AS (

            SELECT

                p.capture_id,

                CAST(
                    FLOOR(
                        (
                            p."frame.time_epoch"
                            - c.capture_start
                        )
                        / {BASE_WINDOW}
                    )
                    AS BIGINT
                ) AS window_idx,

                p."eth.src" AS mac,

                CAST(
                    COUNT(*)
                    AS BIGINT
                ) AS outgoing_packet_count,

                CAST(
                    SUM(p."frame.len")
                    AS BIGINT
                ) AS outgoing_total_bytes,

                CAST(
                    MIN(p."frame.time_epoch")
                    AS DOUBLE
                ) AS outgoing_first_timestamp,

                CAST(
                    MAX(p."frame.time_epoch")
                    AS DOUBLE
                ) AS outgoing_last_timestamp,

                c.capture_start

            FROM read_parquet(
                {raw_sql}
            ) p

            INNER JOIN capture_metadata c
                ON p.capture_id = c.capture_id

            WHERE
                p."eth.src" IN ({device_sql})

                AND p."frame.time_epoch"
                    IS NOT NULL

                AND p."frame.time_epoch" > 0

            GROUP BY
                p.capture_id,
                window_idx,
                p."eth.src",
                c.capture_start
        ),

        incoming AS (

            SELECT

                p.capture_id,

                CAST(
                    FLOOR(
                        (
                            p."frame.time_epoch"
                            - c.capture_start
                        )
                        / {BASE_WINDOW}
                    )
                    AS BIGINT
                ) AS window_idx,

                p."eth.dst" AS mac,

                CAST(
                    COUNT(*)
                    AS BIGINT
                ) AS incoming_packet_count,

                CAST(
                    SUM(p."frame.len")
                    AS BIGINT
                ) AS incoming_total_bytes,

                CAST(
                    MIN(p."frame.time_epoch")
                    AS DOUBLE
                ) AS incoming_first_timestamp,

                CAST(
                    MAX(p."frame.time_epoch")
                    AS DOUBLE
                ) AS incoming_last_timestamp,

                c.capture_start

            FROM read_parquet(
                {raw_sql}
            ) p

            INNER JOIN capture_metadata c
                ON p.capture_id = c.capture_id

            WHERE
                p."eth.dst" IN ({device_sql})

                AND p."frame.time_epoch"
                    IS NOT NULL

                AND p."frame.time_epoch" > 0

            GROUP BY
                p.capture_id,
                window_idx,
                p."eth.dst",
                c.capture_start
        ),

        merged AS (

            SELECT

                COALESCE(
                    o.capture_id,
                    i.capture_id
                ) AS capture_id,

                COALESCE(
                    o.window_idx,
                    i.window_idx
                ) AS window_idx,

                COALESCE(
                    o.mac,
                    i.mac
                ) AS mac,

                CAST(
                    COALESCE(
                        o.outgoing_packet_count,
                        0
                    )
                    AS BIGINT
                ) AS outgoing_packet_count,

                CAST(
                    COALESCE(
                        o.outgoing_total_bytes,
                        0
                    )
                    AS BIGINT
                ) AS outgoing_total_bytes,

                CAST(
                    COALESCE(
                        i.incoming_packet_count,
                        0
                    )
                    AS BIGINT
                ) AS incoming_packet_count,

                CAST(
                    COALESCE(
                        i.incoming_total_bytes,
                        0
                    )
                    AS BIGINT
                ) AS incoming_total_bytes,

                CASE

                    WHEN
                        o.outgoing_first_timestamp
                        IS NULL

                    THEN
                        i.incoming_first_timestamp

                    WHEN
                        i.incoming_first_timestamp
                        IS NULL

                    THEN
                        o.outgoing_first_timestamp

                    ELSE
                        LEAST(
                            o.outgoing_first_timestamp,
                            i.incoming_first_timestamp
                        )

                END AS first_active_timestamp,

                CASE

                    WHEN
                        o.outgoing_last_timestamp
                        IS NULL

                    THEN
                        i.incoming_last_timestamp

                    WHEN
                        i.incoming_last_timestamp
                        IS NULL

                    THEN
                        o.outgoing_last_timestamp

                    ELSE
                        GREATEST(
                            o.outgoing_last_timestamp,
                            i.incoming_last_timestamp
                        )

                END AS last_active_timestamp,

                COALESCE(
                    o.capture_start,
                    i.capture_start
                ) AS capture_start

            FROM outgoing o

            FULL OUTER JOIN incoming i

                ON
                    o.capture_id
                    = i.capture_id

                AND
                    o.window_idx
                    = i.window_idx

                AND
                    o.mac
                    = i.mac
        )

        SELECT

            capture_id,

            window_idx,

            mac,

            outgoing_packet_count,

            outgoing_total_bytes,

            incoming_packet_count,

            incoming_total_bytes,

            first_active_timestamp,

            last_active_timestamp,

            capture_start

        FROM merged

    )

    TO {base_sql}

    (
        FORMAT PARQUET,
        COMPRESSION SNAPPY,
        ROW_GROUP_SIZE 500000
    )
    """

    con.execute(query)

    stats = con.execute(
        f"""
        SELECT
            COUNT(*),
            COUNT(DISTINCT mac),
            COUNT(DISTINCT capture_id)

        FROM read_parquet(
            {base_sql}
        )
        """
    ).fetchone()

    print(
        f"Base feature rows : "
        f"{stats[0]:,}"
    )

    print(
        f"Devices           : "
        f"{stats[1]}"
    )

    print(
        f"Captures          : "
        f"{stats[2]}"
    )

# ============================================================
# Build one requested window
#
# This reproduces your notebook's build_feature().
#
# Because every requested window is a multiple of 2:
#
#     floor(base_window / factor)
#
# gives the same globally aligned larger window.
#
# idle_time is then recomputed at the FINAL requested window,
# exactly like your original implementation.
# ============================================================

def build_feature_window(
    con,
    base_feature_path: Path,
    window_size: int,
    output_path: Path,
) -> None:

    if window_size <= 0:
        raise ValueError(
            "window must be greater than 0"
        )

    if (
        window_size
        % BASE_WINDOW
        != 0
    ):

        raise ValueError(
            f"Window {window_size} is not "
            f"divisible by base window "
            f"{BASE_WINDOW}."
        )

    factor = (
        window_size
        // BASE_WINDOW
    )

    base_sql = sql_quote(
        base_feature_path
    )

    output_sql = sql_quote(
        output_path
    )

    query = f"""
    COPY (

        WITH aggregated AS (

            SELECT

                capture_id,

                CAST(
                    FLOOR(
                        window_idx / {factor}
                    )
                    AS BIGINT
                ) AS final_window_idx,

                mac,

                CAST(
                    SUM(
                        outgoing_packet_count
                    )
                    AS BIGINT
                )
                    AS outgoing_packet_count,

                CAST(
                    SUM(
                        outgoing_total_bytes
                    )
                    AS BIGINT
                )
                    AS outgoing_total_bytes,

                CAST(
                    SUM(
                        incoming_packet_count
                    )
                    AS BIGINT
                )
                    AS incoming_packet_count,

                CAST(
                    SUM(
                        incoming_total_bytes
                    )
                    AS BIGINT
                )
                    AS incoming_total_bytes,

                CAST(
                    MIN(
                        first_active_timestamp
                    )
                    AS DOUBLE
                )
                    AS first_active_timestamp,

                CAST(
                    MAX(
                        last_active_timestamp
                    )
                    AS DOUBLE
                )
                    AS last_active_timestamp,

                CAST(
                    MIN(
                        capture_start
                    )
                    AS DOUBLE
                )
                    AS capture_start

            FROM read_parquet(
                {base_sql}
            )

            GROUP BY
                capture_id,
                final_window_idx,
                mac
        ),

        with_previous AS (

            SELECT

                capture_id,

                final_window_idx,

                mac,

                outgoing_packet_count,

                outgoing_total_bytes,

                incoming_packet_count,

                incoming_total_bytes,

                CAST(
                    outgoing_packet_count
                    + incoming_packet_count
                    AS BIGINT
                )
                    AS aggregated_packet_count,

                CAST(
                    outgoing_total_bytes
                    + incoming_total_bytes
                    AS BIGINT
                )
                    AS aggregated_total_bytes,

                first_active_timestamp,

                last_active_timestamp,

                capture_start,

                LAG(
                    last_active_timestamp
                )
                OVER (

                    PARTITION BY
                        capture_id,
                        mac

                    ORDER BY
                        final_window_idx
                )
                    AS previous_last_active_timestamp

            FROM aggregated
        )

        SELECT

            capture_id,

            CAST(
                final_window_idx
                AS BIGINT
            ) AS "window",

            mac,

            CAST(
                outgoing_packet_count
                AS BIGINT
            )
                AS outgoing_packet_count,

            CAST(
                outgoing_total_bytes
                AS BIGINT
            )
                AS outgoing_total_bytes,

            CAST(
                incoming_packet_count
                AS BIGINT
            )
                AS incoming_packet_count,

            CAST(
                incoming_total_bytes
                AS BIGINT
            )
                AS incoming_total_bytes,

            CAST(
                aggregated_packet_count
                AS BIGINT
            )
                AS aggregated_packet_count,

            CAST(
                aggregated_total_bytes
                AS BIGINT
            )
                AS aggregated_total_bytes,

            CAST(
                first_active_timestamp
                -
                COALESCE(
                    previous_last_active_timestamp,
                    capture_start
                )
                AS DOUBLE
            )
                AS idle_time

        FROM with_previous

        ORDER BY
            capture_start,
            capture_id,
            mac,
            final_window_idx
    )

    TO {output_sql}

    (
        FORMAT PARQUET,
        COMPRESSION SNAPPY,
        ROW_GROUP_SIZE 500000
    )
    """

    con.execute(query)

# ============================================================
# Get row ranges for each (device, capture)
#
# data.parquet is ordered:
#
#     capture
#     mac
#     window
#
# Therefore rows belonging to one (capture, mac) pair are
# contiguous.
#
# Instead of loading millions of rows into pandas, we only need
# the number of feature rows for each pair.
# ============================================================

def get_device_capture_ranges(
    con,
    feature_path: Path,
):

    feature_sql = sql_quote(
        feature_path
    )

    rows = con.execute(
        f"""
        SELECT

            f.capture_id,

            f.mac,

            COUNT(*) AS row_count,

            c.capture_start

        FROM read_parquet(
            {feature_sql}
        ) f

        INNER JOIN capture_metadata c
            ON
                f.capture_id
                = c.capture_id

        GROUP BY
            f.capture_id,
            f.mac,
            c.capture_start

        ORDER BY
            c.capture_start,
            f.capture_id,
            f.mac
        """
    ).fetchall()

    ranges = []

    current_position = 0

    for (
        capture_id,
        mac,
        row_count,
        capture_start,
    ) in rows:

        row_count = int(
            row_count
        )

        start = current_position

        end = (
            current_position
            + row_count
        )

        ranges.append(
            {
                "capture_id":
                    capture_id,

                "mac":
                    mac,

                "start":
                    start,

                "end":
                    end,

                "count":
                    row_count,
            }
        )

        current_position = end

    return (
        ranges,
        current_position,
    )


# ============================================================
# Reproduce device_capture_repeated_split()
#
# We intentionally preserve:
#
#     np.random.default_rng(42)
#
# and the device ordering implied by the saved feature rows.
#
# We do NOT create train_iloc / val_iloc arrays in memory.
# Instead we return index ranges, which are streamed into JSON.
# ============================================================

def build_fold_ranges(
    device_capture_ranges,
    target_devices: set[str],
    n_splits: int = 5,
    random_state: int = 42,
):

    # --------------------------------------------------------
    # Equivalent of:
    #
    # work_df[["mac", "capture_id"]].drop_duplicates()
    #
    # Since ranges are already in dataframe row order.
    # --------------------------------------------------------

    captures_by_device = {}

    for item in device_capture_ranges:

        mac = item["mac"]

        capture_id = (
            item["capture_id"]
        )

        if mac not in captures_by_device:
            captures_by_device[mac] = []

        if (
            capture_id
            not in captures_by_device[mac]
        ):
            captures_by_device[
                mac
            ].append(
                capture_id
            )


    # --------------------------------------------------------
    # Same validation as notebook
    # --------------------------------------------------------

    existing_devices = set(
        captures_by_device.keys()
    )

    missing_devices = (
        target_devices
        - existing_devices
    )

    if missing_devices:

        raise ValueError(
            "Devices not found in dataframe: "
            f"{missing_devices}"
        )


    insufficient = {
        device: len(captures)
        for device, captures
        in captures_by_device.items()
        if len(captures) < 2
    }

    if insufficient:

        raise ValueError(
            "These devices have fewer than "
            "2 capture_ids, so capture-level "
            "train/validation separation is "
            "impossible:\n"
            f"{insufficient}"
        )


    # --------------------------------------------------------
    # SAME RNG as notebook
    # --------------------------------------------------------

    rng = np.random.default_rng(
        random_state
    )

    shuffled_captures = {}

    for (
        device,
        captures,
    ) in captures_by_device.items():

        capture_array = np.array(
            captures,
            dtype=object,
        )

        rng.shuffle(
            capture_array
        )

        shuffled_captures[
            device
        ] = (
            capture_array.tolist()
        )


    # --------------------------------------------------------
    # Build fold metadata as ranges
    # --------------------------------------------------------

    folds = []

    for fold_idx in range(
        n_splits
    ):

        val_capture_by_device = {
            device:
                captures[
                    fold_idx
                    % len(captures)
                ]

            for (
                device,
                captures,
            )
            in shuffled_captures.items()
        }

        train_ranges = []
        val_ranges = []

        for item in device_capture_ranges:

            mac = item["mac"]

            capture_id = (
                item["capture_id"]
            )

            range_tuple = (
                item["start"],
                item["end"],
            )

            if (
                capture_id
                ==
                val_capture_by_device[
                    mac
                ]
            ):

                val_ranges.append(
                    range_tuple
                )

            else:

                train_ranges.append(
                    range_tuple
                )

        folds.append(
            {
                "fold":
                    fold_idx,

                "train_ranges":
                    train_ranges,

                "val_ranges":
                    val_ranges,

                "val_capture_by_device":
                    val_capture_by_device,
            }
        )

    return folds


# ============================================================
# Count how many indices a collection of ranges contains
# ============================================================

def count_range_values(
    ranges,
) -> int:

    return sum(
        end - start
        for (
            start,
            end,
        )
        in ranges
    )


# ============================================================
# Efficiently write explicit iloc lists
#
# Your original JSON stores:
#
#     "train_iloc": [0, 1, 2, ...]
#
# We keep EXACTLY that logical structure.
#
# The difference is that we generate those numbers directly
# into the JSON file instead of constructing a giant Python
# list in RAM.
# ============================================================

def write_integer_ranges_as_json_array(
    file,
    ranges,
    chunk_size: int = 50_000,
) -> None:

    file.write("[")

    first_value = True

    for (
        start,
        end,
    ) in ranges:

        chunk_start = start

        while chunk_start < end:

            chunk_end = min(
                chunk_start
                + chunk_size,
                end,
            )

            text = ",".join(
                map(
                    str,
                    range(
                        chunk_start,
                        chunk_end,
                    ),
                )
            )

            if text:

                if not first_value:
                    file.write(",")

                file.write(text)

                first_value = False

            chunk_start = chunk_end

    file.write("]")


# ============================================================
# Write SAME training_and_validation_fold.json structure
#
# Structure:
#
# [
#     {
#         "fold": 0,
#         "train_iloc": [...],
#         "val_iloc": [...],
#         "val_capture_by_device": {...}
#     },
#     ...
# ]
#
# Formatting is slightly more compact than json.dump(indent=4)
# so the huge index arrays consume less disk, but json.load()
# returns the same Python structure.
# ============================================================

def write_fold_json(
    output_path: Path,
    folds,
) -> None:

    with open(
        output_path,
        "w",
    ) as f:

        f.write("[\n")

        for (
            fold_position,
            fold,
        ) in enumerate(folds):

            f.write("    {\n")

            f.write(
                f'        "fold": '
                f'{fold["fold"]},\n'
            )

            f.write(
                '        "train_iloc": '
            )

            write_integer_ranges_as_json_array(
                f,
                fold["train_ranges"],
            )

            f.write(",\n")

            f.write(
                '        "val_iloc": '
            )

            write_integer_ranges_as_json_array(
                f,
                fold["val_ranges"],
            )

            f.write(",\n")

            f.write(
                '        '
                '"val_capture_by_device": '
            )

            json.dump(
                fold[
                    "val_capture_by_device"
                ],
                f,
                separators=(
                    ",",
                    ":",
                ),
            )

            f.write("\n")
            f.write("    }")

            if (
                fold_position
                < len(folds) - 1
            ):
                f.write(",")

            f.write("\n")

        f.write("]\n")


# ============================================================
# Validate generated Parquet
# ============================================================

def validate_feature_file(
    con,
    feature_path: Path,
):

    feature_sql = sql_quote(
        feature_path
    )

    result = con.execute(
        f"""
        SELECT

            COUNT(*) AS rows,

            COUNT(
                DISTINCT mac
            ) AS devices,

            COUNT(
                DISTINCT capture_id
            ) AS captures,

            MIN("window")
                AS min_window,

            MAX("window")
                AS max_window

        FROM read_parquet(
            {feature_sql}
        )
        """
    ).fetchone()

    return {
        "rows":
            int(result[0]),

        "devices":
            int(result[1]),

        "captures":
            int(result[2]),

        "min_window":
            result[3],

        "max_window":
            result[4],
    }

# ============================================================
# Process one window
# ============================================================

def process_window(
    con,
    base_feature_path: Path,
    window_size: int,
    target_devices: set[str],
) -> None:

    print()
    print("=" * 80)
    print(
        f"PROCESSING WINDOW: "
        f"{window_size} seconds"
    )
    print("=" * 80)

    feature_window_folder = (
        Path(
            EXPORTED_FEATURE_FOLDER
        )
        / str(window_size)
    )

    data_path = (
        feature_window_folder
        / "data.parquet"
    )

    fold_path = (
        feature_window_folder
        / "training_and_validation_fold.json"
    )


    # --------------------------------------------------------
    # SAME behavior as notebook:
    #
    # delete existing window folder
    # --------------------------------------------------------

    if feature_window_folder.exists():

        print(
            "WARNING: Folder "
            f"{feature_window_folder.stem} "
            "exists, overriding it!"
        )

        shutil.rmtree(
            feature_window_folder
        )

    feature_window_folder.mkdir(
        parents=True,
        exist_ok=True,
    )


    # --------------------------------------------------------
    # Build data.parquet directly to disk
    # --------------------------------------------------------

    build_feature_window(
        con=con,
        base_feature_path=base_feature_path,
        window_size=window_size,
        output_path=data_path,
    )


    # --------------------------------------------------------
    # Validate
    # --------------------------------------------------------

    stats = validate_feature_file(
        con,
        data_path,
    )

    print(
        f"Rows     : "
        f"{stats['rows']:,}"
    )

    print(
        f"Devices  : "
        f"{stats['devices']}"
    )

    print(
        f"Captures : "
        f"{stats['captures']}"
    )


    # --------------------------------------------------------
    # Determine contiguous iloc ranges
    # --------------------------------------------------------

    (
        device_capture_ranges,
        total_rows,
    ) = get_device_capture_ranges(
        con,
        data_path,
    )

    if (
        total_rows
        != stats["rows"]
    ):

        raise RuntimeError(
            "Row range calculation does "
            "not match Parquet row count."
        )


    # --------------------------------------------------------
    # Same repeated capture split semantics
    # --------------------------------------------------------

    folds = build_fold_ranges(
        device_capture_ranges=
            device_capture_ranges,

        target_devices=
            target_devices,

        n_splits=
            KSPLITS,

        random_state=
            RANDOM_SEED,
    )


    # --------------------------------------------------------
    # Print fold sizes
    # --------------------------------------------------------

    for fold in folds:

        train_count = (
            count_range_values(
                fold["train_ranges"]
            )
        )

        val_count = (
            count_range_values(
                fold["val_ranges"]
            )
        )

        print(
            f"Fold {fold['fold']}: "
            f"train={train_count:,}, "
            f"validation={val_count:,}"
        )


    # --------------------------------------------------------
    # Write full train_iloc / val_iloc JSON,
    # but without putting those lists in memory
    # --------------------------------------------------------

    write_fold_json(
        output_path=fold_path,
        folds=folds,
    )

    print(
        f"INFO: Finish processing "
        f"for window {window_size}."
    )


# ============================================================
# Main
# ============================================================

def main():

    validate_inputs()

    output_root = Path(
        EXPORTED_FEATURE_FOLDER
    )

    output_root.mkdir(
        parents=True,
        exist_ok=True,
    )


    # --------------------------------------------------------
    # Internal temporary/cache directory
    #
    # It is deleted when processing completes successfully.
    # --------------------------------------------------------

    cache_folder = (
        output_root
        / ".feature_build_cache"
    )

    if cache_folder.exists():

        shutil.rmtree(
            cache_folder
        )

    cache_folder.mkdir(
        parents=True,
        exist_ok=True,
    )

    duckdb_temp_directory = (
        cache_folder
        / "duckdb_temp"
    )

    duckdb_temp_directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    base_feature_path = (
        cache_folder
        / "base_2_second_features.parquet"
    )


    # --------------------------------------------------------
    # Load MAC mapping
    # --------------------------------------------------------

    device_dict = (
        load_device_mapping()
    )

    set_all_devices = set(
        device_dict.keys()
    )

    device_sql = (
        build_device_sql(
            set_all_devices
        )
    )


    print("=" * 80)
    print("FEATURE CONSTRUCTION")
    print("=" * 80)

    print(
        f"Raw parquet     : "
        f"{EXTRACTED_DATA_FOLDER}"
    )

    print(
        f"Device mapping  : "
        f"{DEVICE_TO_BE_INCLUDE}"
    )

    print(
        f"Output folder   : "
        f"{EXPORTED_FEATURE_FOLDER}"
    )

    print(
        f"Devices         : "
        f"{len(set_all_devices)}"
    )

    print(
        f"Window sizes    : "
        f"{len(WINDOW_SIZES)}"
    )

    print(
        f"DuckDB threads  : "
        f"{DUCKDB_THREADS}"
    )

    print(
        f"DuckDB RAM limit: "
        f"{DUCKDB_MEMORY_LIMIT}"
    )


    # --------------------------------------------------------
    # Connect
    # --------------------------------------------------------

    con = create_connection(
        duckdb_temp_directory
    )

    success = False

    try:

        # ----------------------------------------------------
        # Raw packet Parquet is scanned here to calculate
        # capture start.
        # ----------------------------------------------------

        build_capture_metadata(
            con,
            Path(
                EXTRACTED_DATA_FOLDER
            ),
        )


        # ----------------------------------------------------
        # Raw packet Parquet is scanned once more here to
        # construct the exact 2-second feature base.
        #
        # All subsequent windows use ONLY the base dataset.
        # ----------------------------------------------------

        build_base_features(
            con=con,

            raw_parquet_path=Path(
                EXTRACTED_DATA_FOLDER
            ),

            base_feature_path=
                base_feature_path,

            device_sql=
                device_sql,
        )


        # ----------------------------------------------------
        # Build all 50 outputs
        # ----------------------------------------------------

        for (
            index,
            window_size,
        ) in enumerate(
            WINDOW_SIZES,
            start=1,
        ):

            print()
            print(
                f"[{index}/"
                f"{len(WINDOW_SIZES)}]"
            )

            process_window(
                con=con,

                base_feature_path=
                    base_feature_path,

                window_size=
                    window_size,

                target_devices=
                    set_all_devices,
            )

        success = True

    finally:

        con.close()


        # ----------------------------------------------------
        # Remove temporary files on success.
        #
        # If the script fails, leave the cache so you can
        # inspect disk usage / DuckDB temporary files.
        # ----------------------------------------------------

        if (
            success
            and cache_folder.exists()
        ):

            shutil.rmtree(
                cache_folder
            )


    print()
    print("=" * 80)
    print(
        "ALL FEATURE WINDOWS COMPLETE"
    )
    print("=" * 80)

    print(
        f"Generated "
        f"{len(WINDOW_SIZES)} "
        f"window configurations."
    )

    print(
        f"Output folder: "
        f"{EXPORTED_FEATURE_FOLDER}"
    )


# ============================================================
# Entry point
# ============================================================

if __name__ == "__main__":
    main()