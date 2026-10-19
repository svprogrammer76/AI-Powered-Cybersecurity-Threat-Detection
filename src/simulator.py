"""Generate fictional network-flow rows for a safe, reproducible lab."""
from __future__ import annotations

import numpy as np
import pandas as pd


def generate_flows(n_rows: int = 6000, random_state: int = 42) -> pd.DataFrame:
    """Create normal and simulated attack flow summaries; no packets are sent."""
    if n_rows < 100:
        raise ValueError("n_rows must be at least 100")
    rng = np.random.default_rng(random_state)
    labels = rng.choice(["benign", "dos", "brute_force", "scan"], n_rows,
                        p=[0.78, 0.09, 0.07, 0.06])
    n = n_rows
    duration = rng.gamma(2.2, 1.8, n) + 0.05
    packets = rng.poisson(18, n) + 1
    bytes_total = packets * rng.lognormal(5.2, 0.65, n)
    failed = rng.binomial(np.maximum(packets // 3, 1), 0.04)
    dst_ports = rng.choice([53, 80, 443, 22, 8080, 25, 3306], n,
                           p=[.08, .28, .42, .08, .06, .04, .04])
    # Create distinguishable but overlapping patterns rather than perfect labels.
    mask = labels == "dos"
    duration[mask] = rng.gamma(1.2, .25, mask.sum()) + .01
    packets[mask] = rng.poisson(150, mask.sum()) + 20
    bytes_total[mask] = packets[mask] * rng.lognormal(4.7, .6, mask.sum())
    mask = labels == "brute_force"
    dst_ports[mask] = 22
    failed[mask] = rng.poisson(8, mask.sum()) + 3
    packets[mask] = rng.poisson(35, mask.sum()) + 10
    mask = labels == "scan"
    dst_ports[mask] = rng.choice([21, 22, 23, 445, 1433, 3389], mask.sum())
    packets[mask] = rng.poisson(3, mask.sum()) + 1
    duration[mask] = rng.gamma(1.1, .4, mask.sum()) + .01

    df = pd.DataFrame({
        "flow_id": np.arange(1, n + 1),
        "duration_s": np.round(duration, 4),
        "src_bytes": np.round(bytes_total * rng.uniform(.2, .8, n), 2),
        "dst_bytes": np.round(bytes_total * rng.uniform(.2, .8, n), 2),
        "packet_count": packets.astype(int),
        "failed_logins": failed.astype(int),
        "dst_port": dst_ports.astype(int),
        "protocol": rng.choice(["tcp", "udp", "icmp"], n, p=[.78, .19, .03]),
        "label": labels,
    })
    df["bytes_per_second"] = np.round((df.src_bytes + df.dst_bytes) / df.duration_s, 2)
    df["avg_packet_size"] = np.round((df.src_bytes + df.dst_bytes) / df.packet_count, 2)
    return df
