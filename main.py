"""Run the self-contained synthetic network threat detection demonstration."""
from __future__ import annotations

import argparse
from pathlib import Path

from src.pipeline import train_and_detect
from src.simulator import generate_flows

ROOT = Path(__file__).resolve().parent


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rows", type=int, default=6000, help="number of simulated flow rows (minimum 100)")
    parser.add_argument("--seed", type=int, default=42, help="random seed for repeatable output")
    args = parser.parse_args()
    data_dir, output_dir, model_dir = ROOT / "data", ROOT / "outputs", ROOT / "models"
    data_dir.mkdir(exist_ok=True)
    flows = generate_flows(args.rows, args.seed)
    flows.to_csv(data_dir / "synthetic_flows.csv", index=False)
    metrics = train_and_detect(flows, output_dir, model_dir, args.seed)
    print(f"Generated {len(flows):,} fictional flow records at {data_dir / 'synthetic_flows.csv'}")
    print(f"Held-out macro F1: {metrics['f1_macro']:.3f} | accuracy: {metrics['accuracy']:.3f}")
    print(f"Alerts: {metrics['alert_count_in_test_split']:,} | see {output_dir}")
    print("Educational simulation only. No packets were captured or transmitted.")


if __name__ == "__main__":
    main()
