from __future__ import annotations

import sys
from pathlib import Path
REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import argparse
import pandas as pd


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--results', required=True)
    ap.add_argument('--output', required=True)
    args = ap.parse_args()
    df = pd.read_csv(args.results)
    summary = df.groupby(['mode', 'tamper_level'], as_index=False)[['precision', 'recall', 'f1', 'tamper_detection_rate']].mean()
    summary.to_csv(args.output, index=False)


if __name__ == '__main__':
    main()
