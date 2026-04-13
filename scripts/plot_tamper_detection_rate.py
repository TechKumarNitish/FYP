from __future__ import annotations

import sys
from pathlib import Path
REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import argparse
import pandas as pd
import matplotlib.pyplot as plt


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--results', required=True)
    ap.add_argument('--output', required=True)
    args = ap.parse_args()

    df = pd.read_csv(args.results)
    plt.figure(figsize=(7, 4))
    for mode in sorted(df['mode'].unique()):
        sub = df[df['mode'] == mode].groupby('tamper_level', as_index=False)['tamper_detection_rate'].mean()
        plt.plot(sub['tamper_level'], sub['tamper_detection_rate'], marker='o', label=mode)
    plt.xlabel('Tamper level')
    plt.ylabel('Tamper detection rate')
    plt.legend()
    plt.tight_layout()
    plt.savefig(args.output, dpi=300)


if __name__ == '__main__':
    main()
