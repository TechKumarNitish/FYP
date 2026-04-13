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
    agg = df.groupby('mode', as_index=False)[['precision', 'recall']].mean()
    x = range(len(agg))
    width = 0.35
    plt.figure(figsize=(7, 4))
    plt.bar([i - width/2 for i in x], agg['precision'], width=width, label='Precision')
    plt.bar([i + width/2 for i in x], agg['recall'], width=width, label='Recall')
    plt.xticks(list(x), agg['mode'])
    plt.ylabel('Score')
    plt.xlabel('Mode')
    plt.legend()
    plt.tight_layout()
    plt.savefig(args.output, dpi=300)


if __name__ == '__main__':
    main()
