from __future__ import annotations

import sys
from pathlib import Path
REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import argparse
import csv
import subprocess

SCENARIOS = ['benign', 'pfcp_attack', 'session_anomaly']
TAMPER_LEVELS = [0.0, 0.1, 0.2, 0.3]
MODES = [('baseline', 'configs/baseline.yaml'), ('trustaware', 'configs/trustaware.yaml')]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--input-dir', required=True)
    ap.add_argument('--results-csv', required=True)
    args = ap.parse_args()

    results_path = Path(args.results_csv)
    results_path.parent.mkdir(parents=True, exist_ok=True)
    rows = []

    for scenario in SCENARIOS:
        for tamper in TAMPER_LEVELS:
            for mode_name, config_path in MODES:
                outdir = REPO_ROOT / 'outputs' / f'{scenario}_{mode_name}_{str(tamper).replace(".", "p")}'
                cmd = [
                    sys.executable, str(REPO_ROOT / 'scripts' / 'run_pipeline.py'),
                    '--input-dir', args.input_dir,
                    '--config', str(REPO_ROOT / config_path),
                    '--output-dir', str(outdir),
                    '--scenario', scenario,
                    '--tamper-level', str(tamper),
                ]
                subprocess.run(cmd, check=True)
                metrics_file = outdir / 'metrics.csv'
                with open(metrics_file, newline='', encoding='utf-8') as f:
                    rows.extend(list(csv.DictReader(f)))

    if rows:
        with open(results_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            writer.writeheader()
            writer.writerows(rows)
        print(f'Wrote {len(rows)} rows to {results_path}')


if __name__ == '__main__':
    main()
