#!/usr/bin/env bash
set -euo pipefail
OUTDIR=${1:-data/raw/run_001}
mkdir -p "$OUTDIR"
echo "Run UERANSIM manually and redirect stdout to $OUTDIR/gnb.log and $OUTDIR/ue.log"
