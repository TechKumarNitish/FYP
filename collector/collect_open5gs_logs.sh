#!/usr/bin/env bash
set -euo pipefail
OUTDIR=${1:-data/raw/run_001}
echo "$OUTDIR"
mkdir -p "$OUTDIR"
sudo journalctl -u open5gs-amfd -o short-iso > "$OUTDIR/amf.log"
sudo journalctl -u open5gs-smfd -o short-iso > "$OUTDIR/smf.log"
sudo journalctl -u open5gs-upfd -o short-iso > "$OUTDIR/upf.log"
