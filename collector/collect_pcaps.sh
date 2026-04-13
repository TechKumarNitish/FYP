#!/usr/bin/env bash
set -euo pipefail
OUTDIR=${1:-data/raw/run_001}
mkdir -p "$OUTDIR"
sudo tcpdump -i any udp port 8805 -w "$OUTDIR/pfcp.pcap"
