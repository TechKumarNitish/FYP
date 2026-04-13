# TrustProv5GC

This repository is a **research prototype** for a B.Tech paper on tamper-aware provenance-based attack detection in 5G Core Networks.

It targets exactly this scope:
- Open5GS + UERANSIM working on your Linux laptop
- parse **AMF/SMF/UPF + UE/gNB logs**
- parse **PFCP pcap** via `tshark`
- compare **baseline** vs **trust-aware** provenance detection
- support **two attack scenarios**
- support tamper levels **0%, 10%, 20%, 30%**
- generate plots for **precision, recall, F1, tamper-detection rate**

## Repo layout

- `collector/` log + pcap collection helpers
- `parsers/` real parser skeletons for Open5GS, UERANSIM, PFCP
- `correlation/` event matching + semantic grouping
- `trust/` source trust, event trust, tamper rules
- `graph/` baseline and trust-aware provenance builders
- `detection/` baseline and trust-aware detectors
- `experiments/` scenarios, tamper injection, metrics, suite runner
- `scripts/` entrypoints + plotting
- `configs/` baseline and trust-aware YAML configs

## What you need installed locally

- Python 3.10+
- `tshark`
- `tcpdump`
- Open5GS
- UERANSIM

## Minimum workflow

### 1. Collect logs and pcap from your local testbed

Example:
```bash
mkdir -p data/raw/run_001
sudo journalctl -u open5gs-amfd -o short-iso > data/raw/run_001/amf.log
sudo journalctl -u open5gs-smfd -o short-iso > data/raw/run_001/smf.log
sudo journalctl -u open5gs-upfd -o short-iso > data/raw/run_001/upf.log
```

Run UERANSIM with log capture:
```bash
./build/nr-gnb -c config/open5gs-gnb.yaml 2>&1 | tee data/raw/run_001/gnb.log
./build/nr-ue -c config/open5gs-ue.yaml 2>&1 | tee data/raw/run_001/ue.log
```

Capture PFCP:
```bash
sudo tcpdump -i any udp port 8805 -w data/raw/run_001/pfcp.pcap
```

### 2. Install Python deps

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 3. Parse + detect

Baseline:
```bash
python scripts/run_pipeline.py \
  --input-dir data/raw/run_001 \
  --config configs/baseline.yaml \
  --output-dir outputs/run_001_baseline
```

Trust-aware:
```bash
python scripts/run_pipeline.py \
  --input-dir data/raw/run_001 \
  --config configs/trustaware.yaml \
  --output-dir outputs/run_001_trustaware
```

### 4. Run experiment sweep

```bash
python experiments/run_suite.py \
  --input-dir data/raw/run_001 \
  --results-csv data/results/results.csv
```

### 5. Generate paper plots

```bash
python scripts/plot_precision_recall.py --results data/results/results.csv --output outputs/figures/precision_recall.png
python scripts/plot_f1_vs_tamper.py --results data/results/results.csv --output outputs/figures/f1_vs_tamper.png
python scripts/plot_tamper_detection_rate.py --results data/results/results.csv --output outputs/figures/tamper_detection_rate.png
```

