from __future__ import annotations

import sys
from pathlib import Path
REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import argparse
import csv
import json
from pathlib import Path
import yaml

from parsers.open5gs_log_parser import parse_open5gs_log
from parsers.ueransim_log_parser import parse_ueransim_log
from parsers.pfcp_parser import pcap_to_tshark_json, parse_pfcp_json
from parsers.normalize import normalize_events
from correlation.matcher import correlate_events
from trust.tamper_rules import detect_inconsistencies, consistency_score_for_group
from trust.source_trust import compute_source_trust
from trust.event_trust import compute_event_trust
from graph.baseline_graph import build_baseline_graph
from graph.trust_graph import build_trust_graph
from detection.baseline_detector import run_baseline_detector
from detection.trustaware_detector import run_trustaware_detector
from experiments.tamper_injector import apply_tampering
from experiments.scenarios import inject_scenario
from experiments.compute_metrics import compute_binary_metrics


def load_config(path: str):
    with open(path, 'r', encoding='utf-8') as f:
        return yaml.safe_load(f)


def parse_all(input_dir: str):
    base = Path(input_dir)
    events = []
    for name, file in [('amf', 'amf.log'), ('smf', 'smf.log'), ('upf', 'upf.log')]:
        p = base / file
        if p.exists():
            events.extend(parse_open5gs_log(str(p), name))
    for name, file in [('gnb', 'gnb.log'), ('ue', 'ue.log')]:
        p = base / file
        if p.exists():
            events.extend(parse_ueransim_log(str(p), name))
    pcap = base / 'pfcp.pcap'
    if pcap.exists():
        pfcp_json = base / 'pfcp.json'
        if not pfcp_json.exists():
            pcap_to_tshark_json(str(pcap), str(pfcp_json))
        events.extend(parse_pfcp_json(str(pfcp_json)))
    return normalize_events(events)


def scenario_ground_truth(scenario: str) -> int:
    return 0 if scenario == 'benign' else 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--input-dir', required=True)
    ap.add_argument('--config', required=True)
    ap.add_argument('--output-dir', required=True)
    ap.add_argument('--scenario', default='benign')
    ap.add_argument('--tamper-level', type=float, default=0.0)
    args = ap.parse_args()

    cfg = load_config(args.config)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    events = parse_all(args.input_dir)
    events = inject_scenario(events, args.scenario)
    events = apply_tampering(events, args.tamper_level)

    correlated = correlate_events(events, cfg['correlation']['time_window_sec'])
    inconsistencies = detect_inconsistencies(correlated)

    trust_enabled = cfg['trust']['enabled']
    if trust_enabled:
        source_trust = compute_source_trust(events, inconsistencies, cfg['trust']['mismatch_penalty'], cfg['trust']['min_source_trust'])
        for group in correlated:
            cscore = consistency_score_for_group(group, inconsistencies)
            group['event_trust'] = compute_event_trust(group, source_trust, cscore, cfg['trust']['consistency_weight'], cfg['trust']['redundancy_weight'])
    else:
        source_trust = {e.source_name: 1.0 for e in events}
        for group in correlated:
            group['event_trust'] = 1.0

    if cfg['mode'] == 'baseline':
        _ = build_baseline_graph(correlated)
        detections = run_baseline_detector(correlated, inconsistencies, cfg['detection']['attack_threshold'])
    else:
        _ = build_trust_graph(correlated)
        detections = run_trustaware_detector(correlated, inconsistencies, cfg['detection']['attack_threshold'], cfg['detection']['suspicious_event_threshold'])

    ground_truth = scenario_ground_truth(args.scenario)
    detected = 1 if len(detections) > 0 else 0

    tp = 1 if ground_truth == 1 and detected == 1 else 0
    fp = 1 if ground_truth == 0 and detected == 1 else 0
    tn = 1 if ground_truth == 0 and detected == 0 else 0
    fn = 1 if ground_truth == 1 and detected == 0 else 0

    metrics = compute_binary_metrics(tp, fp, tn, fn)
    metrics.update({
        'mode': cfg['mode'],
        'scenario': args.scenario,
        'tamper_level': args.tamper_level,
        'tp': tp,
        'fp': fp,
        'tn': tn,
        'fn': fn,
        'tamper_detection_rate': round(min(1.0, len(inconsistencies) / max(1, len(correlated))), 4) if args.tamper_level > 0 else 0.0,
    })

    with open(output_dir / 'events.jsonl', 'w', encoding='utf-8') as f:
        for e in events:
            f.write(json.dumps(e.to_dict()) + '\n')
    with open(output_dir / 'inconsistencies.json', 'w', encoding='utf-8') as f:
        json.dump(inconsistencies, f, indent=2)
    with open(output_dir / 'detections.json', 'w', encoding='utf-8') as f:
        json.dump(detections, f, indent=2)
    with open(output_dir / 'metrics.csv', 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=list(metrics.keys()))
        writer.writeheader()
        writer.writerow(metrics)


if __name__ == '__main__':
    main()
