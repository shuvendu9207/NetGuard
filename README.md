# NetGuard — ML-Powered Intrusion Detection System

## Run NetGuard

```bash
python netguard.py run --pcap test_dpi.pcap
```

Live capture:

```bash
python netguard.py run --interface eth0
```

Train a model:

```bash
python netguard.py train --dataset data/captures.csv
```

Generate dataset:

```bash
python netguard.py run --pcap input.pcap --export-dataset
```

---

## Overview

NetGuard is a Python-based Intrusion Detection System (IDS) that combines Deep Packet Inspection (DPI), machine learning, and behavioral traffic analysis to detect malicious network activity.

The system analyzes packets from live network interfaces or PCAP files and detects attacks such as port scans, brute force attempts, DoS traffic, and anomalous behavior.

```
Traffic → Packet Parser → Feature Extractor
              │
              ├─ ML Detection Engine
              ├─ Behavioral Analysis
              └─ DPI Inspectors (TLS SNI / HTTP)

                    ↓
            Alert + Block + Report
```

---

## Key Features

- Deep Packet Inspection (HTTP / TLS SNI extraction)
- Machine learning-based intrusion detection
- Behavioral anomaly detection
- Port scan and DoS detection
- Rule-based blocking engine
- Real-time alert system
- Automatic dataset generation for training
- Multi-threaded packet processing
- HTML session reports
- Modular architecture for extending detectors

---

## Example Output

```
[14:32:01] TCP 192.168.1.5:54301 → 142.250.185.78:443  SNI=www.youtube.com  → BLOCKED
[14:32:02] ⚠ ALERT HIGH PORT_SCAN src=192.168.1.77 ports=87 conf=0.94
```

---

## Project Structure

```
netguard/
│
├── netguard.py              # Entry point
├── capture/                 # Packet capture (live / PCAP)
├── parser/                  # Packet parsing
├── extractor/               # Feature extraction
├── inspector/               # DPI inspectors (TLS / HTTP)
├── ml/                      # ML detection and training
├── behavior/                # Behavioral analysis engine
├── rules/                   # Rule-based blocking
├── alerts/                  # Alert generation
├── reporter/                # Traffic reports
├── dataset/                 # Dataset exporter
├── config/                  # Rules and configuration
└── tests/                   # Unit tests
```

---

## Installation

**Requirements:**
- Python 3.10+
- Windows / Linux / macOS
- Npcap (Windows only, for live capture)

```bash
pip install -r requirements.txt
```

---

## Reports & Alerts

NetGuard generates:

- Terminal alerts during capture
- `alerts/alerts.log` — text alert log
- `alerts/alerts.json` — structured alerts
- `data/captures.csv` — training dataset
- `reports/report_<timestamp>.html` — session report

---

## Extending NetGuard

You can easily extend NetGuard by:

- Adding new ML models in `ml/trainer.py`
- Adding behavioral rules in `behavior/behavioral_engine.py`
- Adding DPI inspectors in `inspector/`
- Updating block rules in `config/rules.yaml`

---

## Summary

NetGuard demonstrates how modern IDS systems combine deep packet inspection, machine learning, and behavioral analysis to detect both known and unknown attacks.