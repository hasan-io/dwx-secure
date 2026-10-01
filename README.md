<div align="center">

<img src="https://img.shields.io/badge/DiodeWatch-Passive%20NDR-1F3A5F?style=for-the-badge&logo=shield&logoColor=white" alt="DiodeWatch" />

# DiodeWatch

### AI-Based Passive Network Detection & Response for Unidirectional Monitoring Environments

[![SIH 2026](https://img.shields.io/badge/Smart%20India%20Hackathon-2026-FF6B00?style=flat-square)](https://sih.gov.in)
[![PS](https://img.shields.io/badge/Problem%20Statement-26145-1F3A5F?style=flat-square)](https://sih.gov.in)
[![Theme](https://img.shields.io/badge/Theme-Blockchain%20%26%20Cybersecurity-2F5D9E?style=flat-square)](https://sih.gov.in)
[![Organization](https://img.shields.io/badge/Organization-NTRO-A32020?style=flat-square)](https://sih.gov.in)
[![Stack](https://img.shields.io/badge/Stack-React%20%7C%20Python%20%7C%20Zeek%20%7C%20LightGBM-3E6B57?style=flat-square)](https://sih.gov.in)
[![License](https://img.shields.io/badge/License-MIT-B7791F?style=flat-square)](LICENSE)

<br/>

> **"The witness that sees everything and touches nothing."**
>
> DiodeWatch passively monitors a read-only copy of network traffic, detects six classes of cyber attack, correlates evidence into one explained incident per host, and hands analysts a ready-to-approve mitigation and forensic package — without ever sending a single packet back to the network it monitors.

<br/>

[Live Demo](#demo) · [Architecture](#architecture) · [Threat Detection](#threat-detection) · [Getting Started](#getting-started) · [Documentation](#documentation)

<br/>

---

</div>

## The Problem

High-security networks — national infrastructure, defence installations, government enclaves — use **hardware data diodes** or network taps to mirror traffic into isolated monitoring systems. The monitoring side is strictly **read-only**:

- ❌ No return path to the production network
- ❌ No active probing of suspicious hosts
- ❌ No live threat intelligence API lookups
- ❌ No inline blocking or quarantine
- ❌ No TLS/QUIC decryption
- ❌ Cannot complete TCP handshakes

Every major NDR and threat detection platform on the market assumes at least one of these capabilities. **None of them is built for this constraint from the ground up.**

DiodeWatch treats the constraint as a design principle, not a limitation to work around.

---

## What DiodeWatch Does

```
Mirrored Traffic (Read-Only)
        │
        ▼
┌──────────────────────────────────────────────────────────┐
│                   MONITORING ENCLAVE                     │
│                                                          │
│  [Receive-Only NIC]  →  [Zeek]  →  [Feature Engine]    │
│                                          │               │
│                              ┌───────────┘               │
│                              ▼                           │
│                    [Detection Engine]                    │
│                    DDoS · Beaconing · DGA               │
│                    Encrypted · Scan · Exfil             │
│                              │                           │
│                    [Threat Intel Store]                  │
│                    (Offline IOC Bundles)                 │
│                              │                           │
│                    [Incident & Risk Engine]              │
│                    Kill-Chain · 0-100 Score             │
│                              │                           │
│          ┌───────────────────┼───────────────────┐       │
│          ▼                   ▼                   ▼       │
│    [Alerts JSON]     [Mitigation Artifacts]  [Reports]  │
│                                                          │
└──────────────────────────────────────────────────────────┘
        │
        ▼
Analyst → Approve → Export → [Out-of-band Enforcement]
                              (Outside DiodeWatch)
```

---

## Core Capabilities

| Capability | Description |
|---|---|
| 🔍 **Passive Ingestion** | Receive-only NIC, no IP, TX=0, egress DROP — proven one-way proof |
| 🎯 **6 Threat Detectors** | DDoS, C2 Beaconing, DGA/DNS Tunnelling, Encrypted Malware, Recon, Exfiltration |
| 🧠 **AI/ML Detection** | LightGBM for DGA and encrypted sessions; statistics where ML adds no value |
| 🔗 **Incident Correlation** | Findings on the same host merge into one kill-chain-mapped incident |
| 📊 **Explainable Risk Score** | 0–100 score with a "Why this score?" breakdown for every component |
| 🕵️ **Offline Threat Intel** | Signed IOC bundles, age-based decay, no live lookups |
| 🔁 **Retro-Hunt** | New intel bundle triggers a scan of stored history — finds earlier compromise |
| 📋 **Mitigation Artifacts** | nftables rules, RPZ entries, RTBH suggestions — Proposed → Approved → Exported |
| 🔒 **Hash-Chained Forensics** | SHA-256 chained evidence log with tamper detection and verification |
| 📡 **Direction-Aware Detection** | Every detector has a one-direction fallback with honest confidence degradation |

---

## Threat Detection

### Six Threat Classes

<table>
<tr>
<td>

**1. DDoS**
- SYN flood, UDP reflection, amplification
- Source-address entropy, SYN:ACK ratio
- EWMA/CUSUM statistical baselines
- Method: **Rules + Statistics**

</td>
<td>

**2. C2 Beaconing**
- Periodic connections to external host
- Autocorrelation, FFT periodicity score
- IAT jitter and payload regularity
- Method: **Statistical**

</td>
</tr>
<tr>
<td>

**3. DGA / DNS Tunnelling**
- Algorithmically generated domains
- Char n-gram + lexical features
- Subdomain entropy, NXDOMAIN rate
- Method: **ML (LightGBM) + Hybrid**

</td>
<td>

**4. Encrypted Malware**
- Suspicious TLS without decryption
- JA4/JA3S, ALPN, cert traits
- Early-packet size + timing sequences
- Method: **ML (LightGBM)**

</td>
</tr>
<tr>
<td>

**5. Reconnaissance**
- Horizontal and vertical port scans
- Distinct ports/hosts per source per window
- Sequential patterns, low packets per flow
- Method: **Rules + Statistics**

</td>
<td>

**6. Data Exfiltration**
- Unusual outbound volume or asymmetry
- Per-host baseline robust z-score
- Rare destination, long-lived flows
- Method: **Statistical + Isolation Forest**

</td>
</tr>
</table>

### Where AI/ML is Used

```
DDoS          ──── Rules/Statistics  (rates and ratios are deterministic)
C2 Beaconing  ──── Statistical       (periodicity scoring)
DGA           ──── ML (LightGBM)     (lexical features, char n-grams)
DNS Tunnelling──── Hybrid            (rules for obvious, ML for subtle)
Encrypted     ──── ML (LightGBM)     (JA4 + early-packet sequences)
Exfiltration  ──── Hybrid            (baseline + Isolation Forest)
Anomaly       ──── Unsupervised      (per-host baseline, corroboration only)
```

> ML is used only where statistics genuinely cannot match the complexity.
> For all other classes, statistical methods are more robust and explainable.

---

## Architecture

```
PRODUCTION NETWORK
       │
       │  [Network TAP / SPAN / Hardware Data Diode]
       │  ◄──────────────────────────────────── NO RETURN PATH
       ▼
┌─────────────────────────────────────────────────────────────────┐
│                    MONITORING ENCLAVE                           │
│                                                                 │
│  ┌──────────────────┐    ┌───────────────────────────────────┐  │
│  │   SENSOR LAYER   │    │         ANALYSIS LAYER            │  │
│  │                  │    │                                   │  │
│  │  Receive-Only    │───▶│  Zeek  ──▶  Feature Engine       │  │
│  │  NIC (eth1)      │    │             (windowed, per-entity │  │
│  │  IP: None        │    │              with direction tags) │  │
│  │  TX: 0 packets   │    │                    │              │  │
│  │  Egress: DROP    │    └────────────────────│──────────────┘  │
│  └──────────────────┘                         │                 │
│                                               ▼                 │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │                   DETECTION ENGINE                         │ │
│  │                                                            │ │
│  │   DDoS ──── Beaconing ──── DGA ──── Encrypted ──── Scan  │ │
│  │                     Exfiltration ──── Anomaly Baseline    │ │
│  │                            │                              │ │
│  │              [Threat Intel Store (Offline)]               │ │
│  │              IP · Domain · JA4/JA3 · Cert Hash           │ │
│  │              Age Decay · Retro-Hunt on Import             │ │
│  └────────────────────────────────┬───────────────────────── ┘ │
│                                   │                             │
│  ┌────────────────────────────────▼───────────────────────────┐ │
│  │              INCIDENT & RISK ENGINE                        │ │
│  │                                                            │ │
│  │   Kill-Chain Mapping · 0-100 Risk Score                   │ │
│  │   Multi-signal Correlation · Decomposed Explanation       │ │
│  └────────────┬──────────────────────────┬────────────────── ┘ │
│               │                          │                      │
│  ┌────────────▼──────┐   ┌──────────────▼─────────────────┐    │
│  │  STRUCTURED ALERT │   │  RESPONSE & FORENSICS          │    │
│  │  JSON (ECS/STIX)  │   │  Mitigation Artifacts          │    │
│  └───────────────────┘   │  Hash-Chained Reports          │    │
│                           └────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
                                   │
                    ───────────────┘
                    │   ANALYST APPROVAL (Out-of-band)
                    ▼
            Change Management → Enforcement
            (Outside DiodeWatch — no return path)
```

---

## Tech Stack

```
Layer               Technology
─────────────────────────────────────────────────────────
Traffic Extraction  Zeek (conn, dns, ssl, x509 logs)
Feature Engineering Python · pandas · scikit-learn · river
ML Models           LightGBM · SHAP (explainability)
Anomaly Detection   Isolation Forest · HBOS
Streaming           Redis Streams
Storage             PostgreSQL · TimescaleDB
Backend API         FastAPI (Python)
Dashboard           React · TypeScript · Tailwind CSS · Recharts
Cryptography        SHA-256 hash chain · GPG-signed IOC bundles
Deployment          Docker Compose (fully offline, single server)
```

**No cloud dependencies. No vendor APIs. No licensing cost.**

---

## Dashboard

Six views covering the full workflow:

```
┌─────────────────────────────────────────────────────────────┐
│  RECEIVE-ONLY | TX 0 pkts | Egress: DROP    sensor-01  UTC │
├──────────┬──────────────────────────────────────────────────┤
│          │                                                  │
│ Overview │  Active Incidents · Severity Distribution        │
│          │  Traffic Summary · One-Way Integrity Badge       │
│──────────│──────────────────────────────────────────────────│
│   Live   │  Streaming Flow Feed · Detection Timeline        │
│ Monitor  │  Threat Category Filters · Direction Toggle      │
│──────────│──────────────────────────────────────────────────│
│Incidents │  [List]   [Investigation View]                   │
│          │  Kill-Chain · Evidence · TI Matches              │
│          │  Risk Breakdown · "Why this score?"              │
│──────────│──────────────────────────────────────────────────│
│ Threat   │  IOC Database · Matches · Bundle Status          │
│  Intel   │  Import Bundle → Retro-Hunt Results              │
│──────────│──────────────────────────────────────────────────│
│Response  │  Mitigation Artifacts (Proposed→Approved→Exported│
│& Reports │  Forensic Report · Hash-Chain Verification       │
│──────────│──────────────────────────────────────────────────│
│Evaluation│  Per-class Precision/Recall · Time-to-Detect     │
│ & Trust  │  Bi-directional vs One-Direction Comparison      │
└──────────┴──────────────────────────────────────────────────┘
```

---

## Demo Scenario

The prototype includes a built-in guided demo walking through a complete attack lifecycle:

### INC-0417 — Multi-Stage Compromise (Host: 10.2.3.15, WKS-FIN-015)

```
08:47  Reconnaissance      Port scan: 254 hosts on 445/tcp in 90s
         │                 Risk: 34 (Low)
         ▼
09:05  DGA Activity        61 DGA domains, 62% NXDOMAIN, entropy 3.62
         │                 Risk: 52 (Medium)
         ▼
09:31  C2 Beaconing        203.0.113.47:443 every 60.1s ± 2s, 142 connections
         │                 Risk: 71 (High)
         ▼
09:52  Encrypted Malware   JA4 match, self-signed cert, early-packet cluster
         │                 Risk: 79
         ▼
11:20  Data Exfiltration   4.8 GB outbound, 27× host baseline, new destination
         │                 Risk: 86 (High)
         ▼
       IMPORT IOC BUNDLE   Retro-hunt finds C2 contact from 2 days earlier
         │                 Risk: 86 → 95 (CRITICAL)
         ▼
       RESPONSE PACKAGE    Mitigation artifacts generated → Approved → Exported
         │
         ▼
       FORENSIC REPORT     Hash-chain verified → Tamper simulation → Chain broken
```

### INC-0418 — DDoS Attack (Victim: 10.0.5.20, WEB-PUB-02)

```
UDP Reflection: 412 reflectors · ports 53/123/11211 · ~3.1 Gbps
SYN Flood: SYN:ACK ratio 14:1 · high source-address entropy
Risk: 82 (High)
Recommendation: Upstream rate-limiting (per-source blocking ineffective — spoofed/reflected sources)
```

---

## What DiodeWatch Does NOT Claim

This is important. We are technically honest about the system's boundaries:

- ❌ Does not block, reset, or quarantine anything on the production network
- ❌ Does not decrypt TLS or QUIC payloads
- ❌ Does not attribute malware families beyond fingerprint IOC matches
- ❌ "Exported" does not mean "Enforced" — enforcement is out-of-band
- ❌ No live threat intelligence lookups
- ❌ No active probing of any host
- ❌ No production-scale throughput claims
- ❌ No hardware-level data diode certification

---

## Getting Started

### Prerequisites

```bash
Docker + Docker Compose
Git
A receive-only NIC (or use PCAP replay for lab/demo)
```

### Quick Start

```bash
# Clone the repository
git clone https://github.com/your-team/diodewatch.git
cd diodewatch

# Start all services
docker compose up -d

# Dashboard available at
http://localhost:3000

# Run demo scenario (PCAP replay)
./scripts/replay-demo.sh
```

### PCAP Replay (Lab Demo)

```bash
# Replay the included demo scenario
tcpreplay -i eth1 --pps=1000 scenarios/inc-0417-multistage.pcap

# Or use the built-in scenario launcher
./scripts/launch-scenario.sh inc-0417
./scripts/launch-scenario.sh inc-0418-ddos
```

---

## Project Structure

```
diodewatch/
│
├── sensor/                  # Zeek scripts and config
│   ├── zeek-scripts/
│   └── capture-config/
│
├── engine/                  # Python detection backend
│   ├── detectors/
│   │   ├── ddos.py
│   │   ├── beaconing.py
│   │   ├── dga.py
│   │   ├── encrypted.py
│   │   ├── recon.py
│   │   └── exfiltration.py
│   ├── ml/                  # LightGBM models + SHAP
│   ├── correlation/         # Incident + risk engine
│   ├── intel/               # IOC store + retro-hunt
│   └── api/                 # FastAPI backend
│
├── dashboard/               # React + TypeScript frontend
│   ├── src/
│   │   ├── views/           # Overview, Monitor, Incidents, TI, Response, Eval
│   │   ├── components/
│   │   └── data/            # Seeded demo data (TypeScript)
│   └── public/
│
├── scenarios/               # Labelled PCAP suite for demo + benchmark
├── ioc-bundles/             # Sample signed IOC bundles
├── scripts/                 # Replay, setup, benchmark scripts
└── docker-compose.yml
```

---

## Differentiators

### 1. Direction-Aware Detection
Every detector has a bidirectional mode and a one-direction fallback, selected automatically based on which directions were observed. Detection does not silently fail — confidence degrades measurably and visibly.

### 2. Evidence-Backed Incidents with Explainable Risk
Hundreds of raw findings become a handful of cases. Every risk point is traceable to a specific signal. The "Why this score?" panel shows each contribution.

### 3. Diode-Native Intelligence with Retro-Hunt
All IOC matching is local and offline. Importing a new signed bundle triggers a retroactive scan of stored metadata — surfacing compromises that predate the first behavioural detection.

### 4. Verifiable Forensic Package
SHA-256 hash-chained evidence log. Altering any record makes verification fail at that point. Mitigation artifacts carry approval states and blast-radius notes.

---

## Evaluation

| Threat Class | Precision | Recall | F1 | Bi-dir | One-dir |
|---|---|---|---|---|---|
| DDoS | 0.97 | 0.95 | 0.96 | 0.95 | 0.92 |
| C2 Beaconing | 0.95 | 0.93 | 0.94 | 0.94 | 0.90 |
| DGA Detection | 0.94 | 0.91 | 0.92 | 0.93 | 0.88 |
| Encrypted Malware | 0.89 | 0.86 | 0.87 | 0.88 | 0.84 |
| Reconnaissance | 0.98 | 0.96 | 0.97 | 0.97 | 0.91 |
| Data Exfiltration | 0.91 | 0.88 | 0.89 | 0.90 | 0.82 |

> Illustrative target values. Final figures come from the labelled scenario benchmark on unseen traffic.

---

## Research Foundation

| Paper | Used For |
|---|---|
| Paxson, V. (1999). "Bro: A System for Detecting Network Intruders in Real-Time." *Computer Networks.* | Zeek foundation |
| Antonakakis, M. et al. (2012). "From Throw-Away Traffic to Bots: Detecting DGA-Based Malware." *USENIX Security.* | DGA detection |
| Anderson, B. & McGrew, D. (2017). "Machine Learning for Encrypted Malware Traffic Classification." *ACM KDD.* | Encrypted session classifier |
| Ke, G. et al. (2017). "LightGBM: A Highly Efficient Gradient Boosting Decision Tree." *NeurIPS.* | ML model |
| Lundberg, S. & Lee, S.I. (2017). "A Unified Approach to Interpreting Model Predictions." *NeurIPS.* | SHAP explainability |
| Althouse, J. (2023). "JA4+: A Suite of Network Fingerprinting Standards." *FoxIO Research.* | TLS fingerprinting |

---

## Team

Built for **Smart India Hackathon 2026** · Problem Statement 26145 · NTRO · Blockchain & Cybersecurity Theme

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

<div align="center">

**DiodeWatch** · SIH 2026 · PS 26145 · NTRO

*Passive. Evidence-backed. Diode-safe.*

</div>
