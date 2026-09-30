import type { EvidenceRecord } from "../lib/types";

export const EVIDENCE_SEED: Omit<EvidenceRecord, "hash" | "prevHash" | "status">[] = [
  {
    index: 1,
    recordType: "Flow metadata",
    ts: "2026-09-30T08:47:12Z",
    ref: "EV-0001",
    content:
      "flow-meta INC-0417 F-0417-01 src=10.2.3.15 dst=10.2.3.0/24 dport=445/tcp pkts=12208 handshakes=3 window=90s",
  },
  {
    index: 2,
    recordType: "DNS query log",
    ts: "2026-09-30T09:05:40Z",
    ref: "EV-0003",
    content:
      "dns-log INC-0417 F-0417-02 domains=61 nxdomain=0.62 entropy=3.62 model_p=0.89 sensor=sensor-01",
  },
  {
    index: 3,
    recordType: "TLS session metadata",
    ts: "2026-09-30T09:31:05Z",
    ref: "EV-0005",
    content:
      "tls-meta INC-0417 F-0417-03 dst=203.0.113.47:443 conns=142 interval=60.1s cv=0.03 payload=212B ja4=t13d1715h2_5b57614c22b0_a1c94e30f7d2",
  },
  {
    index: 4,
    recordType: "Flow metadata",
    ts: "2026-09-30T11:20:44Z",
    ref: "EV-0010",
    content:
      "flow-meta INC-0417 F-0417-05 src=10.2.3.15 dst=198.51.100.88:443 bytes=5153960755 window=2460s ratio=27x",
  },
  {
    index: 5,
    recordType: "Indicator match",
    ts: "2026-09-30T12:01:48Z",
    ref: "EV-0701",
    content:
      "ioc-match bundle=DW-TI-2026-09-30-B indicator=203.0.113.47 type=IPv4 source=Community C2 tracker (sample) base_conf=0.91",
  },
  {
    index: 6,
    recordType: "Retro-hunt result",
    ts: "2026-09-30T12:02:14Z",
    ref: "EV-0702",
    content:
      "retro-hunt RH-2026-09-30-B window=14d flows=48200000 dns=2100000 tls=310000 hits=18 new_leads=1",
  },
  {
    index: 7,
    recordType: "Analyst note",
    ts: "2026-09-30T12:04:11Z",
    ref: "EV-0703",
    content:
      "analyst-note INC-0417 author=Analyst | SOC-1 text=Retro-hunt completed 12:02 UTC. Risk raised to 95. Mitigation package proposed.",
  },
  {
    index: 8,
    recordType: "Artifact approval",
    ts: "2026-09-30T12:09:33Z",
    ref: "EV-0704",
    content:
      "artifact-approval ART-005 incident=INC-0417 type=IOC block list state=Approved approver=Analyst | SOC-1",
  },
  {
    index: 9,
    recordType: "Report digest",
    ts: "2026-09-30T12:15:02Z",
    ref: "EV-0705",
    content:
      "report-digest RPT-INC-0417-20260930 sections=7 evidence_records=9 chain_head=<computed-at-generation>",
  },
];
