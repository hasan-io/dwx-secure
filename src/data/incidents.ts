import type { Incident, DnsRecord, TlsRecord, FlowRecord, Finding } from "../lib/types";
import { mulberry32 } from "../lib/utils";

const D = "2026-09-30";

/* ------------------------------------------------------------------ *
 * Deterministic helpers for the secondary incidents
 * ------------------------------------------------------------------ */

function dnsList(seed: number, base: string[], count: number): DnsRecord[] {
  const r = mulberry32(seed);
  const out: DnsRecord[] = [];
  for (let i = 0; i < count; i++) {
    const dom = base[i % base.length];
    const ent = Number((2.1 + r() * 2.1).toFixed(2));
    const nx = r() > 0.45;
    out.push({
      ts: `${D}T${String(8 + Math.floor(i / 8)).padStart(2, "0")}:${String(
        (i * 7) % 60
      ).padStart(2, "0")}:${String((i * 13) % 60).padStart(2, "0")}Z`,
      query: i % 5 === 2 ? `node-${100 + i}.${dom}` : dom,
      type: ["A", "A", "A", "TXT", "AAAA", "CNAME"][i % 6],
      response: nx ? "NXDOMAIN" : `192.0.2.${10 + (i % 200)}`,
      entropy: ent,
      nxdomain: nx,
      length: dom.length,
    });
  }
  return out;
}

function tlsList(seed: number, dst: string, ja4: string, sni: string, count: number): TlsRecord[] {
  const r = mulberry32(seed);
  const out: TlsRecord[] = [];
  for (let i = 0; i < count; i++) {
    out.push({
      ts: `${D}T${String(9 + Math.floor(i / 6)).padStart(2, "0")}:${String(
        (i * 11) % 60
      ).padStart(2, "0")}:${String((i * 29) % 60).padStart(2, "0")}Z`,
      src: "10.2.3.15",
      dst,
      sni: i % 3 === 0 ? sni : "(absent)",
      ja4,
      ja4s: `t130200_9e8a4c1d2f7b_5c3a91b7e204`,
      alpn: "http/1.1",
      certSubject: i % 3 === 0 ? sni : "CN=localhost",
      certIssuer: i % 3 === 0 ? "CN=localhost" : "Let's Encrypt R11 (synthetic)",
      certValidityDays: 3650,
      selfSigned: true,
      epsScore: Number((0.62 + r() * 0.25).toFixed(2)),
      bytes: 180 + Math.floor(r() * 90),
    });
  }
  return out;
}

function flowList(
  seed: number,
  pairs: [string, number, string, number][],
  count: number,
  tagsPool: string[]
): FlowRecord[] {
  const r = mulberry32(seed);
  const out: FlowRecord[] = [];
  for (let i = 0; i < count; i++) {
    const [src, sp, dst, dp] = pairs[i % pairs.length];
    const dir = r() > 0.35 ? "client-to-server" : "bidirectional";
    out.push({
      ts: `${D}T${String(8 + Math.floor(i / 5)).padStart(2, "0")}:${String(
        (i * 9) % 60
      ).padStart(2, "0")}:${String((i * 17) % 60).padStart(2, "0")}Z`,
      src,
      srcPort: sp,
      dst,
      dstPort: dp,
      proto: dp === 53 ? "UDP" : dp === 443 ? "TCP" : "TCP",
      packets: 4 + Math.floor(r() * 240),
      bytes: 240 + Math.floor(r() * 24000),
      direction: dir,
      durationS: Number((r() * 62).toFixed(1)),
      tags: [tagsPool[i % tagsPool.length]],
    });
  }
  return out;
}

function f(
  id: string,
  ts: string,
  category: Finding["category"],
  title: string,
  detail: string,
  detector: string,
  direction: Finding["direction"],
  confidence: number,
  risk: number,
  features: Finding["features"],
  chart: Finding["chart"],
  refs: string[]
): Finding {
  const sev = risk >= 90 ? "Critical" : risk >= 70 ? "High" : risk >= 50 ? "Medium" : "Low";
  return {
    id,
    ts,
    category,
    title,
    detail,
    detector,
    direction,
    confidence,
    risk,
    severity: sev as Finding["severity"],
    features,
    chart,
    evidenceRefs: refs,
  };
}

/* ------------------------------------------------------------------ *
 * INC-0417 — hero incident
 * ------------------------------------------------------------------ */

const DGA_DOMAINS = [
  "qx4v8mzt2kd7p1.com",
  "h7nb3wry6sq9zc.net",
  "5jfd8kqp2xvtnl.org",
  "z9wt3cbn6mryqh.info",
  "2kxv7dpl8nzwmq.biz",
  "m6ryq9ht3zvpwx.com",
  "t8nzc4wdl6kqxv.net",
  "4bvh2jms7qplrd.org",
  "r3qzk9wxc6mtnv.info",
  "6ydph5nxb8tqzj.com",
  "w2mkv7bqz4xtrn.net",
  "8sltc3pjq9nwvz.org",
];

const heroFindings: Finding[] = [
  f(
    "F-0417-01",
    `${D}T08:47:12Z`,
    "Reconnaissance",
    "Horizontal scan on 445/tcp across /24",
    "Sequential address sweep of 10.2.3.0/24 on 445/tcp from 10.2.3.15. 254 hosts probed in 90 s with 12,208 SYN packets and only 3 completed handshakes, consistent with an automated scanner rather than user activity.",
    "rule SIG-RECON-HSCAN-445 v2.4",
    "client-to-server",
    0.97,
    34,
    [
      { feature: "Distinct hosts contacted in /24", value: "254", threshold: "> 50 in 300 s", baseline: "12 (30-day median)", verdict: "above" },
      { feature: "Sweep duration", value: "90 s", threshold: "< 180 s", baseline: "n/a", verdict: "above" },
      { feature: "SYN packets", value: "12,208", threshold: "> 2,000", baseline: "180/day", verdict: "above" },
      { feature: "Completed handshakes", value: "3 (0.02%)", threshold: "< 5%", baseline: "96%", verdict: "below" },
      { feature: "Distinct destination ports", value: "1 (445/tcp)", threshold: "1–3", baseline: "14", verdict: "match" },
      { feature: "Sequential address order", value: "monotonic /24 walk", threshold: "monotonic", baseline: "random", verdict: "match" },
    ],
    "packet",
    ["EV-0001", "EV-0002"]
  ),
  f(
    "F-0417-02",
    `${D}T09:05:40Z`,
    "DGA/DNS Tunnelling",
    "Algorithmically generated domain activity",
    "61 algorithmically generated domains queried in a 22-minute window, 62% returning NXDOMAIN. Mean label entropy 3.62 and classifier probability 0.89 indicate domain generation algorithm usage, a common pre-C2 resolution step.",
    "model dga-lstm-v3.1 + rule SIG-DNS-DGA-ENTROPY",
    "client-to-server",
    0.89,
    52,
    [
      { feature: "Distinct domains queried (10 min)", value: "61", threshold: "≥ 25", baseline: "9", verdict: "above" },
      { feature: "NXDOMAIN ratio", value: "62%", threshold: "> 55%", baseline: "6%", verdict: "above" },
      { feature: "Mean label entropy (bits)", value: "3.62", threshold: "> 3.40", baseline: "2.71", verdict: "above" },
      { feature: "Mean label length", value: "11.4 chars", threshold: "> 10", baseline: "8.2 chars", verdict: "above" },
      { feature: "Domains absent from top 1M list", value: "61 / 61", threshold: "> 80%", baseline: "22%", verdict: "above" },
      { feature: "Model probability", value: "0.89", threshold: "≥ 0.75", baseline: "0.06", verdict: "above" },
      { feature: "Distinct parent zones", value: "4 (.com .net .org .info)", threshold: "≥ 3", baseline: "1", verdict: "above" },
    ],
    "entropy",
    ["EV-0003", "EV-0004"]
  ),
  f(
    "F-0417-03",
    `${D}T09:31:05Z`,
    "C2 Beaconing",
    "Periodic beaconing to 203.0.113.47:443",
    "142 connections to 203.0.113.47:443 over 2 h 22 m at a mean interval of 60.1 s with coefficient of variation 0.03, far below the 0.10 jitter threshold. Payload size held at 212 ± 6 bytes against a host baseline of 1.4 KB ± 2.1 KB.",
    "model beacon-periodicity-v2.7 (interval CV + payload stability)",
    "bidirectional",
    0.88,
    71,
    [
      { feature: "Beacon interval (mean)", value: "60.1 s", threshold: "30–600 s", baseline: "n/a", verdict: "match" },
      { feature: "Interval coefficient of variation", value: "0.03", threshold: "< 0.10", baseline: "0.41", verdict: "below" },
      { feature: "Payload size (mean ± sd)", value: "212 ± 6 B", threshold: "sd < 15% of mean", baseline: "1.4 KB ± 2.1 KB", verdict: "above" },
      { feature: "Periodicity score", value: "0.93", threshold: "≥ 0.80", baseline: "0.22", verdict: "above" },
      { feature: "Connections observed", value: "142 by 11:53 UTC", threshold: "≥ 20", baseline: "3/day", verdict: "above" },
      { feature: "DNS TTL on resolved name", value: "60 s (flat)", threshold: "< 300 s", baseline: "3,600 s", verdict: "below" },
      { feature: "Jitter entropy", value: "0.11", threshold: "< 0.25", baseline: "0.68", verdict: "below" },
    ],
    "iat",
    ["EV-0005", "EV-0006", "EV-0007"]
  ),
  f(
    "F-0417-04",
    `${D}T09:52:19Z`,
    "Encrypted Malware",
    "Suspicious encrypted session to 203.0.113.47",
    "TLS session with a self-signed certificate of 3,650-day validity, ALPN http/1.1 and a single cipher suite. The early-packet-sequence classifier scores the session at p=0.83; the JA4 fingerprint matches a loader family entry in the local malware fingerprint database.",
    "model tls-eps-v1.9 + JA4 exact match (local bundle)",
    "bidirectional",
    0.83,
    79,
    [
      { feature: "Certificate validity", value: "3,650 days", threshold: "> 825 days", baseline: "90 days", verdict: "above" },
      { feature: "Certificate issuer", value: "self-signed (CN=localhost)", threshold: "self-signed", baseline: "public CA", verdict: "match" },
      { feature: "ALPN", value: "http/1.1", threshold: "absent or http/1.1", baseline: "h2", verdict: "match" },
      { feature: "JA4 client fingerprint", value: "t13d1715h2_5b57614c22b0_a1c94e30f7d2", threshold: "exact match", baseline: "no match", verdict: "match" },
      { feature: "Cipher suites offered", value: "1", threshold: "≤ 2", baseline: "9", verdict: "below" },
      { feature: "SNI present", value: "no (IP literal)", threshold: "absent", baseline: "present", verdict: "match" },
      { feature: "Early-packet-sequence classifier", value: "p = 0.83", threshold: "≥ 0.70", baseline: "0.09", verdict: "above" },
    ],
    "packet",
    ["EV-0008", "EV-0009"]
  ),
  f(
    "F-0417-05",
    `${D}T11:20:44Z`,
    "Exfiltration",
    "Sustained outbound transfer to 198.51.100.88:443",
    "4.8 GB uploaded to 198.51.100.88:443 in 41 minutes across 38 flows, 27× the host baseline. The destination had not been observed on this network before. Upload:download ratio 312:1 with no user-driven browsing pattern in the same window.",
    "model exfil-volume-v2.2 (baseline ratio + destination novelty)",
    "client-to-server",
    0.86,
    86,
    [
      { feature: "Outbound volume (41 min)", value: "4.8 GB", threshold: "> 500 MB", baseline: "180 MB/day", verdict: "above" },
      { feature: "Ratio to host baseline", value: "27×", threshold: "> 5×", baseline: "1.0×", verdict: "above" },
      { feature: "Upload : download ratio", value: "312 : 1", threshold: "> 20 : 1", baseline: "1 : 4", verdict: "above" },
      { feature: "Destination first seen", value: "yes (198.51.100.88)", threshold: "first seen", baseline: "no", verdict: "match" },
      { feature: "Distinct flows in window", value: "38", threshold: "≥ 5", baseline: "2", verdict: "above" },
      { feature: "Sustained throughput", value: "19.6 Mbps equivalent", threshold: "> 5 Mbps", baseline: "0.4 Mbps", verdict: "above" },
      { feature: "Concurrent user sessions", value: "0", threshold: "0 expected", baseline: "1–2", verdict: "match" },
    ],
    "volume",
    ["EV-0010", "EV-0011", "EV-0012"]
  ),
];

const heroDns: DnsRecord[] = DGA_DOMAINS.map((dom, i) => ({
  ts: `${D}T09:${String(5 + Math.floor(i / 4)).padStart(2, "0")}:${String((i * 11) % 60).padStart(
    2,
    "0"
  )}Z`,
  query: dom,
  type: i % 4 === 3 ? "TXT" : "A",
  response: i % 3 === 0 ? "NXDOMAIN" : `203.0.113.${20 + (i % 20)}`,
  entropy: Number((3.1 + ((i * 37) % 60) / 100).toFixed(2)),
  nxdomain: i % 3 === 0,
  length: dom.length,
}));

const heroTls: TlsRecord[] = [
  {
    ts: `${D}T09:52:19Z`,
    src: "10.2.3.15",
    dst: "203.0.113.47",
    sni: "(absent)",
    ja4: "t13d1715h2_5b57614c22b0_a1c94e30f7d2",
    ja4s: "t130200_9e8a4c1d2f7b_5c3a91b7e204",
    alpn: "http/1.1",
    certSubject: "CN=localhost",
    certIssuer: "CN=localhost (self-signed)",
    certValidityDays: 3650,
    selfSigned: true,
    epsScore: 0.83,
    bytes: 212,
  },
  {
    ts: `${D}T09:53:21Z`,
    src: "10.2.3.15",
    dst: "203.0.113.47",
    sni: "(absent)",
    ja4: "t13d1715h2_5b57614c22b0_a1c94e30f7d2",
    ja4s: "t130200_9e8a4c1d2f7b_5c3a91b7e204",
    alpn: "http/1.1",
    certSubject: "CN=localhost",
    certIssuer: "CN=localhost (self-signed)",
    certValidityDays: 3650,
    selfSigned: true,
    epsScore: 0.81,
    bytes: 209,
  },
  {
    ts: `${D}T10:14:02Z`,
    src: "10.2.3.15",
    dst: "203.0.113.47",
    sni: "(absent)",
    ja4: "t13d1715h2_5b57614c22b0_a1c94e30f7d2",
    ja4s: "t130200_9e8a4c1d2f7b_5c3a91b7e204",
    alpn: "http/1.1",
    certSubject: "CN=localhost",
    certIssuer: "CN=localhost (self-signed)",
    certValidityDays: 3650,
    selfSigned: true,
    epsScore: 0.79,
    bytes: 218,
  },
  {
    ts: `${D}T11:20:44Z`,
    src: "10.2.3.15",
    dst: "198.51.100.88",
    sni: "cdn-metrics.example.invalid",
    ja4: "t13d2015h2_5b57614c22b0_a1c94e30f7d2",
    ja4s: "t130200_9e8a4c1d2f7b_5c3a91b7e204",
    alpn: "http/1.1",
    certSubject: "CN=cdn-metrics.example.invalid",
    certIssuer: "CN=cdn-metrics.example.invalid (self-signed)",
    certValidityDays: 730,
    selfSigned: true,
    epsScore: 0.74,
    bytes: 1418,
  },
  {
    ts: `${D}T11:24:10Z`,
    src: "10.2.3.15",
    dst: "198.51.100.88",
    sni: "cdn-metrics.example.invalid",
    ja4: "t13d2015h2_5b57614c22b0_a1c94e30f7d2",
    ja4s: "t130200_9e8a4c1d2f7b_5c3a91b7e204",
    alpn: "h2",
    certSubject: "CN=cdn-metrics.example.invalid",
    certIssuer: "CN=cdn-metrics.example.invalid (self-signed)",
    certValidityDays: 730,
    selfSigned: true,
    epsScore: 0.71,
    bytes: 1462,
  },
];

const heroFlows: FlowRecord[] = [
  ...flowList(
    4171,
    [
      ["10.2.3.15", 49712, "203.0.113.47", 443],
      ["203.0.113.47", 443, "10.2.3.15", 49712],
      ["10.2.3.15", 49880, "198.51.100.88", 443],
    ],
    16,
    ["beacon", "c2", "exfil-candidate", "tls"]
  ),
];

const INC_0417: Incident = {
  id: "INC-0417",
  entity: "10.2.3.15",
  hostname: "WKS-FIN-015",
  title: "Multi-stage compromise of finance workstation",
  summary:
    "Five correlated findings on a single host progress from internal reconnaissance through command-and-control to a sustained outbound transfer. Risk 86 (High); a retro-hunt against the 2026-09-30 threat-intel bundle adds a historical match and raises risk to 95 (Critical).",
  category: "Exfiltration",
  severity: "High",
  risk: 86,
  baseRisk: 86,
  status: "Open",
  confidence: 0.88,
  firstSeen: `${D}T08:47:12Z`,
  lastSeen: `${D}T11:53:10Z`,
  killChain: [
    {
      stage: "Reconnaissance",
      ts: `${D}T08:47:12Z`,
      detail: "Horizontal scan of 10.2.3.0/24 on 445/tcp, 254 hosts in 90 s.",
    },
    {
      stage: "Command & Control",
      ts: `${D}T09:31:05Z`,
      detail:
        "DGA resolution from 09:05 followed by 142 periodic beacons to 203.0.113.47:443 (CV 0.03).",
    },
    {
      stage: "Exfiltration",
      ts: `${D}T11:20:44Z`,
      detail: "4.8 GB outbound to 198.51.100.88:443 in 41 minutes, 27× host baseline.",
    },
  ],
  findings: heroFindings,
  riskHistory: [
    { ts: `${D}T08:47:12Z`, risk: 34, label: "Horizontal scan 445/tcp" },
    { ts: `${D}T09:05:40Z`, risk: 52, label: "DGA domain activity" },
    { ts: `${D}T09:31:05Z`, risk: 71, label: "C2 beaconing to 203.0.113.47" },
    { ts: `${D}T09:52:19Z`, risk: 79, label: "Suspicious TLS session" },
    { ts: `${D}T11:20:44Z`, risk: 86, label: "Outbound transfer 4.8 GB" },
  ],
  riskBreakdown: [
    {
      label: "Detection evidence",
      value: 58,
      reason: "Five independent findings, three of them model-based, on one entity inside 2 h 33 m.",
    },
    {
      label: "Kill-chain progression",
      value: 14,
      reason: "Reconnaissance, command-and-control and exfiltration stages all observed in sequence.",
    },
    {
      label: "Persistence",
      value: 6,
      reason: "Beaconing sustained over 2 h 22 m with no analyst-visible user session in the window.",
    },
    {
      label: "Asset criticality",
      value: 8,
      reason: "Finance VLAN 23 workstation, criticality High, holds finance data and credentials.",
    },
    {
      label: "Threat-intel match",
      value: 0,
      reason: "No current-bundle indicator matched at time of detection.",
    },
  ],
  dns: heroDns,
  tls: heroTls,
  flows: heroFlows,
  tiMatches: [
    {
      indicator: "203.0.113.47",
      type: "IPv4",
      source: "Community C2 tracker (sample)",
      firstSeen: "2026-09-26",
      confidence: 0.91,
      context:
        "Historical contact from 10.2.3.15 on 2026-09-27 21:14 UTC, 2.5 days before behavioural detection. 7 flows, 3 TLS sessions.",
      origin: "retro-hunt",
    },
    {
      indicator: "t13d1715h2_5b57614c22b0_a1c94e30f7d2",
      type: "JA4",
      source: "Malware fingerprint DB (sample)",
      firstSeen: "2026-09-29",
      confidence: 0.84,
      context:
        "Fingerprint present in bundle DW-TI-2026-09-30-B. 9 TLS sessions across 4 internal hosts matched in the retro-hunt window.",
      origin: "retro-hunt",
    },
    {
      indicator: "qx4v8mzt2kd7p1.com",
      type: "Domain",
      source: "DGA family list (sample)",
      firstSeen: "2026-09-28",
      confidence: 0.79,
      context: "One of 61 DGA domains queried by 10.2.3.15; listed in bundle DW-TI-2026-09-30-B.",
      origin: "retro-hunt",
    },
    {
      indicator: "m6ryq9ht3zvpwx.com",
      type: "Domain",
      source: "DGA family list (sample)",
      firstSeen: "2026-09-28",
      confidence: 0.76,
      context: "Second matched DGA domain from the same family.",
      origin: "retro-hunt",
    },
  ],
  recommendedActions: [
    {
      id: "A-0417-01",
      group: "Immediate",
      text: "Submit a host-isolation request for WKS-FIN-015 (10.2.3.15) to the out-of-band change queue.",
      rationale:
        "Exfiltration is active as of 11:20 UTC. Isolation is executed by network operations, not by DiodeWatch.",
      artifactType: "Host isolation request",
    },
    {
      id: "A-0417-02",
      group: "Immediate",
      text: "Export the IOC block list covering 203.0.113.47, 198.51.100.88 and the matched JA4 fingerprint.",
      rationale:
        "Both destinations are dedicated infrastructure with no shared-service history on this network.",
      artifactType: "IOC block list",
    },
    {
      id: "A-0417-03",
      group: "Immediate",
      text: "Place a 14-day retention hold on the flow, DNS and TLS metadata referenced by this incident.",
      rationale: "Evidence records are already chained; the hold stops rotation of the underlying metadata.",
    },
    {
      id: "A-0417-04",
      group: "Short-term",
      text: "Rotate credentials, tokens and certificates reachable from WKS-FIN-015.",
      rationale: "Credential access is implied by the C2 stage but cannot be confirmed from metadata alone.",
    },
    {
      id: "A-0417-05",
      group: "Short-term",
      text: "Propose DNS sinkhole / RPZ entries for the 61 generated domains.",
      rationale:
        "Reduces re-resolution if the implant retries a second DGA seed. Applied by the DNS team, not by DiodeWatch.",
      artifactType: "DNS sinkhole / RPZ",
    },
    {
      id: "A-0417-06",
      group: "Short-term",
      text: "Review egress from Finance VLAN 23 to 203.0.113.0/24 and 198.51.100.0/24 over the last 14 days.",
      rationale: "The retro-hunt shows first C2 contact on 2026-09-27; earlier activity may be unobserved.",
    },
    {
      id: "A-0417-07",
      group: "Hardening",
      text: "Route all outbound 443 from VLAN 23 through an approved forward proxy and deny direct egress.",
      rationale: "Removes the direct-to-Internet path used by both the C2 and exfiltration stages.",
      artifactType: "Firewall rules (nftables)",
    },
    {
      id: "A-0417-08",
      group: "Hardening",
      text: "Add self-signed certificates with validity over 825 days to the standing watchlist.",
      rationale: "The TLS finding was detectable 29 minutes before the exfiltration began.",
    },
    {
      id: "A-0417-09",
      group: "Hardening",
      text: "Re-baseline per-host exfiltration thresholds for VLAN 23 workstations.",
      rationale: "Current thresholds are organisation-wide; per-host baselines reduce the 27× blind spot.",
    },
  ],
  notes: [
    {
      author: "Analyst | SOC-1",
      ts: `${D}T12:04:11Z`,
      text: "Retro-hunt completed 12:02 UTC. Historical C2 contact on 2026-09-27 confirmed. Risk raised to 95. Escalated to incident commander; mitigation package proposed.",
    },
  ],
};

/* ------------------------------------------------------------------ *
 * INC-0418 — DDoS against the public web server
 * ------------------------------------------------------------------ */

const INC_0418: Incident = {
  id: "INC-0418",
  entity: "10.0.5.20",
  hostname: "WEB-PUB-02",
  title: "Volumetric DDoS against public web service",
  summary:
    "Combined UDP reflection/amplification and SYN flood directed at the public web server. Peak inbound equivalent 3.1 Gbps from 412 distinct reflectors. Sources are reflectors or spoofed, so per-source blocking is ineffective; upstream rate-limiting and traffic scrubbing are recommended.",
  category: "DDoS",
  severity: "High",
  risk: 82,
  baseRisk: 82,
  status: "Open",
  confidence: 0.94,
  firstSeen: `${D}T10:12:03Z`,
  lastSeen: `${D}T11:58:40Z`,
  killChain: [
    {
      stage: "Impact",
      ts: `${D}T10:12:03Z`,
      detail:
        "Service degradation of WEB-PUB-02. Reconnaissance and delivery stages were not observed on the monitored segment.",
    },
  ],
  findings: [
    f(
      "F-0418-01",
      `${D}T10:12:03Z`,
      "DDoS",
      "UDP reflection and amplification",
      "412 distinct reflector addresses observed sending UDP responses to 10.0.5.20 from source ports 53, 123 and 11211. Peak inbound equivalent 3.1 Gbps sustained for 21 minutes. Amplification factor estimated at 28–54× depending on reflector type.",
      "rule SIG-DDOS-UDP-REFLECT v3.1 + volume model ddos-vol-v1.4",
      "server-to-client",
      0.94,
      74,
      [
        { feature: "Distinct reflectors", value: "412", threshold: "> 50", baseline: "6", verdict: "above" },
        { feature: "Source ports", value: "53 / 123 / 11211", threshold: "known amplifier set", baseline: "ephemeral", verdict: "match" },
        { feature: "Peak inbound equivalent", value: "3.1 Gbps", threshold: "> 500 Mbps", baseline: "180 Mbps", verdict: "above" },
        { feature: "Estimated amplification", value: "28–54×", threshold: "> 10×", baseline: "1×", verdict: "above" },
        { feature: "Median packet size", value: "1,412 B", threshold: "> 1,000 B", baseline: "512 B", verdict: "above" },
        { feature: "Incomplete/one-way flows", value: "99.4%", threshold: "> 90%", baseline: "12%", verdict: "above" },
      ],
      "volume",
      ["EV-0101", "EV-0102"]
    ),
    f(
      "F-0418-02",
      `${D}T10:31:47Z`,
      "DDoS",
      "SYN flood with source-address entropy",
      "SYN:ACK ratio of 14:1 against 10.0.5.20:443, high source-address entropy and 91% single-packet sources. No completed handshake growth beyond the pre-attack baseline, indicating spoofed source addresses.",
      "rule SIG-DDOS-SYNFLOOD v2.8",
      "server-to-client",
      0.81,
      82,
      [
        { feature: "SYN : ACK ratio", value: "14 : 1", threshold: "> 4 : 1", baseline: "1 : 3", verdict: "above" },
        { feature: "Source-address entropy (window)", value: "7.9 bits", threshold: "> 6.0 bits", baseline: "3.1 bits", verdict: "above" },
        { feature: "Single-packet sources", value: "91%", threshold: "> 70%", baseline: "22%", verdict: "above" },
        { feature: "Half-open connections", value: "48,213", threshold: "> 5,000", baseline: "310", verdict: "above" },
        { feature: "Distinct source ports per address", value: "1.0 mean", threshold: "< 2", baseline: "4.6", verdict: "below" },
      ],
      "packet",
      ["EV-0103", "EV-0104"]
    ),
  ],
  riskHistory: [
    { ts: `${D}T10:12:03Z`, risk: 74, label: "UDP reflection 412 reflectors" },
    { ts: `${D}T10:31:47Z`, risk: 82, label: "SYN flood, 14:1 SYN:ACK" },
  ],
  riskBreakdown: [
    {
      label: "Detection evidence",
      value: 61,
      reason: "Two volumetric detectors agree on a single victim asset over a 20-minute window.",
    },
    {
      label: "Kill-chain progression",
      value: 4,
      reason: "Only the impact stage is observable from mirrored metadata; delivery stages sit upstream.",
    },
    {
      label: "Persistence",
      value: 0,
      reason: "Attack duration 1 h 46 m and still active; scored on observed window only.",
    },
    {
      label: "Asset criticality",
      value: 12,
      reason: "Public web server, criticality Critical, externally reachable service.",
    },
    {
      label: "Threat-intel match",
      value: 5,
      reason: "Reflector ranges partially overlap the scanner/abuse list (sample) at low confidence.",
    },
  ],
  dns: dnsList(418, ["cdn-metrics.example.invalid", "web-pub-02.example.invalid"], 8),
  tls: tlsList(418, "203.0.113.47", "t13d1715h2_5b57614c22b0_a1c94e30f7d2", "(absent)", 4).map(
    (t) => ({ ...t, src: "10.0.5.20" })
  ),
  flows: flowList(
    4181,
    [
      ["192.0.2.31", 53, "10.0.5.20", 443],
      ["198.51.100.7", 123, "10.0.5.20", 443],
      ["203.0.113.19", 11211, "10.0.5.20", 80],
      ["10.0.5.20", 443, "192.0.2.31", 37912],
    ],
    16,
    ["reflector", "spoofed-source", "syn-flood", "amplified"]
  ),
  tiMatches: [
    {
      indicator: "192.0.2.0/24 (subset)",
      type: "IPv4",
      source: "Scanner/abuse list (sample)",
      firstSeen: "2026-09-30",
      confidence: 0.48,
      context:
        "3 of 412 reflectors appear on the scanner/abuse list. Reflector addresses are third-party resolvers and are not attacker infrastructure.",
      origin: "bundle",
    },
  ],
  recommendedActions: [
    {
      id: "A-0418-01",
      group: "Immediate",
      text: "Issue a rate-limit / RTBH request to the upstream provider for traffic to 10.0.5.20.",
      rationale:
        "Reflectors and spoofed sources cannot be filtered at the perimeter; upstream absorption is the effective control.",
      artifactType: "DDoS rate-limit / RTBH request",
    },
    {
      id: "A-0418-02",
      group: "Immediate",
      text: "Enable SYN cookies and reduce the half-open connection backlog timeout on WEB-PUB-02.",
      rationale: "Directly addresses the 14:1 SYN:ACK ratio and 48,213 half-open connections.",
    },
    {
      id: "A-0418-03",
      group: "Short-term",
      text: "Verify reflector ranges against shared DNS resolver inventory before proposing any source block.",
      rationale:
        "412 reflectors are largely legitimate open resolvers; blocking them causes collateral damage.",
      artifactType: "IOC block list",
    },
    {
      id: "A-0418-04",
      group: "Short-term",
      text: "Confirm service capacity and failover behaviour with the platform team during the event window.",
      rationale: "Service-level impact assessment requires data that is outside the monitoring enclave.",
    },
    {
      id: "A-0418-05",
      group: "Hardening",
      text: "Restrict outbound responses from DNS, NTP and memcached services on internal ranges.",
      rationale: "Reduces the amplification surface available to future reflection attacks.",
      artifactType: "Firewall rules (nftables)",
    },
    {
      id: "A-0418-06",
      group: "Hardening",
      text: "Establish a pre-agreed upstream scrubbing activation threshold with the provider.",
      rationale: "Median time-to-detect for volumetric events was 9 minutes; activation should be faster.",
    },
  ],
  notes: [
    {
      author: "Analyst | SOC-1",
      ts: `${D}T11:05:22Z`,
      text: "Upstream engaged by the duty NOC at 10:26 UTC through the standard change process. DiodeWatch has no visibility of enforcement status.",
    },
  ],
};

/* ------------------------------------------------------------------ *
 * INC-0415 — DNS tunnelling
 * ------------------------------------------------------------------ */

const INC_0415: Incident = {
  id: "INC-0415",
  entity: "10.4.7.33",
  hostname: "WKS-LAB-033",
  title: "DNS tunnelling from research workstation",
  summary:
    "Sustained TXT-record tunnelling to a single authoritative name server with high per-query payload sizes and flat TTLs. Channel remains open at the time of review.",
  category: "DGA/DNS Tunnelling",
  severity: "Medium",
  risk: 61,
  baseRisk: 61,
  status: "Investigating",
  confidence: 0.82,
  firstSeen: `${D}T07:52:18Z`,
  lastSeen: `${D}T11:44:02Z`,
  killChain: [
    {
      stage: "Command & Control",
      ts: `${D}T07:52:18Z`,
      detail: "TXT channel to 192.0.2.77:53 carrying an estimated 118 MB in 4 hours.",
    },
  ],
  findings: [
    f(
      "F-0415-01",
      `${D}T07:52:18Z`,
      "DGA/DNS Tunnelling",
      "High-volume TXT queries to single authority",
      "3,412 TXT queries to ns-tunnel.example.invalid (192.0.2.77) in 4 hours, mean query size 218 bytes, mean response 1,104 bytes. No other host on VLAN 47 contacts this authority.",
      "rule SIG-DNS-TUNNEL-TXT v2.1",
      "bidirectional",
      0.85,
      48,
      [
        { feature: "TXT queries per hour", value: "853", threshold: "> 200", baseline: "4", verdict: "above" },
        { feature: "Mean query size", value: "218 B", threshold: "> 120 B", baseline: "34 B", verdict: "above" },
        { feature: "Mean response size", value: "1,104 B", threshold: "> 400 B", baseline: "96 B", verdict: "above" },
        { feature: "Distinct authorities contacted", value: "1", threshold: "1–2", baseline: "6", verdict: "match" },
        { feature: "Query label entropy", value: "4.11 bits", threshold: "> 3.80", baseline: "2.64", verdict: "above" },
      ],
      "entropy",
      ["EV-0201", "EV-0202"]
    ),
    f(
      "F-0415-02",
      `${D}T09:14:36Z`,
      "DGA/DNS Tunnelling",
      "Estimated tunnelled volume 118 MB",
      "Cumulative TXT payload volume estimated at 118 MB over 3 h 22 m, against a 30-day host baseline of 12 MB total DNS response volume.",
      "model dns-tunnel-volume-v1.6",
      "bidirectional",
      0.78,
      61,
      [
        { feature: "Estimated tunnelled volume", value: "118 MB", threshold: "> 40 MB", baseline: "12 MB / 30 d", verdict: "above" },
        { feature: "Sustained channel duration", value: "3 h 22 m", threshold: "> 45 min", baseline: "6 min", verdict: "above" },
        { feature: "TTL consistency", value: "flat 60 s", threshold: "< 300 s", baseline: "3,600 s", verdict: "below" },
        { feature: "Distinct subdomains", value: "2,914", threshold: "> 500", baseline: "80", verdict: "above" },
      ],
      "volume",
      ["EV-0203"]
    ),
  ],
  riskHistory: [
    { ts: `${D}T07:52:18Z`, risk: 48, label: "TXT tunnelling detected" },
    { ts: `${D}T09:14:36Z`, risk: 61, label: "Estimated volume 118 MB" },
  ],
  riskBreakdown: [
    { label: "Detection evidence", value: 47, reason: "Rule plus volume model, consistent over 3 h 22 m." },
    { label: "Kill-chain progression", value: 8, reason: "Command-and-control stage only." },
    { label: "Persistence", value: 4, reason: "Channel open continuously since 07:52 UTC." },
    { label: "Asset criticality", value: 2, reason: "Research VLAN 47 workstation, criticality Medium." },
    { label: "Threat-intel match", value: 0, reason: "Authority 192.0.2.77 not present in the current bundle." },
  ],
  dns: dnsList(
    415,
    [
      "ns-tunnel.example.invalid",
      "4f9a2c.example.invalid",
      "zz81mq.example.invalid",
      "t7k3pd.example.invalid",
      "q6wvxn.example.invalid",
    ],
    14
  ),
  tls: tlsList(415, "192.0.2.77", "t13d1516h2_9e8a4c1d2f7b_5c3a91b7e204", "(absent)", 3).map((t) => ({
    ...t,
    src: "10.4.7.33",
    dst: "192.0.2.77",
  })),
  flows: flowList(
    4151,
    [
      ["10.4.7.33", 53210, "192.0.2.77", 53],
      ["192.0.2.77", 53, "10.4.7.33", 53210],
      ["10.4.7.33", 53244, "192.0.2.77", 53],
    ],
    14,
    ["dns-tunnel", "txt", "high-entropy"]
  ),
  tiMatches: [],
  recommendedActions: [
    {
      id: "A-0415-01",
      group: "Immediate",
      text: "Confirm with the research group whether the TXT channel is an approved instrument feed.",
      rationale: "Research VLAN 47 runs instrument integrations that legitimately use high-volume DNS.",
    },
    {
      id: "A-0415-02",
      group: "Short-term",
      text: "Propose DNS sinkhole / RPZ entries for ns-tunnel.example.invalid and its observed subdomains.",
      rationale: "Applicable only if the channel is confirmed unauthorised.",
      artifactType: "DNS sinkhole / RPZ",
    },
    {
      id: "A-0415-03",
      group: "Hardening",
      text: "Restrict direct outbound 53/udp from VLAN 47 to approved resolvers only.",
      rationale: "Removes the arbitrary-authority path used by the tunnel.",
      artifactType: "Firewall rules (nftables)",
    },
  ],
  notes: [
    {
      author: "Analyst | SOC-1",
      ts: `${D}T10:02:44Z`,
      text: "Awaiting confirmation from R&D IT Operations on the instrument integration. Status held at Investigating.",
    },
  ],
};

/* ------------------------------------------------------------------ *
 * INC-0409 — suspicious encrypted session
 * ------------------------------------------------------------------ */

const INC_0409: Incident = {
  id: "INC-0409",
  entity: "10.3.2.71",
  hostname: "WKS-OPS-071",
  title: "Suspicious encrypted session to unclassified host",
  summary:
    "Single TLS session to 203.0.113.91 with a self-signed certificate and an early-packet-sequence score of 0.78. No follow-on activity observed; the finding rests on one session.",
  category: "Encrypted Malware",
  severity: "Medium",
  risk: 58,
  baseRisk: 58,
  status: "Open",
  confidence: 0.78,
  firstSeen: `${D}T06:38:51Z`,
  lastSeen: `${D}T06:41:09Z`,
  killChain: [
    {
      stage: "Command & Control",
      ts: `${D}T06:38:51Z`,
      detail: "Single 138-second session; no beacon periodicity established.",
    },
  ],
  findings: [
    f(
      "F-0409-01",
      `${D}T06:38:51Z`,
      "Encrypted Malware",
      "Self-signed certificate, non-standard ALPN",
      "Session to 203.0.113.91:8443 presenting a self-signed certificate valid 3,650 days with ALPN http/1.1 and no SNI. Early-packet-sequence classifier p=0.78.",
      "model tls-eps-v1.9",
      "bidirectional",
      0.78,
      58,
      [
        { feature: "Certificate validity", value: "3,650 days", threshold: "> 825 days", baseline: "90 days", verdict: "above" },
        { feature: "Certificate issuer", value: "self-signed", threshold: "self-signed", baseline: "public CA", verdict: "match" },
        { feature: "Early-packet-sequence classifier", value: "p = 0.78", threshold: "≥ 0.70", baseline: "0.09", verdict: "above" },
        { feature: "Session duration", value: "138 s", threshold: "30–900 s", baseline: "42 s", verdict: "match" },
        { feature: "Bytes transferred", value: "41.2 KB", threshold: "< 5 MB", baseline: "180 KB", verdict: "neutral" },
      ],
      "packet",
      ["EV-0301", "EV-0302"]
    ),
  ],
  riskHistory: [{ ts: `${D}T06:38:51Z`, risk: 58, label: "Self-signed TLS session" }],
  riskBreakdown: [
    { label: "Detection evidence", value: 44, reason: "One model-based finding on a single session." },
    { label: "Kill-chain progression", value: 4, reason: "Possible command-and-control; delivery stage not observed." },
    { label: "Persistence", value: 0, reason: "No recurrence within 5 hours of observation." },
    { label: "Asset criticality", value: 8, reason: "Operations VLAN 12 workstation, criticality High." },
    { label: "Threat-intel match", value: 2, reason: "203.0.113.91 appears once on the scanner/abuse list (sample) at low confidence." },
  ],
  dns: dnsList(409, ["203.0.113.91.invalid", "ops-metrics.example.invalid"], 6),
  tls: tlsList(409, "203.0.113.91", "t13d1713h2_4a91c7e2b8d0_9c1e44b7a203", "(absent)", 3).map((t) => ({
    ...t,
    src: "10.3.2.71",
    certValidityDays: 3650,
  })),
  flows: flowList(
    4091,
    [
      ["10.3.2.71", 51420, "203.0.113.91", 8443],
      ["203.0.113.91", 8443, "10.3.2.71", 51420],
    ],
    10,
    ["self-signed", "eps-flag", "single-session"]
  ),
  tiMatches: [
    {
      indicator: "203.0.113.91",
      type: "IPv4",
      source: "Scanner/abuse list (sample)",
      firstSeen: "2026-09-30",
      confidence: 0.34,
      context: "Listed as an unclassified scanning host. No C2 or malware attribution.",
      origin: "bundle",
    },
  ],
  recommendedActions: [
    {
      id: "A-0409-01",
      group: "Immediate",
      text: "Review the 06:38 UTC session record with the operations shift lead.",
      rationale: "Single-session finding; context from the asset owner is the fastest discriminator.",
    },
    {
      id: "A-0409-02",
      group: "Short-term",
      text: "Add 203.0.113.91 to the watchlist and alert on any recurrence.",
      rationale: "Watchlisting is local to the monitoring enclave and requires no network change.",
    },
    {
      id: "A-0409-03",
      group: "Hardening",
      text: "Deny direct outbound 8443 from Operations VLAN 12.",
      rationale: "Non-standard TLS ports from workstations have no approved business use.",
      artifactType: "Firewall rules (nftables)",
    },
  ],
  notes: [],
};

/* ------------------------------------------------------------------ *
 * INC-0412 — slow port scan
 * ------------------------------------------------------------------ */

const INC_0412: Incident = {
  id: "INC-0412",
  entity: "10.1.9.8",
  hostname: "WKS-ENG-008",
  title: "Slow port scan of engineering subnet",
  summary:
    "Low-rate scan of 10.1.9.0/24 across 41 ports over 3 h 10 m, below the volumetric threshold but with a monotonic address and port order consistent with a stealth scanner.",
  category: "Reconnaissance",
  severity: "Low",
  risk: 38,
  baseRisk: 38,
  status: "Open",
  confidence: 0.91,
  firstSeen: `${D}T05:11:26Z`,
  lastSeen: `${D}T08:21:44Z`,
  killChain: [
    {
      stage: "Reconnaissance",
      ts: `${D}T05:11:26Z`,
      detail: "Slow scan, 2,184 probes, no follow-on stage observed.",
    },
  ],
  findings: [
    f(
      "F-0412-01",
      `${D}T05:11:26Z`,
      "Reconnaissance",
      "Low-rate sequential scan",
      "2,184 probes against 96 hosts on 41 ports over 3 h 10 m, mean 11.5 packets per minute. Monotonic address and port order; 0 completed handshakes.",
      "rule SIG-RECON-SLOWSCAN v1.7",
      "client-to-server",
      0.91,
      38,
      [
        { feature: "Probes in window", value: "2,184", threshold: "> 1,000", baseline: "60/day", verdict: "above" },
        { feature: "Probe rate", value: "11.5 / min", threshold: "< 30 / min", baseline: "0.4 / min", verdict: "match" },
        { feature: "Distinct ports", value: "41", threshold: "> 20", baseline: "6", verdict: "above" },
        { feature: "Completed handshakes", value: "0", threshold: "< 5%", baseline: "96%", verdict: "below" },
        { feature: "Address order", value: "monotonic", threshold: "monotonic or shuffled", baseline: "random", verdict: "match" },
      ],
      "packet",
      ["EV-0401"]
    ),
  ],
  riskHistory: [{ ts: `${D}T05:11:26Z`, risk: 38, label: "Slow scan detected" }],
  riskBreakdown: [
    { label: "Detection evidence", value: 31, reason: "Single high-confidence rule; no corroborating detector." },
    { label: "Kill-chain progression", value: 5, reason: "Reconnaissance stage only." },
    { label: "Persistence", value: 2, reason: "Scan spread over 3 h 10 m, consistent with threshold evasion." },
    { label: "Asset criticality", value: 0, reason: "Engineering workstation, criticality Low." },
    { label: "Threat-intel match", value: 0, reason: "No indicator matched." },
  ],
  dns: dnsList(412, ["eng-ci.example.invalid", "10.1.9.8.invalid"], 5),
  tls: [],
  flows: flowList(
    4121,
    [
      ["10.1.9.8", 44120, "10.1.9.21", 445],
      ["10.1.9.8", 44124, "10.1.9.22", 3389],
      ["10.1.9.8", 44131, "10.1.9.33", 22],
      ["10.1.9.8", 44140, "10.1.9.44", 139],
    ],
    14,
    ["scan", "stealth", "no-handshake"]
  ),
  tiMatches: [],
  recommendedActions: [
    {
      id: "A-0412-01",
      group: "Short-term",
      text: "Confirm whether an authorised vulnerability scan was scheduled for 05:00–08:30 UTC.",
      rationale: "Engineering runs quarterly internal scans that resemble this pattern.",
    },
    {
      id: "A-0412-02",
      group: "Hardening",
      text: "Restrict workstation-to-workstation 445/tcp and 3389/tcp within VLAN 18.",
      rationale: "Both ports are probed by the scan and have no approved workstation-to-workstation use.",
      artifactType: "Firewall rules (nftables)",
    },
  ],
  notes: [],
};

/* ------------------------------------------------------------------ *
 * INC-0403 — exfiltration anomaly, resolved benign
 * ------------------------------------------------------------------ */

const INC_0403: Incident = {
  id: "INC-0403",
  entity: "10.2.8.14",
  hostname: "SRV-BACKUP-14",
  title: "Exfiltration anomaly — scheduled backup job",
  summary:
    "Outbound volume anomaly of 6.2 GB in 34 minutes. Review identified the approved nightly backup job to 198.51.100.140. Closed as benign with a baseline exception recorded.",
  category: "Exfiltration",
  severity: "Medium",
  risk: 44,
  baseRisk: 44,
  status: "Resolved",
  confidence: 0.72,
  firstSeen: `${D}T02:14:08Z`,
  lastSeen: `${D}T02:48:31Z`,
  killChain: [
    {
      stage: "Exfiltration",
      ts: `${D}T02:14:08Z`,
      detail: "Volume anomaly later attributed to the scheduled backup window; no C2 stage observed.",
    },
  ],
  findings: [
    f(
      "F-0403-01",
      `${D}T02:14:08Z`,
      "Exfiltration",
      "Outbound volume 6.2 GB in 34 min",
      "Outbound transfer to 198.51.100.140:443 at 24 Mbps equivalent, 18× the rolling host baseline, inside the approved backup window.",
      "model exfil-volume-v2.2",
      "client-to-server",
      0.72,
      44,
      [
        { feature: "Outbound volume (34 min)", value: "6.2 GB", threshold: "> 500 MB", baseline: "340 MB/night", verdict: "above" },
        { feature: "Ratio to host baseline", value: "18×", threshold: "> 5×", baseline: "1.0×", verdict: "above" },
        { feature: "Upload : download ratio", value: "9 : 1", threshold: "> 20 : 1", baseline: "1 : 1", verdict: "neutral" },
        { feature: "Destination", value: "198.51.100.140 (known)", threshold: "first seen", baseline: "seen 61 nights", verdict: "neutral" },
      ],
      "volume",
      ["EV-0501"]
    ),
  ],
  riskHistory: [{ ts: `${D}T02:14:08Z`, risk: 44, label: "Volume anomaly detected" }],
  riskBreakdown: [
    { label: "Detection evidence", value: 33, reason: "Single model finding." },
    { label: "Kill-chain progression", value: 2, reason: "Exfiltration stage only, no precursor stages." },
    { label: "Persistence", value: 0, reason: "Single 34-minute window." },
    { label: "Asset criticality", value: 6, reason: "Backup server, criticality Medium." },
    { label: "Threat-intel match", value: 3, reason: "Destination appears on the scanner/abuse list (sample) at low confidence." },
  ],
  dns: dnsList(403, ["backup-store.example.invalid"], 5),
  tls: tlsList(403, "198.51.100.140", "t13d2014h2_7b3c91a4e2d8_1c9e44b7a203", "backup-store.example.invalid", 3).map(
    (t) => ({ ...t, src: "10.2.8.14", selfSigned: false, certValidityDays: 90, epsScore: 0.12 })
  ),
  flows: flowList(
    4031,
    [
      ["10.2.8.14", 51001, "198.51.100.140", 443],
      ["198.51.100.140", 443, "10.2.8.14", 51001],
    ],
    12,
    ["backup-window", "known-destination", "scheduled"]
  ),
  tiMatches: [
    {
      indicator: "198.51.100.140",
      type: "IPv4",
      source: "Scanner/abuse list (sample)",
      firstSeen: "2026-09-30",
      confidence: 0.29,
      context: "Listed address; the backup vendor operates documentation-range space. Low confidence, dismissed.",
      origin: "bundle",
    },
  ],
  recommendedActions: [
    {
      id: "A-0403-01",
      group: "Hardening",
      text: "Record a baseline exception for the 02:00–03:00 UTC backup window on SRV-BACKUP-14.",
      rationale: "Avoids repeat alerts for the same scheduled window without lowering global thresholds.",
    },
  ],
  notes: [
    {
      author: "Analyst | SOC-1",
      ts: `${D}T03:12:40Z`,
      text: "Scheduled backup job, benign. Confirmed against the change calendar (CHG-2291). Closing as Resolved with a baseline exception.",
    },
  ],
};

/* ------------------------------------------------------------------ *
 * INC-0419 — created by the retro-hunt
 * ------------------------------------------------------------------ */

const INC_0419: Incident = {
  id: "INC-0419",
  entity: "10.2.9.44",
  hostname: "WKS-HR-044",
  title: "Historical contact with known C2 address",
  summary:
    "Retro-hunt against bundle DW-TI-2026-09-30-B found a single historical flow from 10.2.9.44 to 203.0.113.47 on 2026-09-28 at 14:22 UTC, two days before the same address was detected behaviourally on 10.2.3.15. No further activity from this host.",
  category: "C2 Beaconing",
  severity: "Medium",
  risk: 57,
  baseRisk: 57,
  status: "Open",
  confidence: 0.62,
  firstSeen: "2026-09-28T14:22:07Z",
  lastSeen: "2026-09-28T14:22:41Z",
  hiddenUntilRetroHunt: true,
  createdByRetroHunt: true,
  killChain: [
    {
      stage: "Command & Control",
      ts: "2026-09-28T14:22:07Z",
      detail: "Single 34-second flow, 1.2 KB outbound, no beacon periodicity established.",
    },
  ],
  findings: [
    f(
      "F-0419-01",
      "2026-09-28T14:22:07Z",
      "C2 Beaconing",
      "Single contact with known C2 address 203.0.113.47",
      "One flow of 1.2 KB outbound over 34 seconds from 10.2.9.44 to 203.0.113.47:443, matched by the retro-hunt against bundle DW-TI-2026-09-30-B. No recurrence in the 14-day scan window.",
      "retro-hunt: exact IOC match on stored flow metadata",
      "client-to-server",
      0.62,
      57,
      [
        { feature: "Flows matched", value: "1", threshold: "≥ 1", baseline: "0", verdict: "match" },
        { feature: "Outbound bytes", value: "1.2 KB", threshold: "n/a", baseline: "0", verdict: "neutral" },
        { feature: "Recurrence in 14-day window", value: "0", threshold: "≥ 3 for beaconing", baseline: "0", verdict: "below" },
        { feature: "JA4 fingerprint", value: "no match", threshold: "exact match", baseline: "no match", verdict: "neutral" },
        { feature: "Interval regularity", value: "not applicable", threshold: "CV < 0.10", baseline: "n/a", verdict: "neutral" },
      ],
      "iat",
      ["EV-0601", "EV-0602"]
    ),
  ],
  riskHistory: [{ ts: "2026-09-28T14:22:07Z", risk: 57, label: "Historical C2 contact (retro-hunt)" }],
  riskBreakdown: [
    { label: "Detection evidence", value: 40, reason: "Exact indicator match on stored metadata, single occurrence." },
    { label: "Kill-chain progression", value: 6, reason: "Possible command-and-control stage; no precursor or follow-on observed." },
    { label: "Persistence", value: 0, reason: "No recurrence within the 14-day scan window." },
    { label: "Asset criticality", value: 8, reason: "HR VLAN 31 workstation, criticality Medium." },
    { label: "Threat-intel match", value: 3, reason: "Indicator 203.0.113.47 present in bundle DW-TI-2026-09-30-B at 0.91 base confidence." },
  ],
  dns: [
    {
      ts: "2026-09-28T14:22:05Z",
      query: "cdn-metrics.example.invalid",
      type: "A",
      response: "203.0.113.47",
      entropy: 2.94,
      nxdomain: false,
      length: 28,
    },
    {
      ts: "2026-09-28T14:21:58Z",
      query: "hr-portal.example.invalid",
      type: "A",
      response: "10.2.9.44",
      entropy: 2.41,
      nxdomain: false,
      length: 24,
    },
    {
      ts: "2026-09-28T14:22:31Z",
      query: "ntp.example.invalid",
      type: "A",
      response: "10.2.9.44",
      entropy: 2.2,
      nxdomain: false,
      length: 20,
    },
    {
      ts: "2026-09-28T14:22:38Z",
      query: "telemetry-cdn.example.invalid",
      type: "A",
      response: "203.0.113.47",
      entropy: 3.12,
      nxdomain: false,
      length: 27,
    },
  ],
  tls: [
    {
      ts: "2026-09-28T14:22:09Z",
      src: "10.2.9.44",
      dst: "203.0.113.47",
      sni: "(absent)",
      ja4: "t13d1715h2_5b57614c22b0_a1c94e30f7d2",
      ja4s: "t130200_9e8a4c1d2f7b_5c3a91b7e204",
      alpn: "http/1.1",
      certSubject: "CN=localhost",
      certIssuer: "CN=localhost (self-signed)",
      certValidityDays: 3650,
      selfSigned: true,
      epsScore: 0.77,
      bytes: 1204,
    },
  ],
  flows: [
    {
      ts: "2026-09-28T14:22:07Z",
      src: "10.2.9.44",
      srcPort: 49310,
      dst: "203.0.113.47",
      dstPort: 443,
      proto: "TCP",
      packets: 18,
      bytes: 1204,
      direction: "client-to-server",
      durationS: 34.2,
      tags: ["retro-hunt-match", "known-c2"],
    },
    {
      ts: "2026-09-28T14:20:51Z",
      src: "10.2.9.44",
      srcPort: 49288,
      dst: "10.2.9.9",
      dstPort: 53,
      proto: "UDP",
      packets: 2,
      bytes: 148,
      direction: "bidirectional",
      durationS: 0.4,
      tags: ["dns"],
    },
    {
      ts: "2026-09-28T14:19:12Z",
      src: "10.2.9.44",
      srcPort: 49260,
      dst: "10.2.9.10",
      dstPort: 443,
      proto: "TCP",
      packets: 42,
      bytes: 8120,
      direction: "bidirectional",
      durationS: 12.8,
      tags: ["internal"],
    },
  ],
  tiMatches: [
    {
      indicator: "203.0.113.47",
      type: "IPv4",
      source: "Community C2 tracker (sample)",
      firstSeen: "2026-09-26",
      confidence: 0.91,
      context:
        "Single flow on 2026-09-28 14:22 UTC, 34 seconds, 1.2 KB outbound. Matched by retro-hunt on bundle DW-TI-2026-09-30-B.",
      origin: "retro-hunt",
    },
    {
      indicator: "t13d1715h2_5b57614c22b0_a1c94e30f7d2",
      type: "JA4",
      source: "Malware fingerprint DB (sample)",
      firstSeen: "2026-09-29",
      confidence: 0.84,
      context: "Same JA4 fingerprint as the INC-0417 C2 session, observed on this host on 2026-09-28.",
      origin: "retro-hunt",
    },
  ],
  recommendedActions: [
    {
      id: "A-0419-01",
      group: "Immediate",
      text: "Submit a host-isolation request for WKS-HR-044 (10.2.9.44) to the out-of-band change queue.",
      rationale:
        "Host shares the C2 address and the JA4 fingerprint with INC-0417; isolation is executed outside DiodeWatch.",
      artifactType: "Host isolation request",
    },
    {
      id: "A-0419-02",
      group: "Short-term",
      text: "Preserve the 14 days of stored metadata for 10.2.9.44 and review all contacts with 203.0.113.47.",
      rationale: "The single matched flow may be the visible edge of a longer, unrecorded pattern.",
    },
    {
      id: "A-0419-03",
      group: "Short-term",
      text: "Rotate credentials and tokens reachable from WKS-HR-044.",
      rationale: "HR workstations hold personnel records and shared credentials.",
    },
  ],
  notes: [
    {
      author: "Retro-hunt (automated)",
      ts: "2026-09-30T12:02:14Z",
      text: "Incident created by retro-hunt job RH-2026-09-30-B. Single historical contact with 203.0.113.47 on 2026-09-28 14:22 UTC.",
    },
  ],
};

export const INCIDENTS: Incident[] = [INC_0417, INC_0418, INC_0415, INC_0409, INC_0412, INC_0403, INC_0419];

export function incidentById(id: string): Incident | undefined {
  return INCIDENTS.find((i) => i.id === id);
}
