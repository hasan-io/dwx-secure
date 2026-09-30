import type { Category } from "../lib/types";

/* ------------------------------------------------------------------ *
 * Security Visualization — deterministic seeded observability data.
 * Times are minutes of day on 2026-09-30 unless marked historical.
 * ------------------------------------------------------------------ */

export type VizNodeType = "internal" | "service" | "external";

export interface VizNode {
  id: string;
  label: string;
  sub: string;
  type: VizNodeType;
  x: number;
  y: number;
  category?: Category;
  host?: string;
  note: string;
}

export interface VizEdge {
  id: string;
  from: string;
  to: string;
  mb: number;
  flows: number;
  direction: "client-to-server" | "server-to-client" | "both";
  category: Category | null;
  confidence: number;
  proto: string;
  port: number;
  note: string;
  retroHuntOnly?: boolean;
}

export const GRAPH_NODES: VizNode[] = [
  { id: "10.2.3.15", label: "10.2.3.15", sub: "WKS-FIN-015 · VLAN 23", type: "internal", x: 120, y: 48, host: "10.2.3.15", category: "Exfiltration", note: "Finance workstation. Five findings on 2026-09-30; incident INC-0417." },
  { id: "10.2.9.44", label: "10.2.9.44", sub: "WKS-HR-044 · VLAN 31", type: "internal", x: 120, y: 118, host: "10.2.9.44", category: "C2 Beaconing", note: "HR workstation. Single historical contact with the C2 address (INC-0419)." },
  { id: "10.0.5.20", label: "10.0.5.20", sub: "WEB-PUB-02 · VLAN 10", type: "internal", x: 120, y: 188, host: "10.0.5.20", category: "DDoS", note: "Public web server. Volumetric attack in progress (INC-0418)." },
  { id: "10.4.7.33", label: "10.4.7.33", sub: "WKS-LAB-033 · VLAN 47", type: "internal", x: 120, y: 258, host: "10.4.7.33", category: "DGA/DNS Tunnelling", note: "Research workstation. Sustained TXT tunnel to a single authority (INC-0415)." },
  { id: "10.3.2.71", label: "10.3.2.71", sub: "WKS-OPS-071 · VLAN 12", type: "internal", x: 120, y: 328, host: "10.3.2.71", category: "Encrypted Malware", note: "Operations workstation. One anomalous TLS session (INC-0409)." },
  { id: "10.2.8.14", label: "10.2.8.14", sub: "SRV-BACKUP-14 · VLAN 8", type: "internal", x: 120, y: 398, host: "10.2.8.14", note: "Backup server. Volume anomaly closed as benign (INC-0403)." },
  { id: "10.1.9.8", label: "10.1.9.8", sub: "WKS-ENG-008 · VLAN 18", type: "internal", x: 120, y: 468, host: "10.1.9.8", category: "Reconnaissance", note: "Engineering workstation. Slow port scan of its own subnet (INC-0412)." },

  { id: "https443", label: "HTTPS / 443", sub: "service", type: "service", x: 500, y: 78, note: "Largest observed service. Mixes user browsing, C2 beaconing and exfiltration." },
  { id: "dns53", label: "DNS / 53", sub: "service", type: "service", x: 500, y: 168, note: "Resolution traffic. Carries DGA lookup patterns and the TXT tunnel." },
  { id: "smb445", label: "SMB / 445", sub: "service", type: "service", x: 500, y: 258, note: "Internal file service. Probed by horizontal and slow scans." },
  { id: "https8443", label: "HTTPS / 8443", sub: "service", type: "service", x: 500, y: 328, note: "Non-standard TLS port from workstations. No approved business use." },
  { id: "reflect", label: "UDP 53 / 123 / 11211", sub: "amplifier services", type: "service", x: 500, y: 398, category: "DDoS", note: "DNS, NTP and memcached amplifiers used in the reflection attack." },

  { id: "203.0.113.47", label: "203.0.113.47", sub: "known C2 address", type: "external", x: 870, y: 48, category: "C2 Beaconing", note: "Command-and-control address. Bundle DW-TI-2026-09-30-B lists it at 0.91 base confidence." },
  { id: "198.51.100.88", label: "198.51.100.88", sub: "exfiltration sink", type: "external", x: 870, y: 118, category: "Exfiltration", note: "Destination of the 4.8 GB outbound transfer. Never observed before 2026-09-30." },
  { id: "gen-domains", label: "Generated domains (61)", sub: "DGA resolution targets", type: "external", x: 870, y: 188, category: "DGA/DNS Tunnelling", note: "61 algorithmically generated names, 62% NXDOMAIN, mean label entropy 3.62." },
  { id: "10.2.3.0/24", label: "10.2.3.0/24", sub: "254 internal hosts", type: "external", x: 870, y: 258, category: "Reconnaissance", note: "Horizontal scan target of INC-0417. 254 hosts probed in 90 seconds." },
  { id: "192.0.2.77", label: "192.0.2.77", sub: "tunnel authority", type: "external", x: 870, y: 328, category: "DGA/DNS Tunnelling", note: "ns-tunnel.example.invalid. Estimated 118 MB tunnelled over TXT records." },
  { id: "203.0.113.91", label: "203.0.113.91", sub: "unclassified host", type: "external", x: 870, y: 398, category: "Encrypted Malware", note: "Self-signed certificate, 3,650-day validity, early-packet-sequence p = 0.78." },
  { id: "reflector-set", label: "Reflector set (412)", sub: "third-party resolvers", type: "external", x: 870, y: 468, category: "DDoS", note: "412 distinct amplifiers. Sources are reflectors or spoofed; not attacker infrastructure." },
  { id: "10.1.9.0/24", label: "10.1.9.0/24", sub: "96 internal hosts", type: "external", x: 870, y: 538, category: "Reconnaissance", note: "Slow scan target of INC-0412. 41 ports over 3 h 10 m." },
  { id: "198.51.100.140", label: "198.51.100.140", sub: "backup store", type: "external", x: 870, y: 608, note: "Approved backup destination for SRV-BACKUP-14. Known good." },
];

export const GRAPH_EDGES: VizEdge[] = [
  { id: "e1", from: "10.2.3.15", to: "https443", mb: 8.2, flows: 240, direction: "both", category: null, confidence: 0.04, proto: "TCP", port: 443, note: "Baseline browsing and mail synchronisation on the finance workstation." },
  { id: "e2", from: "10.2.3.15", to: "dns53", mb: 0.42, flows: 61, direction: "both", category: "DGA/DNS Tunnelling", confidence: 0.89, proto: "UDP", port: 53, note: "61 algorithmically generated domain queries between 09:05 and 09:27." },
  { id: "e3", from: "10.2.3.15", to: "smb445", mb: 0.7, flows: 254, direction: "client-to-server", category: "Reconnaissance", confidence: 0.97, proto: "TCP", port: 445, note: "Horizontal scan of 10.2.3.0/24 on 445/tcp, 254 hosts in 90 s." },
  { id: "e4", from: "https443", to: "203.0.113.47", mb: 12.4, flows: 142, direction: "both", category: "C2 Beaconing", confidence: 0.88, proto: "TCP", port: 443, note: "Beacon interval 60.1 s, CV 0.03, payload 212 ± 6 bytes. 142 connections by 11:53." },
  { id: "e5", from: "https443", to: "198.51.100.88", mb: 4800, flows: 38, direction: "client-to-server", category: "Exfiltration", confidence: 0.86, proto: "TCP", port: 443, note: "4.8 GB outbound in 41 minutes, 27× host baseline, upload:download 312:1." },
  { id: "e6", from: "dns53", to: "gen-domains", mb: 0.38, flows: 61, direction: "both", category: "DGA/DNS Tunnelling", confidence: 0.89, proto: "UDP", port: 53, note: "Resolution attempts against 61 generated names, 62% NXDOMAIN." },
  { id: "e7", from: "smb445", to: "10.2.3.0/24", mb: 0.7, flows: 254, direction: "client-to-server", category: "Reconnaissance", confidence: 0.97, proto: "TCP", port: 445, note: "Sequential address walk with 3 completed handshakes in 12,208 SYN packets." },
  { id: "e8", from: "10.2.9.44", to: "https443", mb: 0.02, flows: 1, direction: "client-to-server", category: "C2 Beaconing", confidence: 0.62, proto: "TCP", port: 443, note: "Single 34-second flow on 2026-09-28 14:22 UTC, 1.2 KB outbound. Found by the retro-hunt.", retroHuntOnly: true },
  { id: "e9", from: "reflector-set", to: "reflect", mb: 3100, flows: 412, direction: "server-to-client", category: "DDoS", confidence: 0.94, proto: "UDP", port: 53, note: "Amplified responses from 412 reflectors, peak 3.1 Gbps equivalent." },
  { id: "e10", from: "reflect", to: "10.0.5.20", mb: 3100, flows: 412, direction: "server-to-client", category: "DDoS", confidence: 0.94, proto: "UDP", port: 53, note: "Inbound to the public web server. Per-source filtering is ineffective." },
  { id: "e11", from: "10.0.5.20", to: "https443", mb: 184, flows: 1240, direction: "both", category: null, confidence: 0.02, proto: "TCP", port: 443, note: "Legitimate request/response traffic to real clients before and during the event." },
  { id: "e12", from: "10.4.7.33", to: "dns53", mb: 118, flows: 3412, direction: "both", category: "DGA/DNS Tunnelling", confidence: 0.85, proto: "UDP", port: 53, note: "TXT record tunnel, mean query 218 bytes, mean response 1,104 bytes." },
  { id: "e13", from: "dns53", to: "192.0.2.77", mb: 118, flows: 3412, direction: "both", category: "DGA/DNS Tunnelling", confidence: 0.85, proto: "UDP", port: 53, note: "Single authoritative name server, 2,914 distinct subdomains observed." },
  { id: "e14", from: "10.3.2.71", to: "https8443", mb: 0.04, flows: 1, direction: "both", category: "Encrypted Malware", confidence: 0.78, proto: "TCP", port: 8443, note: "Self-signed certificate valid 3,650 days, ALPN http/1.1." },
  { id: "e15", from: "https8443", to: "203.0.113.91", mb: 0.04, flows: 1, direction: "both", category: "Encrypted Malware", confidence: 0.78, proto: "TCP", port: 8443, note: "Early-packet-sequence classifier p = 0.78. No recurrence in 5 hours." },
  { id: "e16", from: "10.2.8.14", to: "https443", mb: 6200, flows: 28, direction: "client-to-server", category: null, confidence: 0.0, proto: "TCP", port: 443, note: "Scheduled backup window 02:00–03:00 UTC. Closed as benign (INC-0403)." },
  { id: "e17", from: "https443", to: "198.51.100.140", mb: 6200, flows: 28, direction: "client-to-server", category: null, confidence: 0.0, proto: "TCP", port: 443, note: "Approved backup destination, seen on 61 consecutive nights." },
  { id: "e18", from: "10.1.9.8", to: "smb445", mb: 0.12, flows: 2184, direction: "client-to-server", category: "Reconnaissance", confidence: 0.91, proto: "TCP", port: 445, note: "Low-rate scan, 41 ports, 96 hosts, 0 completed handshakes." },
  { id: "e19", from: "smb445", to: "10.1.9.0/24", mb: 0.12, flows: 2184, direction: "client-to-server", category: "Reconnaissance", confidence: 0.91, proto: "TCP", port: 445, note: "Monotonic address and port order, consistent with threshold evasion." },
];

/* ------------------------------ Timeline --------------------------- */

export interface TimelineEvent {
  id: string;
  minute: number; // minutes of day
  category: Category;
  title: string;
  incident: string;
  entity: string;
  confidence: number;
  risk?: number;
  detail: string;
  historical?: boolean;
}

export const TIMELINE_EVENTS: TimelineEvent[] = [
  { id: "T-01", minute: 134, category: "Exfiltration", title: "Outbound volume anomaly", incident: "INC-0403", entity: "10.2.8.14", confidence: 0.72, risk: 44, detail: "6.2 GB in 34 minutes to 198.51.100.140. Later attributed to the scheduled backup job." },
  { id: "T-02", minute: 311, category: "Reconnaissance", title: "Slow port scan", incident: "INC-0412", entity: "10.1.9.8", confidence: 0.91, risk: 38, detail: "2,184 probes across 41 ports in 3 h 10 m. 0 completed handshakes." },
  { id: "T-03", minute: 398, category: "Encrypted Malware", title: "Self-signed TLS session", incident: "INC-0409", entity: "10.3.2.71", confidence: 0.78, risk: 58, detail: "3,650-day certificate validity to 203.0.113.91:8443. No follow-on activity." },
  { id: "T-04", minute: 472, category: "DGA/DNS Tunnelling", title: "TXT tunnelling begins", incident: "INC-0415", entity: "10.4.7.33", confidence: 0.85, risk: 48, detail: "853 TXT queries per hour to a single authority. Channel remains open." },
  { id: "T-05", minute: 527, category: "Reconnaissance", title: "Horizontal scan 445/tcp", incident: "INC-0417", entity: "10.2.3.15", confidence: 0.97, risk: 34, detail: "254 hosts in 90 s. Rule SIG-RECON-HSCAN-445 v2.4. First finding of the hero incident." },
  { id: "T-06", minute: 545, category: "DGA/DNS Tunnelling", title: "61 generated domains", incident: "INC-0417", entity: "10.2.3.15", confidence: 0.89, risk: 52, detail: "62% NXDOMAIN, mean label entropy 3.62, model probability 0.89." },
  { id: "T-07", minute: 554, category: "DGA/DNS Tunnelling", title: "Tunnelled volume 118 MB", incident: "INC-0415", entity: "10.4.7.33", confidence: 0.78, risk: 61, detail: "Cumulative TXT payload estimated at 118 MB over 3 h 22 m." },
  { id: "T-08", minute: 571, category: "C2 Beaconing", title: "Beacon to 203.0.113.47", incident: "INC-0417", entity: "10.2.3.15", confidence: 0.88, risk: 71, detail: "Interval 60.1 s, CV 0.03, periodicity score 0.93. 142 connections by 11:53." },
  { id: "T-09", minute: 592, category: "Encrypted Malware", title: "Anomalous TLS to C2", incident: "INC-0417", entity: "10.2.3.15", confidence: 0.83, risk: 79, detail: "JA4 t13d1715h2_5b57614c22b0_a1c94e30f7d2, early-packet-sequence p = 0.83." },
  { id: "T-10", minute: 612, category: "DDoS", title: "UDP reflection starts", incident: "INC-0418", entity: "10.0.5.20", confidence: 0.94, risk: 74, detail: "412 reflectors, source ports 53 / 123 / 11211, peak 3.1 Gbps equivalent." },
  { id: "T-11", minute: 631, category: "DDoS", title: "SYN flood follows", incident: "INC-0418", entity: "10.0.5.20", confidence: 0.81, risk: 82, detail: "SYN:ACK 14:1, 91% single-packet sources, 48,213 half-open connections." },
  { id: "T-12", minute: 680, category: "Exfiltration", title: "4.8 GB outbound transfer", incident: "INC-0417", entity: "10.2.3.15", confidence: 0.86, risk: 86, detail: "38 flows in 41 minutes to 198.51.100.88:443. 27× host baseline." },
  { id: "T-13", minute: 722, category: "C2 Beaconing", title: "Historical match (retro-hunt)", incident: "INC-0417", entity: "10.2.3.15", confidence: 0.9, risk: 95, detail: "Retro-hunt RH-2026-09-30-B matched 7 historical flows. First contact 2026-09-27 21:14 UTC.", historical: true },
];

export const TIME_RANGES = [
  { id: "1h", label: "Last 1 hour", from: 660, to: 730 },
  { id: "6h", label: "Last 6 hours", from: 360, to: 730 },
  { id: "24h", label: "Last 24 hours", from: 0, to: 730 },
  { id: "window", label: "Incident window", from: 500, to: 730 },
];

/* ------------------------------- Flow ------------------------------ */

export interface FlowNode {
  id: string;
  label: string;
  column: number;
  sub?: string;
}

export interface FlowLink {
  source: string;
  target: string;
  mb: number;
  category: Category | null;
  label: string;
}

export const FLOW_NODES: FlowNode[] = [
  { id: "f-102315", label: "10.2.3.15", column: 0, sub: "WKS-FIN-015" },
  { id: "f-102944", label: "10.2.9.44", column: 0, sub: "WKS-HR-044" },
  { id: "f-100520", label: "10.0.5.20", column: 0, sub: "WEB-PUB-02" },
  { id: "f-104733", label: "10.4.7.33", column: 0, sub: "WKS-LAB-033" },
  { id: "f-103271", label: "10.3.2.71", column: 0, sub: "WKS-OPS-071" },
  { id: "f-102814", label: "10.2.8.14", column: 0, sub: "SRV-BACKUP-14" },

  { id: "f-https", label: "HTTPS / 443", column: 1 },
  { id: "f-dns", label: "DNS / 53", column: 1 },
  { id: "f-udp", label: "UDP 53 / 123 / 11211", column: 1 },
  { id: "f-8443", label: "HTTPS / 8443", column: 1 },

  { id: "f-c2", label: "203.0.113.47", column: 2, sub: "known C2" },
  { id: "f-exfil", label: "198.51.100.88", column: 2, sub: "exfil sink" },
  { id: "f-dga", label: "Generated domains", column: 2, sub: "61 names" },
  { id: "f-tunnel", label: "192.0.2.77", column: 2, sub: "tunnel authority" },
  { id: "f-unc", label: "203.0.113.91", column: 2, sub: "unclassified" },
  { id: "f-refl", label: "Reflector set", column: 2, sub: "412 sources" },
  { id: "f-backup", label: "198.51.100.140", column: 2, sub: "backup store" },

  { id: "f-cat-c2", label: "C2 Beaconing", column: 3 },
  { id: "f-cat-exfil", label: "Exfiltration", column: 3 },
  { id: "f-cat-dga", label: "DGA / Tunnelling", column: 3 },
  { id: "f-cat-recon", label: "Reconnaissance", column: 3 },
  { id: "f-cat-ddos", label: "DDoS", column: 3 },
  { id: "f-cat-enc", label: "Encrypted anomaly", column: 3 },
  { id: "f-cat-benign", label: "Benign / baseline", column: 3 },
];

export const FLOW_LINKS: FlowLink[] = [
  { source: "f-102315", target: "f-https", mb: 20.6, category: null, label: "8.2 MB baseline + 12.4 MB beacon" },
  { source: "f-102315", target: "f-dns", mb: 0.8, category: "DGA/DNS Tunnelling", label: "61 queries" },
  { source: "f-102315", target: "f-udp", mb: 0.1, category: "Reconnaissance", label: "scan probes" },
  { source: "f-102944", target: "f-https", mb: 0.02, category: "C2 Beaconing", label: "1 historical flow" },
  { source: "f-100520", target: "f-udp", mb: 3100, category: "DDoS", label: "reflected amplification" },
  { source: "f-100520", target: "f-https", mb: 184, category: null, label: "legitimate clients" },
  { source: "f-104733", target: "f-dns", mb: 118, category: "DGA/DNS Tunnelling", label: "TXT tunnel" },
  { source: "f-103271", target: "f-8443", mb: 0.04, category: "Encrypted Malware", label: "self-signed session" },
  { source: "f-102814", target: "f-https", mb: 6200, category: null, label: "scheduled backup" },

  { source: "f-https", target: "f-c2", mb: 12.4, category: "C2 Beaconing", label: "142 beacons" },
  { source: "f-https", target: "f-exfil", mb: 4800, category: "Exfiltration", label: "4.8 GB outbound" },
  { source: "f-https", target: "f-backup", mb: 6200, category: null, label: "known good" },
  { source: "f-https", target: "f-unc", mb: 0.04, category: "Encrypted Malware", label: "1 session" },
  { source: "f-dns", target: "f-dga", mb: 0.8, category: "DGA/DNS Tunnelling", label: "62% NXDOMAIN" },
  { source: "f-dns", target: "f-tunnel", mb: 118, category: "DGA/DNS Tunnelling", label: "2,914 subdomains" },
  { source: "f-udp", target: "f-refl", mb: 3100, category: "DDoS", label: "412 reflectors" },
  { source: "f-udp", target: "f-https", mb: 0.2, category: "Reconnaissance", label: "scan probes" },

  { source: "f-c2", target: "f-cat-c2", mb: 12.4, category: "C2 Beaconing", label: "" },
  { source: "f-exfil", target: "f-cat-exfil", mb: 4800, category: "Exfiltration", label: "" },
  { source: "f-dga", target: "f-cat-dga", mb: 0.8, category: "DGA/DNS Tunnelling", label: "" },
  { source: "f-tunnel", target: "f-cat-dga", mb: 118, category: "DGA/DNS Tunnelling", label: "" },
  { source: "f-unc", target: "f-cat-enc", mb: 0.04, category: "Encrypted Malware", label: "" },
  { source: "f-refl", target: "f-cat-ddos", mb: 3100, category: "DDoS", label: "" },
  { source: "f-backup", target: "f-cat-benign", mb: 6200, category: null, label: "" },
  { source: "f-102315", target: "f-cat-recon", mb: 0.7, category: "Reconnaissance", label: "horizontal scan" },
];

/* ------------------------------ Heatmap ---------------------------- */

/** 24 buckets of 30 minutes, 00:00 → 12:00 UTC. Values are event counts. */
export const HEATMAP_ROWS: { category: Category; values: number[] }[] = [
  {
    category: "DDoS",
    values: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 4, 4, 3],
  },
  {
    category: "C2 Beaconing",
    values: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 3, 3, 4, 3, 3],
  },
  {
    category: "DGA/DNS Tunnelling",
    values: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 3, 4, 2, 1, 1, 1],
  },
  {
    category: "Encrypted Malware",
    values: [0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 2, 1, 1, 1],
  },
  {
    category: "Reconnaissance",
    values: [0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 5, 3, 1, 1, 1, 1, 1],
  },
  {
    category: "Exfiltration",
    values: [1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 5],
  },
];

export const HEATMAP_BUCKETS = Array.from({ length: 24 }, (_, i) => {
  const start = i * 30;
  const hh = String(Math.floor(start / 60)).padStart(2, "0");
  const mm = String(start % 60).padStart(2, "0");
  return { index: i, label: `${hh}:${mm}`, from: start, to: start + 30 };
});

/* --------------------------- Host profile -------------------------- */

export interface HostMetric {
  label: string;
  baseline: number;
  current: number;
  baselineText: string;
  currentText: string;
  unit: string;
}

export interface HostProfile {
  ip: string;
  hostname: string;
  incident: string | null;
  risk: number | null;
  anomaly: number;
  summary: string;
  categories: Category[];
  metrics: HostMetric[];
  note: string;
}

export const HOST_PROFILES: HostProfile[] = [
  {
    ip: "10.2.3.15",
    hostname: "WKS-FIN-015",
    incident: "INC-0417",
    risk: 86,
    anomaly: 92,
    summary: "Internal reconnaissance, algorithmic DNS, periodic beaconing and a 4.8 GB outbound transfer inside 2 h 33 m.",
    categories: ["Reconnaissance", "DGA/DNS Tunnelling", "C2 Beaconing", "Encrypted Malware", "Exfiltration"],
    metrics: [
      { label: "Connection volume", baseline: 18, current: 96, baselineText: "1,240 / h", currentText: "6,820 / h", unit: "flows/h" },
      { label: "DNS activity", baseline: 22, current: 88, baselineText: "42 / h", currentText: "312 / h", unit: "queries/h" },
      { label: "Unique destinations", baseline: 14, current: 78, baselineText: "12 / h", currentText: "268 / h", unit: "endpoints" },
      { label: "Outbound traffic", baseline: 8, current: 100, baselineText: "180 MB / day", currentText: "4.8 GB / 41 min", unit: "volume" },
      { label: "Beaconing periodicity", baseline: 12, current: 93, baselineText: "0.22", currentText: "0.93", unit: "score" },
      { label: "Anomaly level", baseline: 10, current: 92, baselineText: "0.06", currentText: "0.92", unit: "index" },
    ],
    note: "Risk rises from 34 to 86 as five findings accumulate; the retro-hunt raises it to 95.",
  },
  {
    ip: "10.2.9.44",
    hostname: "WKS-HR-044",
    incident: "INC-0419",
    risk: 57,
    anomaly: 41,
    summary: "Single historical contact with the C2 address on 2026-09-28. No other deviation from baseline is visible in metadata.",
    categories: ["C2 Beaconing"],
    metrics: [
      { label: "Connection volume", baseline: 26, current: 34, baselineText: "2,140 / h", currentText: "2,610 / h", unit: "flows/h" },
      { label: "DNS activity", baseline: 30, current: 32, baselineText: "88 / h", currentText: "94 / h", unit: "queries/h" },
      { label: "Unique destinations", baseline: 20, current: 24, baselineText: "18 / h", currentText: "22 / h", unit: "endpoints" },
      { label: "Outbound traffic", baseline: 12, current: 16, baselineText: "220 MB / day", currentText: "268 MB / day", unit: "volume" },
      { label: "Beaconing periodicity", baseline: 14, current: 38, baselineText: "0.19", currentText: "0.41", unit: "score" },
      { label: "Anomaly level", baseline: 10, current: 41, baselineText: "0.06", currentText: "0.41", unit: "index" },
    ],
    note: "Match found only by the retro-hunt. Single 34-second flow, 1.2 KB outbound, no recurrence in 14 days.",
  },
  {
    ip: "10.0.5.20",
    hostname: "WEB-PUB-02",
    incident: "INC-0418",
    risk: 82,
    anomaly: 88,
    summary: "Inbound volume exceeds the 30-day peak by an order of magnitude while request-level behaviour stays unchanged.",
    categories: ["DDoS"],
    metrics: [
      { label: "Connection volume", baseline: 24, current: 100, baselineText: "9,400 / h", currentText: "412,000 / h", unit: "flows/h" },
      { label: "DNS activity", baseline: 18, current: 20, baselineText: "31 / h", currentText: "34 / h", unit: "queries/h" },
      { label: "Unique destinations", baseline: 22, current: 97, baselineText: "1,120 / h", currentText: "18,400 / h", unit: "endpoints" },
      { label: "Outbound traffic", baseline: 30, current: 44, baselineText: "620 MB / h", currentText: "890 MB / h", unit: "volume" },
      { label: "Beaconing periodicity", baseline: 11, current: 12, baselineText: "0.14", currentText: "0.15", unit: "score" },
      { label: "Anomaly level", baseline: 12, current: 88, baselineText: "0.08", currentText: "0.88", unit: "index" },
    ],
    note: "Sources are reflectors or spoofed, so per-source blocking is ineffective. Upstream rate-limiting is recommended.",
  },
  {
    ip: "10.4.7.33",
    hostname: "WKS-LAB-033",
    incident: "INC-0415",
    risk: 61,
    anomaly: 71,
    summary: "DNS response volume is 9.8× baseline and concentrated on a single authority with flat TTLs.",
    categories: ["DGA/DNS Tunnelling"],
    metrics: [
      { label: "Connection volume", baseline: 20, current: 31, baselineText: "980 / h", currentText: "1,540 / h", unit: "flows/h" },
      { label: "DNS activity", baseline: 12, current: 100, baselineText: "44 / h", currentText: "853 / h", unit: "queries/h" },
      { label: "Unique destinations", baseline: 16, current: 19, baselineText: "14 / h", currentText: "16 / h", unit: "endpoints" },
      { label: "Outbound traffic", baseline: 14, current: 62, baselineText: "12 MB / 30 d", currentText: "118 MB / 3 h", unit: "volume" },
      { label: "Beaconing periodicity", baseline: 13, current: 44, baselineText: "0.18", currentText: "0.47", unit: "score" },
      { label: "Anomaly level", baseline: 10, current: 71, baselineText: "0.06", currentText: "0.71", unit: "index" },
    ],
    note: "Channel open since 07:52 UTC. Awaiting confirmation from R&D IT Operations on the instrument integration.",
  },
  {
    ip: "10.3.2.71",
    hostname: "WKS-OPS-071",
    incident: "INC-0409",
    risk: 58,
    anomaly: 54,
    summary: "One anomalous TLS session on a non-standard port. All other metrics remain at baseline.",
    categories: ["Encrypted Malware"],
    metrics: [
      { label: "Connection volume", baseline: 22, current: 25, baselineText: "1,420 / h", currentText: "1,510 / h", unit: "flows/h" },
      { label: "DNS activity", baseline: 19, current: 21, baselineText: "56 / h", currentText: "61 / h", unit: "queries/h" },
      { label: "Unique destinations", baseline: 18, current: 26, baselineText: "16 / h", currentText: "19 / h", unit: "endpoints" },
      { label: "Outbound traffic", baseline: 15, current: 18, baselineText: "180 MB / day", currentText: "196 MB / day", unit: "volume" },
      { label: "Beaconing periodicity", baseline: 12, current: 31, baselineText: "0.16", currentText: "0.34", unit: "score" },
      { label: "Anomaly level", baseline: 9, current: 54, baselineText: "0.05", currentText: "0.54", unit: "index" },
    ],
    note: "Single-session finding. Confidence rests on certificate and early-packet-sequence features only.",
  },
  {
    ip: "10.2.8.14",
    hostname: "SRV-BACKUP-14",
    incident: "INC-0403",
    risk: 44,
    anomaly: 22,
    summary: "Nightly backup window only. Volume is high but the destination and schedule are both known good.",
    categories: ["Exfiltration"],
    metrics: [
      { label: "Connection volume", baseline: 28, current: 36, baselineText: "620 / h", currentText: "780 / h", unit: "flows/h" },
      { label: "DNS activity", baseline: 14, current: 15, baselineText: "12 / h", currentText: "13 / h", unit: "queries/h" },
      { label: "Unique destinations", baseline: 8, current: 9, baselineText: "4 / h", currentText: "5 / h", unit: "endpoints" },
      { label: "Outbound traffic", baseline: 40, current: 88, baselineText: "340 MB / night", currentText: "6.2 GB / 34 min", unit: "volume" },
      { label: "Beaconing periodicity", baseline: 10, current: 11, baselineText: "0.11", currentText: "0.12", unit: "score" },
      { label: "Anomaly level", baseline: 10, current: 22, baselineText: "0.06", currentText: "0.22", unit: "index" },
    ],
    note: "Closed as benign against change record CHG-2291. Baseline exception recorded for 02:00–03:00 UTC.",
  },
  {
    ip: "10.1.9.8",
    hostname: "WKS-ENG-008",
    incident: "INC-0412",
    risk: 38,
    anomaly: 46,
    summary: "Low-rate scan of its own subnet. Volume is below the volumetric threshold but the ordering is machine-generated.",
    categories: ["Reconnaissance"],
    metrics: [
      { label: "Connection volume", baseline: 16, current: 68, baselineText: "420 / h", currentText: "1,760 / h", unit: "flows/h" },
      { label: "DNS activity", baseline: 15, current: 17, baselineText: "22 / h", currentText: "25 / h", unit: "queries/h" },
      { label: "Unique destinations", baseline: 12, current: 74, baselineText: "9 / h", currentText: "96 / h", unit: "endpoints" },
      { label: "Outbound traffic", baseline: 8, current: 14, baselineText: "60 MB / day", currentText: "82 MB / day", unit: "volume" },
      { label: "Beaconing periodicity", baseline: 11, current: 13, baselineText: "0.13", currentText: "0.15", unit: "score" },
      { label: "Anomaly level", baseline: 10, current: 46, baselineText: "0.06", currentText: "0.46", unit: "index" },
    ],
    note: "Engineering runs quarterly internal scans that resemble this pattern. Confirmation requested.",
  },
];

/* ------------------------- Risk annotations ------------------------ */

export interface RiskAnnotation {
  minute: number;
  risk: number;
  label: string;
  finding: string;
  confidence: number;
  contribution: string;
  delta: number;
  historical?: boolean;
}

export const RISK_ANNOTATIONS: RiskAnnotation[] = [
  { minute: 527, risk: 34, label: "Risk 34", finding: "Horizontal scan on 445/tcp", confidence: 0.97, contribution: "Detection evidence +34", delta: 34 },
  { minute: 545, risk: 52, label: "Risk 52", finding: "61 algorithmically generated domains", confidence: 0.89, contribution: "Detection evidence +13, persistence +5", delta: 18 },
  { minute: 571, risk: 71, label: "Risk 71", finding: "Beaconing to 203.0.113.47:443", confidence: 0.88, contribution: "Detection evidence +11, kill-chain progression +8", delta: 19 },
  { minute: 592, risk: 79, label: "Risk 79", finding: "Anomalous encrypted session", confidence: 0.83, contribution: "Detection evidence +6, asset criticality +2", delta: 8 },
  { minute: 680, risk: 86, label: "Risk 86", finding: "4.8 GB outbound transfer", confidence: 0.86, contribution: "Detection evidence +4, kill-chain progression +6", delta: 7 },
  { minute: 722, risk: 95, label: "Risk 95", finding: "Historical indicator match (retro-hunt)", confidence: 0.9, contribution: "Threat-intel match +9", delta: 9, historical: true },
];
