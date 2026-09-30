export const OVERVIEW_KPI = {
  activeIncidents: 6,
  criticalHigh: 3,
  findings24h: 14,
  mttdMinutes: 9.4,
  mttdBaselineMinutes: 12.1,
  flowsPerMin: 41280,
  packetsPerSecond: 18420,
  monitoredVlans: 22,
};

export const SEVERITY_DISTRIBUTION = [
  { severity: "Critical", count: 0, color: "#A32020" },
  { severity: "High", count: 2, color: "#C2410C" },
  { severity: "Medium", count: 3, color: "#B7791F" },
  { severity: "Low", count: 1, color: "#3E6B57" },
];

/** Findings per hour by category across the last 24 hours. */
export const FINDINGS_BY_CATEGORY: { hour: string; [k: string]: number | string }[] = (() => {
  const cats = [
    "Reconnaissance",
    "C2 Beaconing",
    "DGA/DNS Tunnelling",
    "Encrypted Malware",
    "Exfiltration",
    "DDoS",
  ];
  const seed = [
    [2, 1, 1, 0, 1, 0],
    [1, 0, 2, 1, 0, 0],
    [3, 1, 0, 0, 0, 1],
    [1, 2, 1, 1, 1, 0],
    [4, 3, 2, 1, 0, 2],
    [2, 1, 3, 0, 1, 1],
    [1, 2, 1, 2, 0, 0],
    [3, 4, 2, 1, 3, 4],
    [2, 1, 1, 0, 1, 0],
    [1, 2, 0, 1, 0, 1],
  ];
  const hours = [
    "2026-09-29 15:00",
    "2026-09-29 18:00",
    "2026-09-29 21:00",
    "2026-09-30 00:00",
    "2026-09-30 03:00",
    "2026-09-30 06:00",
    "2026-09-30 09:00",
    "2026-09-30 12:00",
    "2026-09-30 15:00",
    "2026-09-30 18:00",
  ];
  return seed.map((row, i) => {
    const obj: { hour: string; [k: string]: number | string } = { hour: hours[i].slice(11) };
    cats.forEach((c, j) => (obj[c] = row[j]));
    return obj;
  });
})();

export const DIRECTION_COVERAGE = [
  { direction: "Bidirectional", share: 71, color: "#2F5D9E" },
  { direction: "Client-to-server only", share: 24, color: "#5B6773" },
  { direction: "Server-to-client only", share: 5, color: "#B7791F" },
];

export const ONEWAY_INTEGRITY = {
  captureInterface: "eth1 (mirrored SPAN from core switch pair)",
  mode: "Receive-only (promiscuous, no L3 address)",
  ipAddress: "none",
  txPackets: 0,
  txBytes: 0,
  egressPolicy: "DROP (default-deny outbound on monitoring enclave)",
  activeProbing: "Disabled",
  tlsDecryption: "Not performed",
  handshakes: "None initiated by sensor",
  lastIntegrityCheck: "2026-09-30 11:45:00 UTC",
  diodeModel: "Unidirectional optical gate, 10 Gbps, TX path physically absent",
};

export const SENSOR = {
  name: "sensor-01",
  site: "Enclave A — Monitoring Zone",
  uptime: "61 d 04 h",
  version: "DiodeWatch 2.4.1 (prototype build)",
};

export const CLASS_METRICS = [
  {
    class: "Reconnaissance",
    precision: 0.97,
    recall: 0.94,
    f1: 0.95,
    mttd: "4.2 min",
    fpPerHour: 0.6,
  },
  {
    class: "DDoS",
    precision: 0.95,
    recall: 0.93,
    f1: 0.94,
    mttd: "9.0 min",
    fpPerHour: 0.3,
  },
  {
    class: "C2 Beaconing",
    precision: 0.94,
    recall: 0.92,
    f1: 0.93,
    mttd: "18.6 min",
    fpPerHour: 0.8,
  },
  {
    class: "DGA/DNS Tunnelling",
    precision: 0.93,
    recall: 0.91,
    f1: 0.92,
    mttd: "12.4 min",
    fpPerHour: 1.1,
  },
  {
    class: "Encrypted Malware",
    precision: 0.88,
    recall: 0.82,
    f1: 0.85,
    mttd: "22.1 min",
    fpPerHour: 1.4,
  },
  {
    class: "Exfiltration",
    precision: 0.9,
    recall: 0.84,
    f1: 0.87,
    mttd: "26.8 min",
    fpPerHour: 0.9,
  },
];

export const DIRECTION_COMPARISON = [
  {
    class: "Reconnaissance",
    bi: 0.97,
    uni: 0.91,
    note: "Direction-tolerant flow symmetry still separates scans, but one-way views lose half-open state.",
  },
  {
    class: "DDoS",
    bi: 0.95,
    uni: 0.92,
    note: "Volumetric features survive; SYN:ACK ratio and half-open counts degrade without return traffic.",
  },
  {
    class: "C2 Beaconing",
    bi: 0.94,
    uni: 0.9,
    note: "Beacon interval and payload size are still visible; jitter correlation across both legs is lost.",
  },
  {
    class: "DGA/DNS Tunnelling",
    bi: 0.93,
    uni: 0.88,
    note: "Query-side entropy is intact, response size and NXDOMAIN ratio are only partly observable.",
  },
  {
    class: "Encrypted Malware",
    bi: 0.88,
    uni: 0.84,
    note: "Early-packet-sequence features rely on packet ordering in both directions.",
  },
  {
    class: "Exfiltration",
    bi: 0.9,
    uni: 0.82,
    note: "Upload:download ratio and baseline comparison require the return leg.",
  },
];

export const CONSTRAINTS = [
  { label: "Transmit", allowed: false, detail: "Sensor interface has no IP address and no TX path; egress policy DROP." },
  { label: "Active probing", allowed: false, detail: "No packets are sent to monitored or external hosts." },
  { label: "Handshakes", allowed: false, detail: "No TCP, TLS or DNS sessions are initiated by the sensor." },
  { label: "TLS decryption", allowed: false, detail: "Session metadata and JA4 fingerprints only; payloads stay encrypted." },
  { label: "Live lookups", allowed: false, detail: "Threat intel is a signed local bundle; no online reputation queries." },
  { label: "Mitigation push", allowed: false, detail: "DiodeWatch recommends and exports. Enforcement is an external process." },
];

export const NOT_CLAIMED = [
  "Blocking, prevention, quarantine or reset of any host, session or flow.",
  "Payload inspection, content reconstruction or file recovery.",
  "Attribution to a named actor, group or state.",
  "Confirmation that any recommended action was applied or was effective.",
  "Complete visibility: 29% of observed flows carry a single direction only.",
];

export const DETECTOR_INVENTORY = [
  { name: "SIG-RECON-HSCAN-445 v2.4", type: "Rule", category: "Reconnaissance", enabled: true },
  { name: "dga-lstm-v3.1", type: "Model", category: "DGA/DNS Tunnelling", enabled: true },
  { name: "beacon-periodicity-v2.7", type: "Model", category: "C2 Beaconing", enabled: true },
  { name: "tls-eps-v1.9", type: "Model", category: "Encrypted Malware", enabled: true },
  { name: "exfil-volume-v2.2", type: "Model", category: "Exfiltration", enabled: true },
  { name: "SIG-DDOS-UDP-REFLECT v3.1", type: "Rule", category: "DDoS", enabled: true },
  { name: "SIG-DDOS-SYNFLOOD v2.8", type: "Rule", category: "DDoS", enabled: true },
  { name: "SIG-DNS-TUNNEL-TXT v2.1", type: "Rule", category: "DGA/DNS Tunnelling", enabled: true },
];
