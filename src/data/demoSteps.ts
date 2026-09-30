export interface DemoStep {
  n: number;
  title: string;
  path: string;
  target: string;
  instruction: string;
  action?: "visibility-one" | "select-0418" | "select-0417" | "import-retrohunt" | "mitigation" | "report-verify" | "tamper";
}

export const DEMO_STEPS: DemoStep[] = [
  {
    n: 1,
    title: "Overview and receive-only status",
    path: "/",
    target: "overview-status",
    instruction:
      "DiodeWatch observes a mirrored, read-only copy of traffic. The status pill is persistent: TX 0 packets, egress policy DROP. Nothing on this screen is sent back to the monitored network.",
  },
  {
    n: 2,
    title: "Live Monitor",
    path: "/live",
    target: "live-table",
    instruction:
      "Streaming flow records from the mirrored tap. Each row carries an observed direction. Injected finding rows are marked with a category dot; detection runs on metadata only.",
  },
  {
    n: 3,
    title: "INC-0417 timeline and risk building",
    path: "/incidents",
    target: "risk-timeline",
    instruction:
      "One incident, five findings. Risk steps from 34 to 86 as reconnaissance, DGA activity, C2 beaconing, an anomalous TLS session and a 4.8 GB outbound transfer accumulate on the same host.",
    action: "select-0417",
  },
  {
    n: 4,
    title: "Evidence and why this score",
    path: "/incidents",
    target: "why-score",
    instruction:
      "Every score contribution is itemised with its reason. Feature tables show observed value against threshold and 30-day baseline for each finding.",
  },
  {
    n: 5,
    title: "One-direction visibility mode",
    path: "/live",
    target: "visibility-toggle",
    instruction:
      "Switch to one-direction visibility. Reverse-direction flows are dimmed, direction coverage changes, and detectors fall back to direction-tolerant features — beaconing confidence moves from 0.88 to 0.81, exfiltration from 0.86 to 0.79.",
    action: "visibility-one",
  },
  {
    n: 6,
    title: "DDoS incident INC-0418",
    path: "/incidents",
    target: "ddos-note",
    instruction:
      "UDP reflection plus SYN flood against the public web server. Sources are reflectors or spoofed, so per-source blocking is ineffective; upstream rate-limiting is the recommended response.",
    action: "select-0418",
  },
  {
    n: 7,
    title: "Import bundle and run the retro-hunt",
    path: "/intel",
    target: "import-bundle",
    instruction:
      "Import the signed bundle DW-TI-2026-09-30-B. Verification steps run in sequence, then a retro-hunt scans 14 days of stored metadata: 48.2M flows, 2.1M DNS queries, 310K TLS sessions.",
    action: "import-retrohunt",
  },
  {
    n: 8,
    title: "Map: where the campaign points",
    path: "/visualization",
    target: "activity-map",
    instruction:
      "The C2 address and 23 DGA resolution targets share one /24 announced from EU-Central; the 4.8 GB transfer went to NA-East, a region with no approved data-transfer relationship. The retro-hunt contact from 10.2.9.44 now appears as a dashed arc. Regions come from the local bundle enrichment — no attribution is implied.",
    action: "select-0417",
  },
  {
    n: 9,
    title: "Risk 86 to 95 and a new incident",
    path: "/incidents",
    target: "incident-header",
    instruction:
      "The retro-hunt adds a threat-intel match of 9 to INC-0417, raising risk to 95 (Critical), and creates INC-0419: WKS-HR-044 contacted the same C2 address once on 2026-09-28.",
    action: "select-0417",
  },
  {
    n: 10,
    title: "Generate, approve and export a mitigation package",
    path: "/response",
    target: "artifact-table",
    instruction:
      "The response advisor proposes artifacts with blast-radius and rollback notes. Approval records who and when. Export hands the file to the out-of-band change process — DiodeWatch cannot confirm enforcement.",
    action: "mitigation",
  },
  {
    n: 11,
    title: "Forensic report and evidence chain",
    path: "/response",
    target: "evidence-panel",
    instruction:
      "The forensic report previews on screen and downloads as a file. Verify chain recomputes real SHA-256 digests in the browser and walks the records row by row.",
    action: "report-verify",
  },
  {
    n: 12,
    title: "Simulate tampering and observe the failure",
    path: "/trust",
    target: "trust-boundary",
    instruction:
      "The demo control alters one record. Verification then fails at that record and flags every later record as chain broken. This is the trust boundary: detection and advice inside the enclave, enforcement outside it.",
    action: "tamper",
  },
];
