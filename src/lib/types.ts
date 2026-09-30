export type Severity = "Critical" | "High" | "Medium" | "Low" | "Info";

export type Category =
  | "Reconnaissance"
  | "C2 Beaconing"
  | "DGA/DNS Tunnelling"
  | "Encrypted Malware"
  | "Exfiltration"
  | "DDoS";

export type IncidentStatus = "Open" | "Investigating" | "Resolved";

export type Direction = "client-to-server" | "server-to-client" | "bidirectional";

export interface Asset {
  ip: string;
  hostname: string;
  vlan: string;
  department: string;
  criticality: "Critical" | "High" | "Medium" | "Low";
  os: string;
  owner: string;
}

export interface FeatureRow {
  feature: string;
  value: string;
  threshold: string;
  baseline: string;
  verdict: "above" | "below" | "match" | "neutral";
  note?: string;
}

export interface Finding {
  id: string;
  ts: string; // ISO UTC
  category: Category;
  title: string;
  detail: string;
  detector: string;
  direction: Direction;
  confidence: number;
  risk: number; // cumulative incident risk after this finding
  severity: Severity;
  features: FeatureRow[];
  chart?: "iat" | "entropy" | "packet" | "volume";
  evidenceRefs: string[];
}

export interface KillChainStage {
  stage: string;
  ts: string | null;
  detail: string;
}

export interface RiskContribution {
  label: string;
  value: number;
  reason: string;
}

export interface RecommendedAction {
  id: string;
  group: "Immediate" | "Short-term" | "Hardening";
  text: string;
  rationale: string;
  artifactType?: ArtifactType;
}

export interface DnsRecord {
  ts: string;
  query: string;
  type: string;
  response: string;
  entropy: number;
  nxdomain: boolean;
  length: number;
}

export interface TlsRecord {
  ts: string;
  src: string;
  dst: string;
  sni: string;
  ja4: string;
  ja4s: string;
  alpn: string;
  certSubject: string;
  certIssuer: string;
  certValidityDays: number;
  selfSigned: boolean;
  epsScore: number;
  bytes: number;
}

export interface FlowRecord {
  ts: string;
  src: string;
  srcPort: number;
  dst: string;
  dstPort: number;
  proto: string;
  packets: number;
  bytes: number;
  direction: Direction;
  durationS: number;
  tags: string[];
}

export interface TiMatch {
  indicator: string;
  type: "IPv4" | "Domain" | "JA4" | "Cert hash";
  source: string;
  firstSeen: string;
  confidence: number;
  context: string;
  origin: "bundle" | "retro-hunt";
}

export interface Incident {
  id: string;
  entity: string;
  hostname: string | null;
  title: string;
  summary: string;
  category: Category;
  severity: Severity;
  risk: number;
  baseRisk: number;
  status: IncidentStatus;
  confidence: number;
  firstSeen: string;
  lastSeen: string;
  killChain: KillChainStage[];
  findings: Finding[];
  riskHistory: { ts: string; risk: number; label: string }[];
  riskBreakdown: RiskContribution[];
  dns: DnsRecord[];
  tls: TlsRecord[];
  flows: FlowRecord[];
  tiMatches: TiMatch[];
  recommendedActions: RecommendedAction[];
  notes: { author: string; ts: string; text: string }[];
  hiddenUntilRetroHunt?: boolean;
  createdByRetroHunt?: boolean;
}

export type ArtifactType =
  | "IOC block list"
  | "Firewall rules (nftables)"
  | "DNS sinkhole / RPZ"
  | "Host isolation request"
  | "DDoS rate-limit / RTBH request";

export type ArtifactState = "Proposed" | "Approved" | "Exported";

export interface Artifact {
  id: string;
  incidentId: string;
  type: ArtifactType;
  title: string;
  state: ArtifactState;
  created: string;
  sha256: string | null;
  approvedBy: string | null;
  approvedAt: string | null;
  exportedAt: string | null;
  blastRadius: string;
  rollback: string;
  content: string;
}

export interface Ioc {
  indicator: string;
  type: "IPv4" | "Domain" | "JA4" | "Cert hash";
  source: string;
  firstSeen: string;
  lastSeen: string;
  baseConfidence: number;
  effectiveConfidence: number;
  matches: number;
}

export interface EvidenceRecord {
  index: number;
  recordType: string;
  ts: string;
  ref: string;
  content: string;
  prevHash: string;
  hash: string;
  status: "Verified" | "Pending" | "Broken" | "Unverified";
}

export interface LiveFlowRow {
  id: number;
  ts: string;
  src: string;
  srcPort: number;
  dst: string;
  dstPort: number;
  proto: string;
  bytes: number;
  packets: number;
  direction: Direction;
  tags: string[];
  injected?: Category;
}
