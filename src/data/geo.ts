import type { Category } from "../lib/types";

/* ------------------------------------------------------------------ *
 * Network activity map — seeded geographic associations.
 *
 * Geography in DiodeWatch comes from the ASN / prefix dataset shipped
 * inside the signed threat-intel bundle. There are no live lookups.
 * External addresses in this demo are documentation ranges and carry
 * SYNTHETIC hosting-region associations. Regions are cloud-style hosting
 * regions, not countries; a hosting region says where rented
 * infrastructure is announced from, not who operates it.
 * ------------------------------------------------------------------ */

export type PolicyStatus = "approved" | "no-relationship" | "site" | "not-applicable";

export interface GeoRegion {
  id: string;
  label: string;
  lon: number;
  lat: number;
  policy: PolicyStatus;
  policyText: string;
}

export const GEO_REGIONS: GeoRegion[] = [
  { id: "site", label: "Site A — monitored network", lon: 77.2, lat: 28.6, policy: "site", policyText: "Monitored site. All internal assets and the receive-only sensor are here." },
  { id: "ap-south", label: "AP-South", lon: 76.0, lat: 12.5, policy: "approved", policyText: "Approved data-transfer region (in-region backup and service providers)." },
  { id: "eu-central", label: "EU-Central", lon: 8.7, lat: 50.1, policy: "no-relationship", policyText: "No approved data-transfer relationship with this hosting region." },
  { id: "eu-west", label: "EU-West", lon: -6.3, lat: 53.3, policy: "no-relationship", policyText: "No approved data-transfer relationship with this hosting region." },
  { id: "na-east", label: "NA-East", lon: -77.0, lat: 39.0, policy: "no-relationship", policyText: "No approved data-transfer relationship with this hosting region." },
  { id: "na-west", label: "NA-West", lon: -122.0, lat: 37.4, policy: "no-relationship", policyText: "No approved data-transfer relationship with this hosting region." },
  { id: "ap-southeast", label: "AP-Southeast", lon: 103.8, lat: 1.35, policy: "no-relationship", policyText: "No approved data-transfer relationship with this hosting region." },
  { id: "ap-northeast", label: "AP-Northeast", lon: 139.7, lat: 35.7, policy: "no-relationship", policyText: "No approved data-transfer relationship with this hosting region." },
  { id: "sa-east", label: "SA-East", lon: -46.6, lat: -23.5, policy: "no-relationship", policyText: "No approved data-transfer relationship with this hosting region." },
];

export interface GeoEntity {
  id: string;
  graphNodeId?: string;
  label: string;
  sub: string;
  regionId: string;
  category: Category | null;
  incidents: string[];
  asn: string;
  prefix: string;
  flows: number;
  mb: number;
  firstSeen: string;
  lastSeen: string;
  suspicious: boolean;
  note: string;
  retroHuntOnly?: boolean;
}

export const GEO_ENTITIES: GeoEntity[] = [
  {
    id: "c2",
    graphNodeId: "203.0.113.47",
    label: "203.0.113.47",
    sub: "known C2 address",
    regionId: "eu-central",
    category: "C2 Beaconing",
    incidents: ["INC-0417", "INC-0419"],
    asn: "AS64496 (synthetic hosting)",
    prefix: "203.0.113.0/24",
    flows: 142,
    mb: 12.4,
    firstSeen: "2026-09-27 21:14 UTC",
    lastSeen: "2026-09-30 11:53 UTC",
    suspicious: true,
    note: "Beacon target for WKS-FIN-015. Listed in bundle DW-TI-2026-09-30-B at 0.91 base confidence. Also contacted once by 10.2.9.44 on 2026-09-28.",
  },
  {
    id: "dga-targets",
    graphNodeId: "gen-domains",
    label: "203.0.113.20–39",
    sub: "DGA resolution targets",
    regionId: "eu-central",
    category: "DGA/DNS Tunnelling",
    incidents: ["INC-0417"],
    asn: "AS64496 (synthetic hosting)",
    prefix: "203.0.113.0/24",
    flows: 61,
    mb: 0.38,
    firstSeen: "2026-09-30 09:05 UTC",
    lastSeen: "2026-09-30 09:27 UTC",
    suspicious: true,
    note: "23 of 61 generated domains resolved into the same /24 as the C2 address; the rest returned NXDOMAIN.",
  },
  {
    id: "unclassified",
    graphNodeId: "203.0.113.91",
    label: "203.0.113.91",
    sub: "unclassified host",
    regionId: "eu-central",
    category: "Encrypted Malware",
    incidents: ["INC-0409"],
    asn: "AS64496 (synthetic hosting)",
    prefix: "203.0.113.0/24",
    flows: 1,
    mb: 0.04,
    firstSeen: "2026-09-30 06:38 UTC",
    lastSeen: "2026-09-30 06:41 UTC",
    suspicious: true,
    note: "Single self-signed TLS session from WKS-OPS-071. Same /24 as the known C2 address; no confirmed relation.",
  },
  {
    id: "exfil-sink",
    graphNodeId: "198.51.100.88",
    label: "198.51.100.88",
    sub: "exfiltration sink",
    regionId: "na-east",
    category: "Exfiltration",
    incidents: ["INC-0417"],
    asn: "AS64497 (synthetic hosting)",
    prefix: "198.51.100.0/24",
    flows: 38,
    mb: 4800,
    firstSeen: "2026-09-30 11:20 UTC",
    lastSeen: "2026-09-30 12:01 UTC",
    suspicious: true,
    note: "4.8 GB outbound in 41 minutes. Destination never observed before today; region has no approved data-transfer relationship.",
  },
  {
    id: "tunnel-authority",
    graphNodeId: "192.0.2.77",
    label: "192.0.2.77",
    sub: "tunnel authority",
    regionId: "ap-southeast",
    category: "DGA/DNS Tunnelling",
    incidents: ["INC-0415"],
    asn: "AS64499 (synthetic hosting)",
    prefix: "192.0.2.0/24",
    flows: 3412,
    mb: 118,
    firstSeen: "2026-09-30 07:52 UTC",
    lastSeen: "2026-09-30 11:44 UTC",
    suspicious: true,
    note: "Authoritative name server for ns-tunnel.example.invalid. 118 MB estimated over TXT records.",
  },
  {
    id: "backup-store",
    graphNodeId: "198.51.100.140",
    label: "198.51.100.140",
    sub: "backup store (approved)",
    regionId: "ap-south",
    category: null,
    incidents: ["INC-0403"],
    asn: "AS64500 (synthetic provider)",
    prefix: "198.51.100.128/25",
    flows: 28,
    mb: 6200,
    firstSeen: "2026-07-31 02:00 UTC",
    lastSeen: "2026-09-30 02:48 UTC",
    suspicious: false,
    note: "Approved nightly backup destination, seen on 61 consecutive nights. Stays inside the approved region.",
  },
  ...(
    [
      ["na-east", 96],
      ["eu-west", 88],
      ["ap-southeast", 71],
      ["eu-central", 63],
      ["na-west", 41],
      ["ap-northeast", 34],
      ["sa-east", 19],
    ] as [string, number][]
  ).map<GeoEntity>(([regionId, n]) => ({
    id: `refl-${regionId}`,
    graphNodeId: "reflector-set",
    label: `Reflectors — ${GEO_REGIONS.find((r) => r.id === regionId)!.label}`,
    sub: `${n} open resolvers`,
    regionId,
    category: "DDoS",
    incidents: ["INC-0418"],
    asn: "mixed (third-party resolvers)",
    prefix: "mixed",
    flows: n,
    mb: Math.round((3100 * n) / 412),
    firstSeen: "2026-09-30 10:12 UTC",
    lastSeen: "2026-09-30 11:58 UTC",
    suspicious: true,
    note: "Third-party DNS, NTP and memcached resolvers returning amplified responses to a spoofed victim address. Not attacker infrastructure.",
  })),
];

export interface GeoLink {
  id: string;
  entityId: string;
  host: string;
  inbound: boolean;
  category: Category | null;
  incident: string;
  mb: number;
  flows: number;
  direction: "client-to-server" | "server-to-client" | "both";
  label: string;
  retroHuntOnly?: boolean;
  suspicious: boolean;
}

export const GEO_LINKS: GeoLink[] = [
  { id: "g1", entityId: "c2", host: "10.2.3.15", inbound: false, category: "C2 Beaconing", incident: "INC-0417", mb: 12.4, flows: 142, direction: "both", label: "10.2.3.15 → 203.0.113.47:443 · 142 beacons", suspicious: true },
  { id: "g2", entityId: "dga-targets", host: "10.2.3.15", inbound: false, category: "DGA/DNS Tunnelling", incident: "INC-0417", mb: 0.38, flows: 61, direction: "both", label: "10.2.3.15 → 61 generated domains", suspicious: true },
  { id: "g3", entityId: "exfil-sink", host: "10.2.3.15", inbound: false, category: "Exfiltration", incident: "INC-0417", mb: 4800, flows: 38, direction: "client-to-server", label: "10.2.3.15 → 198.51.100.88:443 · 4.8 GB", suspicious: true },
  { id: "g4", entityId: "c2", host: "10.2.9.44", inbound: false, category: "C2 Beaconing", incident: "INC-0419", mb: 0.02, flows: 1, direction: "client-to-server", label: "10.2.9.44 → 203.0.113.47:443 · 1 historical flow", retroHuntOnly: true, suspicious: true },
  { id: "g5", entityId: "unclassified", host: "10.3.2.71", inbound: false, category: "Encrypted Malware", incident: "INC-0409", mb: 0.04, flows: 1, direction: "both", label: "10.3.2.71 → 203.0.113.91:8443 · 1 session", suspicious: true },
  { id: "g6", entityId: "tunnel-authority", host: "10.4.7.33", inbound: false, category: "DGA/DNS Tunnelling", incident: "INC-0415", mb: 118, flows: 3412, direction: "both", label: "10.4.7.33 → 192.0.2.77:53 · TXT tunnel", suspicious: true },
  { id: "g7", entityId: "backup-store", host: "10.2.8.14", inbound: false, category: null, incident: "INC-0403", mb: 6200, flows: 28, direction: "client-to-server", label: "10.2.8.14 → 198.51.100.140:443 · scheduled backup", suspicious: false },
  ...(["na-east", "eu-west", "ap-southeast", "eu-central", "na-west", "ap-northeast", "sa-east"] as const).map<GeoLink>((r) => {
    const e = GEO_ENTITIES.find((x) => x.id === `refl-${r}`)!;
    return {
      id: `g-refl-${r}`,
      entityId: e.id,
      host: "10.0.5.20",
      inbound: true,
      category: "DDoS",
      incident: "INC-0418",
      mb: e.mb,
      flows: e.flows,
      direction: "server-to-client",
      label: `${e.flows} reflectors → 10.0.5.20 · amplified UDP`,
      suspicious: true,
    };
  }),
];

/** Activity that cannot be placed on a map, stated explicitly. */
export const NOT_PLOTTED = [
  {
    label: "SYN flood sources",
    detail: "Spoofed source addresses (entropy 7.9 bits, 91% single-packet). Geography is not meaningful and is not shown.",
    incident: "INC-0418",
  },
  {
    label: "Internal scans",
    detail: "10.2.3.0/24 (254 hosts) and 10.1.9.0/24 (96 hosts) are inside Site A. Listed under the site marker.",
    incident: "INC-0417 / INC-0412",
  },
  {
    label: "Public web clients",
    detail: "1,240 baseline flows to WEB-PUB-02 from many regions. Aggregated, not plotted per client.",
    incident: "baseline",
  },
];

export const MAP_INSIGHTS: { incident: string | null; text: string }[] = [
  { incident: "INC-0417", text: "4.8 GB left Site A for NA-East, a region with no approved data-transfer relationship, 1 h 49 m after the first C2 beacon." },
  { incident: "INC-0417", text: "The C2 address and 23 DGA resolution targets sit in one /24 announced from EU-Central — rented infrastructure under one operator, not a country." },
  { incident: "INC-0418", text: "412 reflectors span 7 hosting regions. A single-source explanation is excluded; upstream rate-limiting is the effective control." },
  { incident: "INC-0409", text: "203.0.113.91 shares the C2 /24 in EU-Central. The relation is unconfirmed and is recorded as a lead, not a finding." },
  { incident: "INC-0415", text: "The TXT tunnel terminates at a single authority in AP-Southeast; all 3,412 queries go to one address." },
  { incident: "INC-0403", text: "The only approved external transfer (6.2 GB backup) stays inside the approved AP-South region." },
  { incident: null, text: "Region association comes from the bundle's local ASN/prefix dataset. No live lookups; no attribution to a state or actor is implied." },
];
