import type { Ioc } from "../lib/types";
import { mulberry32 } from "../lib/utils";

export const SOURCES = [
  "Community C2 tracker (sample)",
  "National CERT advisory (sample)",
  "Malware fingerprint DB (sample)",
  "DGA family list (sample)",
  "Scanner/abuse list (sample)",
];

const DOC_RANGES = ["192.0.2", "198.51.100", "203.0.113"];

function synthDomain(r: () => number, n: number) {
  const chars = "abcdefghijklmnopqrstuvwxyz0123456789";
  const label = Array.from({ length: n }, () => chars[Math.floor(r() * chars.length)]).join("");
  const tld = ["com", "net", "org", "info", "biz"][Math.floor(r() * 5)];
  return `${label}.${tld}`;
}

function synthJa4(r: () => number) {
  const hex = "0123456789abcdef";
  const part = (n: number) =>
    Array.from({ length: n }, () => hex[Math.floor(r() * 16)]).join("");
  return `t13d${1700 + Math.floor(r() * 400)}h2_${part(12)}_${part(12)}`;
}

function synthCert(r: () => number) {
  const hex = "0123456789abcdef";
  return Array.from({ length: 40 }, () => hex[Math.floor(r() * 16)]).join("");
}

/** 60 deterministic synthetic indicators. Age decay: 0.985^(days since last seen). */
export const IOCS: Ioc[] = (() => {
  const r = mulberry32(20260930);
  const rows: Ioc[] = [];
  for (let i = 0; i < 60; i++) {
    const type = (["IPv4", "Domain", "Domain", "JA4", "Cert hash"] as const)[i % 5];
    const source = SOURCES[i % SOURCES.length];
    let indicator = "";
    if (type === "IPv4") {
      const range = DOC_RANGES[i % DOC_RANGES.length];
      indicator = `${range}.${1 + Math.floor(r() * 250)}`;
    } else if (type === "Domain") {
      indicator = synthDomain(r, 8 + Math.floor(r() * 14));
    } else if (type === "JA4") {
      indicator = synthJa4(r);
    } else {
      indicator = synthCert(r);
    }
    const firstDay = 1 + Math.floor(r() * 28);
    const lastDay = Math.min(29, firstDay + Math.floor(r() * 6));
    const firstSeen = `2026-09-${String(firstDay).padStart(2, "0")}`;
    const lastSeen = `2026-09-${String(lastDay).padStart(2, "0")}`;
    const base = Number((0.32 + r() * 0.66).toFixed(2));
    const ageDays = 30 - lastDay;
    const effective = Number(Math.min(0.99, base * Math.pow(0.985, ageDays)).toFixed(2));
    const matches = type === "IPv4" ? Math.floor(r() * 12) : type === "Domain" ? Math.floor(r() * 30) : Math.floor(r() * 5);
    rows.push({
      indicator,
      type,
      source,
      firstSeen,
      lastSeen,
      baseConfidence: base,
      effectiveConfidence: effective,
      matches,
    });
  }
  // Seeded, named indicators that the demo references explicitly.
  rows[0] = {
    indicator: "203.0.113.47",
    type: "IPv4",
    source: "Community C2 tracker (sample)",
    firstSeen: "2026-09-26",
    lastSeen: "2026-09-30",
    baseConfidence: 0.91,
    effectiveConfidence: 0.9,
    matches: 8,
  };
  rows[1] = {
    indicator: "198.51.100.88",
    type: "IPv4",
    source: "Community C2 tracker (sample)",
    firstSeen: "2026-09-29",
    lastSeen: "2026-09-30",
    baseConfidence: 0.86,
    effectiveConfidence: 0.85,
    matches: 38,
  };
  rows[2] = {
    indicator: "t13d1715h2_5b57614c22b0_a1c94e30f7d2",
    type: "JA4",
    source: "Malware fingerprint DB (sample)",
    firstSeen: "2026-09-29",
    lastSeen: "2026-09-30",
    baseConfidence: 0.84,
    effectiveConfidence: 0.83,
    matches: 13,
  };
  rows[3] = {
    indicator: "qx4v8mzt2kd7p1.com",
    type: "Domain",
    source: "DGA family list (sample)",
    firstSeen: "2026-09-28",
    lastSeen: "2026-09-30",
    baseConfidence: 0.79,
    effectiveConfidence: 0.78,
    matches: 4,
  };
  rows[4] = {
    indicator: "m6ryq9ht3zvpwx.com",
    type: "Domain",
    source: "DGA family list (sample)",
    firstSeen: "2026-09-28",
    lastSeen: "2026-09-30",
    baseConfidence: 0.76,
    effectiveConfidence: 0.75,
    matches: 3,
  };
  return rows;
})();

export const TI_BUNDLES = [
  {
    version: "DW-TI-2026-09-28",
    signature: "Verified",
    schema: "Valid",
    iocs: 1204331,
    ageDays: 2,
    imported: "2026-09-28 06:00 UTC",
    status: "Active",
  },
  {
    version: "DW-TI-2026-09-30-B",
    signature: "Verified",
    schema: "Valid",
    iocs: 1842,
    ageDays: 0,
    imported: null as string | null,
    status: "Available for import",
  },
];

export const BUNDLE_DIFF = {
  added: 1842,
  updated: 37,
  expired: 12,
};

export const RETRO_HUNT = {
  id: "RH-2026-09-30-B",
  windowDays: 14,
  flows: 48200000,
  dnsQueries: 2100000,
  tlsSessions: 310000,
  durationS: 96,
  results: [
    {
      indicator: "203.0.113.47",
      type: "IPv4" as const,
      scope: "Flow metadata",
      hits: 7,
      firstContact: "2026-09-27 21:14 UTC",
      entity: "10.2.3.15",
      note: "First contact 2.5 days before behavioural detection of the same address on the same host.",
    },
    {
      indicator: "t13d1715h2_5b57614c22b0_a1c94e30f7d2",
      type: "JA4" as const,
      scope: "TLS session metadata",
      hits: 9,
      firstContact: "2026-09-28 14:22 UTC",
      entity: "10.2.9.44",
      note: "Same fingerprint observed on WKS-HR-044 one day before the INC-0417 C2 session.",
    },
    {
      indicator: "qx4v8mzt2kd7p1.com / m6ryq9ht3zvpwx.com",
      type: "Domain" as const,
      scope: "DNS query log",
      hits: 2,
      firstContact: "2026-09-27 21:11 UTC",
      entity: "10.2.3.15",
      note: "Two of the 61 generated domains queried by 10.2.3.15 are listed in the new bundle.",
    },
  ],
  newLead: {
    incident: "INC-0419",
    entity: "10.2.9.44",
    hostname: "WKS-HR-044",
    detail:
      "10.2.9.44 contacted 203.0.113.47 once on 2026-09-28 14:22 UTC (34 s, 1.2 KB outbound). No recurrence in the scan window.",
  },
};

export const RETRO_HUNT_HISTORY = [
  {
    id: "RH-2026-09-14",
    bundle: "DW-TI-2026-09-14",
    windowDays: 14,
    hits: 11,
    newIncidents: 0,
    completed: "2026-09-14 05:40 UTC",
    outcome: "Matches attributed to already-open incidents; no new leads.",
  },
  {
    id: "RH-2026-09-21",
    bundle: "DW-TI-2026-09-21",
    windowDays: 14,
    hits: 4,
    newIncidents: 0,
    completed: "2026-09-21 05:38 UTC",
    outcome: "Low-confidence scanner matches, reviewed and dismissed.",
  },
];
