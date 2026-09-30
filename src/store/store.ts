import { create } from "zustand";
import type {
  Artifact,
  ArtifactType,
  EvidenceRecord,
  Incident,
  IncidentStatus,
} from "../lib/types";
import { INCIDENTS } from "../data/incidents";
import { EVIDENCE_SEED } from "../data/evidence";
import { sha256, riskSeverity } from "../lib/utils";

export type VisibilityMode = "both" | "one";
export type RetroHuntStatus = "idle" | "importing" | "scanning" | "complete";

export interface LogEntry {
  id: number;
  ts: string;
  text: string;
}

export interface DemoState {
  incidents: Incident[];
  selectedIncidentId: string;
  search: string;
  filterSeverity: string;
  filterStatus: string;
  filterCategory: string;
  bundleImported: boolean;
  retroHuntStatus: RetroHuntStatus;
  retroHuntProgress: number;
  retroHuntScanLine: string;
  artifacts: Artifact[];
  evidence: EvidenceRecord[];
  chainVerified: boolean;
  tampered: boolean;
  verifying: boolean;
  verifyIndex: number;
  visibilityMode: VisibilityMode;
  guidedOpen: boolean;
  demoStep: number;
  highlight: string | null;
  log: LogEntry[];
  reportIncidentId: string | null;
  tiTab: string;
  toast: string | null;

  setSelected: (id: string) => void;
  setSearch: (s: string) => void;
  setFilter: (k: "severity" | "status" | "category", v: string) => void;
  setStatus: (id: string, status: IncidentStatus) => void;
  addNote: (id: string, text: string) => void;
  setVisibility: (m: VisibilityMode) => void;
  setGuidedOpen: (o: boolean) => void;
  setDemoStep: (n: number) => void;
  setHighlight: (h: string | null) => void;
  setTiTab: (t: string) => void;
  setToast: (t: string | null) => void;
  generateArtifact: (incidentId: string, type: ArtifactType) => Promise<Artifact | null>;
  approveArtifact: (id: string) => void;
  exportArtifact: (id: string) => void;
  verifyChain: () => Promise<void>;
  simulateTamper: () => void;
  restoreChain: () => void;
  importBundle: () => Promise<void>;
  runRetroHunt: () => Promise<void>;
  setReportIncident: (id: string | null) => void;
  resetDemo: () => void;
  pushLog: (text: string) => void;
}

function artifactContent(a: {
  id: string;
  incidentId: string;
  type: ArtifactType;
  entity: string;
  hostname: string;
  created: string;
}): string {
  const head = `# DiodeWatch mitigation package
# Status: Proposed — hand to the out-of-band change process
# Incident: ${a.incidentId}   Entity: ${a.entity} (${a.hostname})
# Artifact: ${a.id}   Generated: ${a.created}
# DiodeWatch is receive-only. Nothing in this file has been applied.

`;
  switch (a.type) {
    case "IOC block list":
      return `${head}# Indicators for review by the authorised change process
203.0.113.47
198.51.100.88
t13d1715h2_5b57614c22b0_a1c94e30f7d2
qx4v8mzt2kd7p1.com
m6ryq9ht3zvpwx.com
`;
    case "Firewall rules (nftables)":
      return `${head}table inet dw_mit_${a.incidentId.toLowerCase().replace("-", "")} {
    chain egress_filter {
        type filter hook output priority 0; policy accept;
        ip daddr 203.0.113.47 drop comment "DW ${a.incidentId} C2"
        ip daddr 198.51.100.88 drop comment "DW ${a.incidentId} exfil"
        tcp dport 8443 drop comment "DW ${a.incidentId} non-standard TLS"
    }
}
`;
    case "DNS sinkhole / RPZ":
      return `${head}$TTL 300
@ IN SOA ns.diode.local. soc.diode.local. 2026093001 3600 600 86400 300
@ IN NS ns.diode.local.

; Generated from INC-0417 finding F-0417-02 (61 domains, 12 listed)
qx4v8mzt2kd7p1.com CNAME .
m6ryq9ht3zvpwx.com CNAME .
h7nb3wry6sq9zc.net CNAME .
5jfd8kqp2xvtnl.org CNAME .
z9wt3cbn6mryqh.info CNAME .
2kxv7dpl8nzwmq.biz CNAME .
t8nzc4wdl6kqxv.net CNAME .
4bvh2jms7qplrd.org CNAME .
r3qzk9wxc6mtnv.info CNAME .
6ydph5nxb8tqzj.com CNAME .
w2mkv7bqz4xtrn.net CNAME .
8sltc3pjq9nwvz.org CNAME .
`;
    case "Host isolation request":
      return `${head}HOST ISOLATION REQUEST
---------------------
Requested by : DiodeWatch response advisor (recommendation only)
Target host  : ${a.hostname} (${a.entity})
Incident     : ${a.incidentId}
Action       : Move host to remediation VLAN, retain capture-only uplink
Justification: Confirmed C2 beaconing and active outbound transfer.
Authorisation: Required from asset owner and network operations.
Note         : DiodeWatch cannot execute this action; no return path exists.
`;
    case "DDoS rate-limit / RTBH request":
      return `${head}UPSTREAM RATE-LIMIT / RTBH REQUEST
----------------------------------
Victim        : ${a.hostname} (${a.entity})
Incident      : ${a.incidentId}
Observed      : UDP reflection, 412 reflectors, peak 3.1 Gbps equivalent
                SYN flood, SYN:ACK 14:1, 91% single-packet sources
Requested     : Upstream absorption / rate-limit for inbound to ${a.entity}
Source blocking: NOT recommended. Reflectors are third-party resolvers and
                sources are spoofed; per-source filtering is ineffective.
`;
    default:
      return head;
  }
}

const INITIAL_ARTIFACTS: Artifact[] = [
  {
    id: "ART-001",
    incidentId: "INC-0418",
    type: "DDoS rate-limit / RTBH request",
    title: "Upstream absorption request for WEB-PUB-02",
    state: "Exported",
    created: "2026-09-30T10:18:00Z",
    sha256: null,
    approvedBy: "Analyst | SOC-1",
    approvedAt: "2026-09-30T10:20:14Z",
    exportedAt: "2026-09-30T10:26:41Z",
    blastRadius:
      "Applies to inbound traffic for 10.0.5.20 only. Reflector ranges may include shared DNS resolvers; verify before blocking.",
    rollback:
      "Rate-limit can be withdrawn by the upstream provider; no sensor-side state is modified.",
    content: "",
  },
  {
    id: "ART-002",
    incidentId: "INC-0418",
    type: "IOC block list",
    title: "Reflector range review list (3 of 412 addresses)",
    state: "Proposed",
    created: "2026-09-30T10:44:00Z",
    sha256: null,
    approvedBy: null,
    approvedAt: null,
    exportedAt: null,
    blastRadius:
      "Reflector ranges may include shared DNS resolvers; verify before blocking. Blocking is not recommended at this time.",
    rollback: "Removal of entries restores previous policy.",
    content: "",
  },
  {
    id: "ART-003",
    incidentId: "INC-0415",
    type: "DNS sinkhole / RPZ",
    title: "Sinkhole for ns-tunnel.example.invalid",
    state: "Proposed",
    created: "2026-09-30T09:22:00Z",
    sha256: null,
    approvedBy: null,
    approvedAt: null,
    exportedAt: null,
    blastRadius:
      "Single authority. Collateral risk low, pending confirmation from R&D IT Operations.",
    rollback: "RPZ entries can be withdrawn individually.",
    content: "",
  },
  {
    id: "ART-004",
    incidentId: "INC-0403",
    type: "Firewall rules (nftables)",
    title: "Backup window exception documentation",
    state: "Approved",
    created: "2026-09-30T03:30:00Z",
    sha256: null,
    approvedBy: "Analyst | SOC-1",
    approvedAt: "2026-09-30T03:41:09Z",
    exportedAt: null,
    blastRadius: "Documentation-only change; no traffic path is altered by this artifact.",
    rollback: "Withdraw the exception record from the baseline store.",
    content: "",
  },
];

function withContent(a: Artifact): Artifact {
  const inc = INCIDENTS.find((i) => i.id === a.incidentId);
  return {
    ...a,
    content: artifactContent({
      id: a.id,
      incidentId: a.incidentId,
      type: a.type,
      entity: inc?.entity ?? "unknown",
      hostname: inc?.hostname ?? "unknown",
      created: a.created.replace("T", " ").replace("Z", " UTC"),
    }),
  };
}

export const INITIAL_ARTIFACTS_WITH_CONTENT: Artifact[] = INITIAL_ARTIFACTS.map(withContent);

export async function buildEvidence(): Promise<EvidenceRecord[]> {
  const out: EvidenceRecord[] = [];
  let prev = "0000000000000000000000000000000000000000000000000000000000000000";
  for (const rec of EVIDENCE_SEED) {
    const hash = await sha256(`${prev}|${rec.content}`);
    out.push({ ...rec, content: rec.content, prevHash: prev, hash, status: "Pending" });
    prev = hash;
  }
  return out;
}

const NOW = "2026-09-30T12:00:00Z";

export const useDemo = create<DemoState>((set, get) => ({
  incidents: INCIDENTS,
  selectedIncidentId: "INC-0417",
  search: "",
  filterSeverity: "all",
  filterStatus: "all",
  filterCategory: "all",
  bundleImported: false,
  retroHuntStatus: "idle",
  retroHuntProgress: 0,
  retroHuntScanLine: "",
  artifacts: INITIAL_ARTIFACTS_WITH_CONTENT,
  evidence: [],
  chainVerified: false,
  tampered: false,
  verifying: false,
  verifyIndex: 0,
  visibilityMode: "both",
  guidedOpen: false,
  demoStep: 0,
  highlight: null,
  log: [
    { id: 1, ts: "2026-09-30T08:47:20Z", text: "Finding F-0417-01 recorded for INC-0417 (reconnaissance)." },
    { id: 2, ts: "2026-09-30T09:31:12Z", text: "Finding F-0417-03 recorded for INC-0417 (C2 beaconing)." },
    { id: 3, ts: "2026-09-30T11:20:51Z", text: "Finding F-0417-05 recorded for INC-0417 (exfiltration). Risk 86." },
    { id: 4, ts: "2026-09-30T12:00:00Z", text: "Analyst session started. sensor-01 receive-only, TX 0 pkts." },
  ],
  reportIncidentId: null,
  tiTab: "iocs",
  toast: null,

  setSelected: (id) => set({ selectedIncidentId: id }),
  setSearch: (s) => set({ search: s }),
  setFilter: (k, v) =>
    set(
      k === "severity"
        ? { filterSeverity: v }
        : k === "status"
        ? { filterStatus: v }
        : { filterCategory: v }
    ),
  setStatus: (id, status) =>
    set((s) => ({
      incidents: s.incidents.map((i) => (i.id === id ? { ...i, status } : i)),
      log: [
        ...s.log,
        { id: s.log.length + 1, ts: NOW, text: `Incident ${id} status changed to ${status}.` },
      ],
    })),
  addNote: (id, text) =>
    set((s) => ({
      incidents: s.incidents.map((i) =>
        i.id === id
          ? { ...i, notes: [...i.notes, { author: "Analyst | SOC-1", ts: NOW, text }] }
          : i
      ),
      log: [...s.log, { id: s.log.length + 1, ts: NOW, text: `Note added to ${id}.` }],
    })),
  setVisibility: (m) => set({ visibilityMode: m }),
  setGuidedOpen: (o) => set({ guidedOpen: o }),
  setDemoStep: (n) => set({ demoStep: n }),
  setHighlight: (h) => set({ highlight: h }),
  setTiTab: (t) => set({ tiTab: t }),
  setToast: (t) => set({ toast: t }),

  generateArtifact: async (incidentId, type) => {
    const s = get();
    const inc = s.incidents.find((i) => i.id === incidentId);
    if (!inc) return null;
    const id = `ART-${String(s.artifacts.length + 1).padStart(3, "0")}`;
    const base: Artifact = {
      id,
      incidentId,
      type,
      title: `${type} for ${inc.hostname ?? inc.entity}`,
      state: "Proposed",
      created: "2026-09-30T12:06:00Z",
      sha256: null,
      approvedBy: null,
      approvedAt: null,
      exportedAt: null,
      blastRadius:
        type === "IOC block list"
          ? "Indicators appear to be dedicated infrastructure; low collateral risk."
          : type === "Firewall rules (nftables)"
            ? "Applies to egress from one VLAN. No shared service addresses included."
            : type === "DNS sinkhole / RPZ"
              ? "12 of 61 generated domains listed. Verify parent-zone ownership before applying."
              : type === "Host isolation request"
                ? "Single host. Finance VLAN 23 services on this host become unavailable until restored."
                : "Reflector ranges may include shared DNS resolvers; verify before blocking.",
      rollback:
        type === "Firewall rules (nftables)"
          ? "Delete the dw_mitigation table; no other policy is touched."
          : type === "DNS sinkhole / RPZ"
            ? "Withdraw the RPZ zone; resolvers fall back to normal resolution."
            : type === "Host isolation request"
              ? "Return the host to VLAN 23 through the change process."
              : "Remove the exported list at the enforcement point.",
      content: "",
    };
    const withC = withContent(base);
    const sha = await sha256(withC.content);
    const art = { ...withC, sha256: sha };
    set((st) => ({
      artifacts: [...st.artifacts, art],
      log: [
        ...st.log,
        {
          id: st.log.length + 1,
          ts: NOW,
          text: `Artifact ${id} proposed for ${incidentId} (${type}).`,
        },
      ],
      toast: `${id} proposed. Review and approve to hand it to the change process.`,
    }));
    return art;
  },

  approveArtifact: (id) =>
    set((s) => ({
      artifacts: s.artifacts.map((a) =>
        a.id === id && a.state !== "Exported"
          ? { ...a, state: "Approved", approvedBy: "Analyst | SOC-1", approvedAt: NOW }
          : a
      ),
      log: [
        ...s.log,
        { id: s.log.length + 1, ts: NOW, text: `Artifact ${id} approved by Analyst | SOC-1.` },
      ],
      toast: `${id} approved. Export hands it to the out-of-band change process.`,
    })),

  exportArtifact: (id) =>
    set((s) => ({
      artifacts: s.artifacts.map((a) =>
        a.id === id && a.state === "Approved"
          ? { ...a, state: "Exported", exportedAt: NOW }
          : a
      ),
      log: [
        ...s.log,
        {
          id: s.log.length + 1,
          ts: NOW,
          text: `Artifact ${id} exported to the out-of-band change process.`,
        },
      ],
      toast: `${id} exported. Enforcement is confirmed by the change process, not by DiodeWatch.`,
    })),

  verifyChain: async () => {
    const records = get().evidence;
    set({ verifying: true, chainVerified: false, verifyIndex: 0, tampered: false });
    for (let i = 0; i < records.length; i++) {
      await new Promise((r) => setTimeout(r, 220));
      set({ verifyIndex: i + 1 });
    }
    let brokenAt = -1;
    for (let i = 0; i < records.length; i++) {
      const computed = await sha256(`${records[i].prevHash}|${records[i].content}`);
      if (computed !== records[i].hash && brokenAt === -1) brokenAt = i;
    }
    const updated = records.map((r, i) => {
      if (brokenAt === -1) return { ...r, status: "Verified" as const };
      if (i < brokenAt) return { ...r, status: "Verified" as const };
      if (i === brokenAt) return { ...r, status: "Broken" as const };
      return { ...r, status: "Broken" as const };
    });
    set({ evidence: updated, verifying: false, chainVerified: brokenAt === -1, tampered: brokenAt !== -1 });
    get().pushLog(
      brokenAt === -1
        ? "Evidence chain verified. All records match their stored SHA-256 digests."
        : `Evidence chain verification failed at record ${brokenAt + 1}. Later records cannot be trusted.`
    );
  },

  simulateTamper: () =>
    set((s) => ({
      evidence: s.evidence.map((r, i) =>
        i === 5
          ? { ...r, content: `${r.content} [altered by demo control]`, status: "Pending" as const }
          : { ...r, status: "Pending" as const }
      ),
      tampered: true,
      chainVerified: false,
      verifyIndex: 0,
      toast: "Record 6 content altered. Run Verify chain to observe the failure.",
      log: [
        ...s.log,
        { id: s.log.length + 1, ts: NOW, text: "Demo control: evidence record 6 content altered." },
      ],
    })),

  restoreChain: async () => {
    const restored = await buildEvidence();
    set({
      evidence: restored,
      tampered: false,
      chainVerified: false,
      verifyIndex: 0,
      toast: "Evidence chain restored from the original record set.",
      log: [...get().log, { id: get().log.length + 1, ts: NOW, text: "Evidence chain restored." }],
    });
  },

  importBundle: async () => {
    set({ retroHuntStatus: "importing", retroHuntProgress: 0, retroHuntScanLine: "" });
    const steps = [
      "Reading DW-TI-2026-09-30-B.dwbundle (4.1 MB)…",
      "Verifying detached signature against the local trust anchor…",
      "Signature verified. Signer: National CERT advisory (sample).",
      "Validating schema against bundle manifest v3…",
      "Schema valid. Computing diff against DW-TI-2026-09-28…",
      "Diff: +1,842 added / ~37 updated / -12 expired.",
      "Import complete. Bundle staged; retro-hunt queued.",
    ];
    for (let i = 0; i < steps.length; i++) {
      await new Promise((r) => setTimeout(r, 420));
      set({
        retroHuntProgress: Math.round(((i + 1) / steps.length) * 100),
        retroHuntScanLine: steps[i],
      });
    }
    set((s) => ({
      bundleImported: true,
      log: [
        ...s.log,
        {
          id: s.log.length + 1,
          ts: NOW,
          text: "Bundle DW-TI-2026-09-30-B imported (+1,842 / ~37 / -12).",
        },
      ],
    }));
  },

  runRetroHunt: async () => {
    set({ retroHuntStatus: "scanning", retroHuntProgress: 0, retroHuntScanLine: "" });
    const lines = [
      "Scanning stored flow metadata — 48.2M flows, 14-day window…",
      "Scanning stored DNS query log — 2.1M queries…",
      "Scanning stored TLS session metadata — 310K sessions…",
      "Correlating matches against active incidents…",
    ];
    for (let i = 0; i < lines.length; i++) {
      await new Promise((r) => setTimeout(r, 900));
      set({
        retroHuntProgress: Math.round(((i + 1) / lines.length) * 100),
        retroHuntScanLine: lines[i],
      });
    }
    set((s) => ({
      retroHuntStatus: "complete",
      incidents: s.incidents.map((i) => {
        if (i.id === "INC-0417") {
          return {
            ...i,
            risk: 95,
            severity: riskSeverity(95),
            confidence: 0.9,
            riskBreakdown: i.riskBreakdown.map((b) =>
              b.label === "Threat-intel match"
                ? {
                    ...b,
                    value: 9,
                    reason:
                      "Retro-hunt matched 203.0.113.47, the JA4 fingerprint and 2 of 61 DGA domains in bundle DW-TI-2026-09-30-B.",
                  }
                : b
            ),
            riskHistory: [
              ...i.riskHistory,
              { ts: "2026-09-30T12:02:14Z", risk: 95, label: "Historical match (retro-hunt)" },
            ],
            findings: [
              ...i.findings,
              {
                id: "F-0417-06",
                ts: "2026-09-30T12:02:14Z",
                category: "C2 Beaconing" as const,
                title: "Historical indicator match (retro-hunt)",
                detail:
                  "Retro-hunt RH-2026-09-30-B matched 203.0.113.47 in 7 historical flows from 10.2.3.15, first contact 2026-09-27 21:14 UTC, 2.5 days before behavioural detection. The same JA4 fingerprint appears in 9 TLS sessions and 2 of the 61 DGA domains are listed in the bundle.",
                detector: "retro-hunt RH-2026-09-30-B (stored metadata, bundle DW-TI-2026-09-30-B)",
                direction: "client-to-server" as const,
                confidence: 0.9,
                risk: 95,
                severity: "Critical" as const,
                chart: "iat" as const,
                features: [
                  { feature: "Historical flows matched", value: "7", threshold: "≥ 1", baseline: "0", verdict: "match" },
                  { feature: "First contact", value: "2026-09-27 21:14 UTC", threshold: "before 2026-09-30", baseline: "n/a", verdict: "match" },
                  { feature: "TLS sessions with matched JA4", value: "9", threshold: "≥ 1", baseline: "0", verdict: "above" },
                  { feature: "DGA domains in bundle", value: "2 of 61", threshold: "≥ 1", baseline: "0", verdict: "above" },
                ],
                evidenceRefs: ["EV-0701", "EV-0702"],
              },
            ],
          };
        }
        if (i.id === "INC-0419") return { ...i, hiddenUntilRetroHunt: false };
        return i;
      }),
      log: [
        ...s.log,
        {
          id: s.log.length + 1,
          ts: NOW,
          text: "Retro-hunt RH-2026-09-30-B complete: 18 matches, 1 new lead (INC-0419). INC-0417 risk 86 → 95.",
        },
      ],
      toast: "Retro-hunt complete. INC-0417 risk 86 → 95 (Critical); INC-0419 created.",
    }));
  },

  setReportIncident: (id) => set({ reportIncidentId: id }),

  resetDemo: () => {
    void buildEvidence().then((ev) => {
      set({
        incidents: INCIDENTS.map((i) => ({ ...i })),
        selectedIncidentId: "INC-0417",
        search: "",
        filterSeverity: "all",
        filterStatus: "all",
        filterCategory: "all",
        bundleImported: false,
        retroHuntStatus: "idle",
        retroHuntProgress: 0,
        retroHuntScanLine: "",
        artifacts: INITIAL_ARTIFACTS_WITH_CONTENT,
        evidence: ev,
        chainVerified: false,
        tampered: false,
        verifying: false,
        verifyIndex: 0,
        visibilityMode: "both",
        guidedOpen: false,
        demoStep: 0,
        highlight: null,
        reportIncidentId: null,
        tiTab: "iocs",
        toast: "Demo reset to the seeded state.",
        log: [{ id: 1, ts: NOW, text: "Demo reset. sensor-01 receive-only, TX 0 pkts." }],
      });
    });
  },

  pushLog: (text) => set((s) => ({ log: [...s.log, { id: s.log.length + 1, ts: NOW, text }] })),
}));

export async function initEvidence() {
  const ev = await buildEvidence();
  useDemo.setState({ evidence: ev });
}

export function useSelectedIncident() {
  return useDemo((s) => s.incidents.find((i) => i.id === s.selectedIncidentId));
}
