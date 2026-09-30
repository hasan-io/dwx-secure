import { useState } from "react";
import { Link } from "react-router-dom";
import { Crosshair, Eye, EyeOff, Layers, Sliders } from "lucide-react";
import { Button, Chip, Panel, PanelHeader, Table, Td } from "../components/ui";
import { CATEGORY_COLOR, downloadText, toCsv } from "../lib/utils";

type Cell = "full" | "partial" | "gap";

const SOURCES = ["Flow", "DNS", "TLS", "Volume", "TI match", "Correlation"];

/** Tactic × detection-source coverage, derived from the enabled detector set. */
const MATRIX: { tactic: string; cells: Cell[]; note: string }[] = [
  { tactic: "Reconnaissance", cells: ["full", "partial", "gap", "full", "partial", "full"], note: "Address sweeps and slow scans are flow-derived; DNS-based discovery is partial." },
  { tactic: "Resource Development", cells: ["gap", "partial", "gap", "gap", "full", "partial"], note: "Only indicator matches on infrastructure registration data are visible." },
  { tactic: "Initial Access", cells: ["partial", "partial", "partial", "gap", "partial", "partial"], note: "Inferred from follow-on stages; the delivery leg itself is not observed." },
  { tactic: "Execution", cells: ["gap", "gap", "gap", "gap", "gap", "partial"], note: "No host telemetry. Execution is inferred from child network behaviour." },
  { tactic: "Persistence", cells: ["partial", "partial", "partial", "partial", "gap", "partial"], note: "Beacon regularity over hours is the only persistence proxy available." },
  { tactic: "Privilege Escalation", cells: ["gap", "gap", "gap", "gap", "gap", "gap"], note: "Out of scope for a metadata-only sensor." },
  { tactic: "Defense Evasion", cells: ["partial", "gap", "partial", "partial", "gap", "partial"], note: "Low-and-slow patterns and single-cipher TLS are the visible signals." },
  { tactic: "Credential Access", cells: ["gap", "gap", "gap", "gap", "gap", "partial"], note: "Kerberos volume anomalies only; no protocol content is inspected." },
  { tactic: "Discovery", cells: ["full", "partial", "gap", "partial", "gap", "full"], note: "Internal scanning and enumeration produce the strongest flow evidence." },
  { tactic: "Lateral Movement", cells: ["full", "gap", "partial", "partial", "gap", "full"], note: "East-west SMB, RDP and WinRM flows are visible on mirrored segments." },
  { tactic: "Collection", cells: ["gap", "gap", "gap", "partial", "gap", "partial"], note: "Only aggregate volume changes are observable." },
  { tactic: "Command & Control", cells: ["full", "full", "full", "partial", "full", "full"], note: "Strongest coverage: periodicity, DGA resolution, TLS fingerprint and indicators." },
  { tactic: "Exfiltration", cells: ["partial", "partial", "partial", "full", "partial", "full"], note: "Volume and upload:download asymmetry carry the detection." },
  { tactic: "Impact", cells: ["partial", "gap", "gap", "full", "gap", "full"], note: "Volumetric impact is visible; destructive activity on the host is not." },
];

const SEGMENTS = [
  { vlan: "Finance VLAN 23", hosts: 214, flowsMin: 6120, bidir: 74, detectors: 8, blind: "None observed", criticality: "High" },
  { vlan: "Public web VLAN 10", hosts: 12, flowsMin: 18440, bidir: 82, detectors: 7, blind: "Return path of spoofed sources", criticality: "Critical" },
  { vlan: "HR VLAN 31", hosts: 168, flowsMin: 3210, bidir: 68, detectors: 8, blind: "DoH to public resolvers not parsed", criticality: "Medium" },
  { vlan: "Research VLAN 47", hosts: 96, flowsMin: 4180, bidir: 51, detectors: 6, blind: "Instrument tunnels over DNS", criticality: "Medium" },
  { vlan: "Operations VLAN 12", hosts: 132, flowsMin: 5240, bidir: 71, detectors: 8, blind: "Legacy SCADA on unmanaged switches", criticality: "High" },
  { vlan: "Engineering VLAN 18", hosts: 187, flowsMin: 4460, bidir: 66, detectors: 7, blind: "Peer-to-peer lab traffic", criticality: "Low" },
  { vlan: "Data Centre VLAN 8", hosts: 74, flowsMin: 19630, bidir: 79, detectors: 8, blind: "Encrypted backup windows", criticality: "Medium" },
];

const BLIND_SPOTS = [
  { area: "Payload content", impact: "High", detail: "TLS is not decrypted and raw payload is not retained. Content-based indicators cannot be evaluated." },
  { area: "Encrypted DNS (DoH/DoT)", impact: "Medium", detail: "Queries to public DoH resolvers appear as opaque TLS flows; DGA and tunnelling detection is unavailable for those clients." },
  { area: "Single-direction flows (29%)", impact: "Medium", detail: "Half of each flow is missing for more than a quarter of records. Detectors fall back to direction-tolerant features." },
  { area: "Unmanaged east-west paths", impact: "Medium", detail: "Traffic between hosts on switches without a mirror port is not captured at all." },
  { area: "IPv6 tunnelling", impact: "Low", detail: "Teredo and 6to4 encapsulation hides inner addresses; only the outer flow is scored." },
  { area: "Host and identity telemetry", impact: "High", detail: "No EDR, authentication or process data is available inside the enclave." },
];

const DETECTORS = [
  { name: "SIG-RECON-HSCAN-445 v2.4", type: "Rule", window: "300 s", threshold: "> 50 hosts / 300 s", category: "Reconnaissance", enabled: true, tuned: "2026-09-12", by: "Analyst | SOC-2" },
  { name: "SIG-RECON-SLOWSCAN v1.7", type: "Rule", window: "10800 s", threshold: "> 1,000 probes / 3 h", category: "Reconnaissance", enabled: true, tuned: "2026-08-30", by: "Analyst | SOC-3" },
  { name: "dga-lstm-v3.1", type: "Model", window: "600 s", threshold: "p ≥ 0.75", category: "DGA/DNS Tunnelling", enabled: true, tuned: "2026-09-18", by: "Detection Eng." },
  { name: "SIG-DNS-TUNNEL-TXT v2.1", type: "Rule", window: "3600 s", threshold: "> 200 TXT queries / h", category: "DGA/DNS Tunnelling", enabled: true, tuned: "2026-09-02", by: "Detection Eng." },
  { name: "beacon-periodicity-v2.7", type: "Model", window: "7200 s", threshold: "CV < 0.10, ≥ 20 flows", category: "C2 Beaconing", enabled: true, tuned: "2026-09-21", by: "Detection Eng." },
  { name: "tls-eps-v1.9", type: "Model", window: "per session", threshold: "p ≥ 0.70", category: "Encrypted Malware", enabled: true, tuned: "2026-09-25", by: "Detection Eng." },
  { name: "exfil-volume-v2.2", type: "Model", window: "2400 s", threshold: "> 5× host baseline", category: "Exfiltration", enabled: true, tuned: "2026-09-27", by: "Analyst | SOC-2" },
  { name: "SIG-DDOS-UDP-REFLECT v3.1", type: "Rule", window: "60 s", threshold: "> 50 reflectors / min", category: "DDoS", enabled: true, tuned: "2026-09-29", by: "Analyst | SOC-1" },
  { name: "SIG-DDOS-SYNFLOOD v2.8", type: "Rule", window: "60 s", threshold: "SYN:ACK > 4:1", category: "DDoS", enabled: true, tuned: "2026-09-29", by: "Analyst | SOC-1" },
];

const PIPELINE = [
  { stage: "Passive traffic", source: "eth1 mirror, receive-only", coverage: 100 },
  { stage: "Feature analysis", source: "flow, DNS, TLS metadata", coverage: 96 },
  { stage: "Threat detection", source: "9 detectors (7 rules / models)", coverage: 88 },
  { stage: "Threat intelligence", source: "DW-TI-2026-09-28", coverage: 74 },
  { stage: "Incident correlation", source: "entity + 300 s window", coverage: 100 },
  { stage: "Risk scoring", source: "5 weighted contributions", coverage: 100 },
  { stage: "Response recommendation", source: "playbook library", coverage: 100 },
  { stage: "Forensic report", source: "evidence chain + report engine", coverage: 100 },
];

const CELL_STYLE: Record<Cell, { bg: string; fg: string; label: string }> = {
  full: { bg: "#3E6B57", fg: "#FFFFFF", label: "Covered" },
  partial: { bg: "#B7791F", fg: "#FFFFFF", label: "Partial" },
  gap: { bg: "#E6E9EE", fg: "#8A949F", label: "Gap" },
};

export default function Coverage() {
  const [detectors, setDetectors] = useState(DETECTORS);

  const covered = MATRIX.reduce((n, r) => n + r.cells.filter((c) => c === "full").length, 0);
  const partial = MATRIX.reduce((n, r) => n + r.cells.filter((c) => c === "partial").length, 0);
  const total = MATRIX.length * SOURCES.length;

  return (
    <div className="space-y-3">
      <div className="flex items-end justify-between">
        <div>
          <h1 className="text-[17px] font-semibold leading-tight text-ink">Coverage &amp; detections</h1>
          <p className="mt-[2px] text-[12px] text-ink2">
            What the mirrored sensor can and cannot see. Coverage is stated in terms of observable
            metadata, not of attack prevention.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Chip>
            <Crosshair size={11} strokeWidth={1.6} /> {covered}/{total} fully covered
          </Chip>
          <Chip>
            <Layers size={11} strokeWidth={1.6} /> {partial} partial
          </Chip>
          <Button
            onClick={() =>
              downloadText(
                "DiodeWatch-coverage-matrix.csv",
                toCsv(
                  ["Tactic", ...SOURCES, "Note"],
                  MATRIX.map((r) => [r.tactic, ...r.cells, r.note])
                )
              )
            }
          >
            Export matrix
          </Button>
        </div>
      </div>

      {/* Pipeline coverage */}
      <Panel>
        <PanelHeader
          title="Detection pipeline coverage"
          subtitle="Each stage of the analysis chain, and what feeds it"
          icon={<Layers size={13} strokeWidth={1.6} />}
        />
        <div className="grid grid-cols-8 divide-x divide-border">
          {PIPELINE.map((p) => (
            <div key={p.stage} className="px-2.5 py-2.5">
              <div className="text-[11px] font-semibold leading-tight text-ink">{p.stage}</div>
              <div className="mt-[3px] text-[10.5px] leading-snug text-ink2">{p.source}</div>
              <div className="mt-2 h-[4px] w-full overflow-hidden rounded-[2px] bg-[#e6e9ee]">
                <div className="h-full bg-navy" style={{ width: `${p.coverage}%` }} />
              </div>
              <div className="mt-1 font-mono text-[11px] tabular-nums text-ink2">{p.coverage}%</div>
            </div>
          ))}
        </div>
      </Panel>

      {/* ATT&CK-style matrix */}
      <Panel>
        <PanelHeader
          title="Tactic coverage matrix"
          subtitle="Detection source availability per tactic. A gap means no detector can observe the tactic from mirrored metadata."
          icon={<Crosshair size={13} strokeWidth={1.6} />}
          right={
            <div className="flex items-center gap-2 text-[11px] text-ink2">
              {(Object.keys(CELL_STYLE) as Cell[]).map((k) => (
                <span key={k} className="inline-flex items-center gap-1">
                  <span
                    className="inline-block h-2.5 w-2.5 rounded-[2px]"
                    style={{ backgroundColor: CELL_STYLE[k].bg }}
                  />
                  {CELL_STYLE[k].label}
                </span>
              ))}
            </div>
          }
        />
        <Table head={["Tactic", ...SOURCES, "Interpretation"]} dense={false}>
          {MATRIX.map((r) => (
            <tr key={r.tactic} className="hover:bg-[#f7f8fa]">
              <Td className="whitespace-nowrap font-medium">{r.tactic}</Td>
              {r.cells.map((c, i) => (
                <Td key={i} className="text-center">
                  <span
                    title={CELL_STYLE[c].label}
                    className="inline-flex h-[18px] w-[34px] items-center justify-center rounded-[2px] text-[10px] font-semibold"
                    style={{ backgroundColor: CELL_STYLE[c].bg, color: CELL_STYLE[c].fg }}
                  >
                    {c === "full" ? "yes" : c === "partial" ? "part" : "—"}
                  </span>
                </Td>
              ))}
              <Td className="whitespace-normal text-[11.5px] text-ink2">{r.note}</Td>
            </tr>
          ))}
        </Table>
      </Panel>

      {/* Segments */}
      <div className="grid grid-cols-3 gap-3">
        <Panel className="col-span-2">
          <PanelHeader
            title="Segment visibility"
            subtitle="Mirror coverage and direction balance per monitored segment"
            icon={<Eye size={13} strokeWidth={1.6} />}
            right={
              <Button
                onClick={() =>
                  downloadText(
                    "DiodeWatch-segment-visibility.csv",
                    toCsv(
                      ["Segment", "Hosts", "Flows/min", "Bidirectional %", "Detectors", "Blind spot", "Criticality"],
                      SEGMENTS.map((s) => [s.vlan, s.hosts, s.flowsMin, s.bidir, s.detectors, s.blind, s.criticality])
                    )
                  )
                }
              >
                Export
              </Button>
            }
          />
          <Table head={["Segment", "Hosts", "Flows / min", "Bidirectional", "Detectors", "Criticality", "Known blind spot"]}>
            {SEGMENTS.map((s) => (
              <tr key={s.vlan} className="hover:bg-[#f7f8fa]">
                <Td>{s.vlan}</Td>
                <Td mono className="tabular-nums">
                  {s.hosts}
                </Td>
                <Td mono className="tabular-nums">
                  {s.flowsMin.toLocaleString("en-US")}
                </Td>
                <Td>
                  <span className="flex items-center gap-2">
                    <span className="h-[6px] w-[52px] overflow-hidden rounded-[2px] bg-[#e6e9ee]">
                      <span
                        className="block h-full bg-[#2F5D9E]"
                        style={{ width: `${s.bidir}%` }}
                      />
                    </span>
                    <span className="font-mono text-[11px] tabular-nums text-ink2">{s.bidir}%</span>
                  </span>
                </Td>
                <Td mono className="tabular-nums">
                  {s.detectors}
                </Td>
                <Td>{s.criticality}</Td>
                <Td className="whitespace-normal text-[11.5px] text-ink2">{s.blind}</Td>
              </tr>
            ))}
          </Table>
        </Panel>

        <Panel>
          <PanelHeader title="Blind spots" subtitle="Stated limits of the observation model" icon={<EyeOff size={13} strokeWidth={1.6} />} />
          <ul className="divide-y divide-border">
            {BLIND_SPOTS.map((b) => (
              <li key={b.area} className="px-3 py-2">
                <div className="flex items-center justify-between">
                  <span className="text-[12px] font-medium text-ink">{b.area}</span>
                  <Chip
                    style={{
                      color: b.impact === "High" ? "#A32020" : b.impact === "Medium" ? "#B7791F" : "#5B6773",
                    }}
                  >
                    {b.impact} impact
                  </Chip>
                </div>
                <p className="mt-[3px] text-[11.5px] leading-snug text-ink2">{b.detail}</p>
              </li>
            ))}
          </ul>
        </Panel>
      </div>

      {/* Detector configuration */}
      <Panel>
        <PanelHeader
          title="Detector configuration"
          subtitle="Thresholds and tuning history. Toggling affects reporting only; it does not alter monitored traffic."
          icon={<Sliders size={13} strokeWidth={1.6} />}
        />
        <Table head={["Detector", "Type", "Category", "Window", "Threshold", "Last tuned", "Tuned by", "State"]}>
          {detectors.map((d) => (
            <tr key={d.name} className="hover:bg-[#f7f8fa]">
              <Td mono>{d.name}</Td>
              <Td>{d.type}</Td>
              <Td>
                <span className="inline-flex items-center gap-1.5">
                  <span
                    className="inline-block h-2 w-2 rounded-full"
                    style={{ backgroundColor: CATEGORY_COLOR[d.category] }}
                  />
                  {d.category}
                </span>
              </Td>
              <Td mono className="tabular-nums">
                {d.window}
              </Td>
              <Td mono>{d.threshold}</Td>
              <Td mono>{d.tuned}</Td>
              <Td>{d.by}</Td>
              <Td>
                <button
                  onClick={() =>
                    setDetectors((prev) =>
                      prev.map((x) => (x.name === d.name ? { ...x, enabled: !x.enabled } : x))
                    )
                  }
                  className={`inline-flex h-[20px] items-center rounded-[3px] border px-1.5 text-[11px] font-medium ${
                    d.enabled
                      ? "border-[#3E6B57] text-[#3E6B57]"
                      : "border-border text-ink3"
                  }`}
                >
                  {d.enabled ? "Enabled" : "Disabled"}
                </button>
              </Td>
            </tr>
          ))}
        </Table>
        <div className="border-t border-border bg-[#f7f8fa] px-3 py-2 text-[11.5px] leading-relaxed text-ink2">
          Disabling a detector stops its findings from being reported. It does not change the
          monitored network in any way.{" "}
          <Link to="/trust" className="text-link hover:underline">
            See the trust boundary
          </Link>
          .
        </div>
      </Panel>
    </div>
  );
}
