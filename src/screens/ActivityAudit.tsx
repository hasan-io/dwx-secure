import { useMemo } from "react";
import { Link } from "react-router-dom";
import { ClipboardList, Download, Fingerprint, ScrollText, UserCheck } from "lucide-react";
import { Button, Chip, KeyValue, Panel, PanelHeader, SeverityBadge, Table, Td } from "../components/ui";
import { useDemo } from "../store/store";
import { downloadText, shortHash, toCsv } from "../lib/utils";

/** Immutable pre-session history, retained alongside the live activity log. */
const HISTORY = [
  { ts: "2026-09-29 06:00:02 UTC", actor: "system | scheduler", action: "Threat-intel bundle DW-TI-2026-09-28 imported and signature verified.", object: "DW-TI-2026-09-28", kind: "Bundle" },
  { ts: "2026-09-29 06:04:41 UTC", actor: "system | scheduler", action: "Retro-hunt RH-2026-09-29 completed. 4 matches, no new incidents.", object: "RH-2026-09-29", kind: "Retro-hunt" },
  { ts: "2026-09-30 02:14:31 UTC", actor: "system | detection", action: "Finding F-0403-01 recorded for INC-0403 (exfiltration volume anomaly).", object: "INC-0403", kind: "Finding" },
  { ts: "2026-09-30 03:12:40 UTC", actor: "Analyst | SOC-1", action: "INC-0403 marked Resolved. Analyst note: scheduled backup job, benign.", object: "INC-0403", kind: "Status" },
  { ts: "2026-09-30 03:41:09 UTC", actor: "Analyst | SOC-1", action: "Artifact ART-004 approved (backup window exception documentation).", object: "ART-004", kind: "Artifact" },
  { ts: "2026-09-30 05:11:26 UTC", actor: "system | detection", action: "Finding F-0412-01 recorded for INC-0412 (slow port scan).", object: "INC-0412", kind: "Finding" },
  { ts: "2026-09-30 06:38:51 UTC", actor: "system | detection", action: "Finding F-0409-01 recorded for INC-0409 (suspicious encrypted session).", object: "INC-0409", kind: "Finding" },
  { ts: "2026-09-30 07:52:18 UTC", actor: "system | detection", action: "Finding F-0415-01 recorded for INC-0415 (DNS tunnelling).", object: "INC-0415", kind: "Finding" },
  { ts: "2026-09-30 08:47:20 UTC", actor: "system | detection", action: "Finding F-0417-01 recorded for INC-0417 (horizontal scan, 445/tcp).", object: "INC-0417", kind: "Finding" },
  { ts: "2026-09-30 09:05:44 UTC", actor: "system | detection", action: "Finding F-0417-02 recorded for INC-0417 (DGA domain activity). Risk 52.", object: "INC-0417", kind: "Finding" },
  { ts: "2026-09-30 09:31:12 UTC", actor: "system | detection", action: "Finding F-0417-03 recorded for INC-0417 (C2 beaconing to 203.0.113.47). Risk 71.", object: "INC-0417", kind: "Finding" },
  { ts: "2026-09-30 09:52:26 UTC", actor: "system | detection", action: "Finding F-0417-04 recorded for INC-0417 (suspicious TLS session). Risk 79.", object: "INC-0417", kind: "Finding" },
  { ts: "2026-09-30 10:12:03 UTC", actor: "system | detection", action: "Finding F-0418-01 recorded for INC-0418 (UDP reflection, 412 reflectors).", object: "INC-0418", kind: "Finding" },
  { ts: "2026-09-30 10:26:41 UTC", actor: "Analyst | SOC-1", action: "Artifact ART-001 exported to the out-of-band change process.", object: "ART-001", kind: "Artifact" },
  { ts: "2026-09-30 10:31:47 UTC", actor: "system | detection", action: "Finding F-0418-02 recorded for INC-0418 (SYN flood). Risk 82.", object: "INC-0418", kind: "Finding" },
  { ts: "2026-09-30 11:20:51 UTC", actor: "system | detection", action: "Finding F-0417-05 recorded for INC-0417 (outbound transfer 4.8 GB). Risk 86.", object: "INC-0417", kind: "Finding" },
  { ts: "2026-09-30 11:45:00 UTC", actor: "system | integrity", action: "Scheduled integrity check passed. TX 0 packets, egress policy DROP.", object: "sensor-01", kind: "Integrity" },
];

const KIND_COLOR: Record<string, string> = {
  Finding: "#3B5B92",
  Artifact: "#B7791F",
  Bundle: "#7A5C7E",
  "Retro-hunt": "#B0662A",
  Status: "#3E6B57",
  Integrity: "#5B6773",
  Note: "#2F6F73",
  Session: "#1F3A5F",
};

export default function ActivityAudit() {
  const log = useDemo((s) => s.log);
  const incidents = useDemo((s) => s.incidents);
  const artifacts = useDemo((s) => s.artifacts);
  const evidence = useDemo((s) => s.evidence);
  const chainVerified = useDemo((s) => s.chainVerified);
  const tampered = useDemo((s) => s.tampered);
  const bundleImported = useDemo((s) => s.bundleImported);

  const chainHead = evidence.length ? evidence[evidence.length - 1].hash : "";

  const sessionRows = useMemo(
    () =>
      log.map((l) => ({
        ts: l.ts.replace("T", " ").replace("Z", " UTC"),
        actor: l.text.startsWith("Demo control") ? "demo | control" : "Analyst | SOC-1",
        action: l.text,
        object: (l.text.match(/(INC-\d+|ART-\d+|DW-TI-[A-Za-z0-9-]+)/) ?? ["session"])[0],
        kind: l.text.includes("Artifact")
          ? "Artifact"
          : l.text.includes("Retro-hunt") || l.text.includes("Bundle")
            ? "Bundle"
            : l.text.includes("Note")
              ? "Note"
              : "Session",
      })),
    [log]
  );

  const rows = [...sessionRows, ...HISTORY].sort((a, b) => (a.ts < b.ts ? 1 : -1));

  const exported = artifacts.filter((a) => a.state === "Exported").length;
  const approved = artifacts.filter((a) => a.state === "Approved").length;
  const proposed = artifacts.filter((a) => a.state === "Proposed").length;
  const openIncidents = incidents.filter((i) => i.status !== "Resolved" && !i.hiddenUntilRetroHunt).length;

  return (
    <div className="space-y-3">
      <div className="flex items-end justify-between">
        <div>
          <h1 className="text-[17px] font-semibold leading-tight text-ink">Activity &amp; audit</h1>
          <p className="mt-[2px] text-[12px] text-ink2">
            Every analyst action, detection event and system check is appended to an immutable
            record. The trail is exported with the forensic report.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Chip>
            <ScrollText size={11} strokeWidth={1.6} /> {rows.length} records
          </Chip>
          <Button
            onClick={() =>
              downloadText(
                "DiodeWatch-audit-trail.csv",
                toCsv(
                  ["Timestamp", "Actor", "Action", "Object", "Kind"],
                  rows.map((r) => [r.ts, r.actor, r.action, r.object, r.kind])
                )
              )
            }
          >
            <Download size={13} strokeWidth={1.6} /> Export audit trail
          </Button>
        </div>
      </div>

      <Panel className="grid grid-cols-5 divide-x divide-border">
        {[
          ["Open incidents", String(openIncidents)],
          ["Artifacts proposed", String(proposed)],
          ["Artifacts approved", String(approved)],
          ["Artifacts exported", String(exported)],
          ["Evidence records", String(evidence.length)],
        ].map(([k, v]) => (
          <div key={k} className="px-3 py-2">
            <div className="text-[11px] uppercase tracking-wide text-ink2">{k}</div>
            <div className="mt-[3px] font-mono text-[20px] font-semibold leading-none tabular-nums text-ink">{v}</div>
          </div>
        ))}
      </Panel>

      <div className="grid grid-cols-3 gap-3">
        <Panel>
          <PanelHeader
            title="Session provenance"
            subtitle="Binding between the analyst session and the evidence chain"
            icon={<UserCheck size={13} strokeWidth={1.6} />}
          />
          <div className="px-3 py-2.5">
            <KeyValue
              rows={[
                { k: "Analyst", v: "Analyst | SOC-1" },
                { k: "Session start", v: <span className="font-mono">2026-09-30 12:00:00 UTC</span> },
                { k: "Workstation", v: <span className="font-mono">SOC-WS-04</span> },
                { k: "Sensor", v: <span className="font-mono">sensor-01 · receive-only</span> },
                {
                  k: "Bundle in use",
                  v: (
                    <span className="font-mono text-[11.5px]">
                      {bundleImported ? "DW-TI-2026-09-30-B" : "DW-TI-2026-09-28"}
                    </span>
                  ),
                },
                {
                  k: "Chain head",
                  v: (
                    <span className="font-mono break-all text-[11px]">
                      {chainHead ? shortHash(chainHead, 18, 8) : "not computed"}
                    </span>
                  ),
                },
                {
                  k: "Chain status",
                  v: (
                    <span className={chainVerified ? "text-[#3E6B57]" : tampered ? "text-[#A32020]" : "text-ink2"}>
                      {chainVerified ? "Verified" : tampered ? "Chain broken" : "Not yet verified"}
                    </span>
                  ),
                },
              ]}
            />
            <p className="mt-2 rounded border border-border bg-[#f7f8fa] px-2 py-1.5 text-[11px] leading-snug text-ink2">
              Actions taken in this session are recorded here and hashed into the evidence chain at
              report generation. DiodeWatch does not write to the monitored network.
            </p>
            <div className="mt-2 flex items-center gap-2">
              <Link to="/response" className="text-[12px] text-link hover:underline">
                Open evidence integrity
              </Link>
              <span className="text-ink3">·</span>
              <Link to="/trust" className="text-[12px] text-link hover:underline">
                Trust boundary
              </Link>
            </div>
          </div>
        </Panel>

        <Panel className="col-span-2">
          <PanelHeader
            title="Audit trail"
            subtitle="Most recent first. Immutable; corrections are appended, never overwritten."
            icon={<ClipboardList size={13} strokeWidth={1.6} />}
            right={
              <div className="flex items-center gap-2 text-[11px] text-ink2">
                {Object.entries(KIND_COLOR).map(([k, c]) => (
                  <span key={k} className="inline-flex items-center gap-1">
                    <span className="inline-block h-2 w-2 rounded-full" style={{ backgroundColor: c }} />
                    {k}
                  </span>
                ))}
              </div>
            }
          />
          <div className="max-h-[520px] overflow-auto">
            <Table head={["Timestamp (UTC)", "Actor", "Object", "Kind", "Action"]}>
              {rows.map((r, i) => (
                <tr key={i} className="hover:bg-[#f7f8fa]">
                  <Td mono className="whitespace-nowrap">
                    {r.ts}
                  </Td>
                  <Td className="whitespace-nowrap">{r.actor}</Td>
                  <Td mono>{r.object}</Td>
                  <Td>
                    <span
                      className="inline-flex items-center gap-1.5 rounded-[3px] px-1.5 py-[1px] text-[11px]"
                      style={{
                        backgroundColor: `${KIND_COLOR[r.kind] ?? "#5B6773"}18`,
                        color: KIND_COLOR[r.kind] ?? "#5B6773",
                      }}
                    >
                      {r.kind}
                    </span>
                  </Td>
                  <Td className="whitespace-normal text-[11.5px] text-ink">{r.action}</Td>
                </tr>
              ))}
            </Table>
          </div>
        </Panel>
      </div>

      <Panel>
        <PanelHeader
          title="Artifact state history"
          subtitle="Who proposed, approved and exported each mitigation package"
          icon={<Fingerprint size={13} strokeWidth={1.6} />}
        />
        <Table head={["Artifact", "Type", "Incident", "Proposed (UTC)", "Approved by", "Approved (UTC)", "Exported (UTC)", "State"]}>
          {artifacts.map((a) => (
            <tr key={a.id} className="hover:bg-[#f7f8fa]">
              <Td mono>{a.id}</Td>
              <Td>{a.type}</Td>
              <Td mono>{a.incidentId}</Td>
              <Td mono>{a.created.replace("T", " ").replace("Z", "")}</Td>
              <Td>{a.approvedBy ?? "—"}</Td>
              <Td mono>{a.approvedAt ? a.approvedAt.replace("T", " ").replace("Z", "") : "—"}</Td>
              <Td mono>{a.exportedAt ? a.exportedAt.replace("T", " ").replace("Z", "") : "—"}</Td>
              <Td>
                <span
                  className={`inline-flex h-[18px] items-center rounded-[3px] px-1.5 text-[11px] font-medium ${
                    a.state === "Exported"
                      ? "bg-[#dff0e6] text-[#3E6B57]"
                      : a.state === "Approved"
                        ? "bg-[#dbe6f4] text-[#1F3A5F]"
                        : "bg-[#eceff3] text-ink2"
                  }`}
                >
                  {a.state}
                </span>
              </Td>
            </tr>
          ))}
        </Table>
        <div className="border-t border-border bg-[#f7f8fa] px-3 py-2 text-[11.5px] leading-relaxed text-ink2">
          Exported artifacts are handed to the out-of-band change process. DiodeWatch receives no
          confirmation of enforcement and does not record one.{" "}
          <span className="inline-flex items-center gap-1">
            <SeverityBadge severity="Info" /> informational
          </span>
        </div>
      </Panel>
    </div>
  );
}
