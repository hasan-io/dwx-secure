import React from "react";
import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import {
  AlertTriangle,
  CheckCircle2,
  Download,
  FileText,
  Fingerprint,
  Printer,
  ShieldCheck,
  Undo2,
} from "lucide-react";
import {
  Button,
  Chip,
  KeyValue,
  Panel,
  PanelHeader,
  Select,
  StatusPill,
  Table,
  Td,
} from "../components/ui";
import { useDemo } from "../store/store";
import { fmtUtc, shortHash, downloadText } from "../lib/utils";
import type { Artifact, ArtifactType, Incident } from "../lib/types";

const ARTIFACT_TYPES: ArtifactType[] = [
  "IOC block list",
  "Firewall rules (nftables)",
  "DNS sinkhole / RPZ",
  "Host isolation request",
  "DDoS rate-limit / RTBH request",
];

const STATE_STEPS = ["Proposed", "Approved", "Exported"];

function Stepper({ state }: { state: Artifact["state"] }) {
  const idx = STATE_STEPS.indexOf(state);
  return (
    <span className="inline-flex items-center gap-1">
      {STATE_STEPS.map((s, i) => (
        <span key={s} className="inline-flex items-center gap-1">
          <span
            className={`inline-flex h-[16px] items-center rounded-[3px] px-1.5 text-[10.5px] font-medium ${
              i <= idx
                ? i === 0
                  ? "bg-[#eceff3] text-ink"
                  : i === 1
                  ? "bg-[#dbe6f4] text-navy"
                  : "bg-[#dff0e6] text-[#3E6B57]"
                : "bg-white text-ink3"
            }`}
          >
            {s}
          </span>
          {i < STATE_STEPS.length - 1 ? <span className="text-ink3">›</span> : null}
        </span>
      ))}
    </span>
  );
}

function reportText(inc: Incident, chainHead: string): string {
  const lines: string[] = [];
  const push = (s = "") => lines.push(s);
  push("DIODEWATCH FORENSIC REPORT");
  push("Prototype build. Simulated telemetry, synthetic IOCs, illustrative benchmark values.");
  push("=".repeat(78));
  push(`Incident        : ${inc.id}`);
  push(`Entity          : ${inc.entity} (${inc.hostname ?? "unmanaged host"})`);
  push(`Title           : ${inc.title}`);
  push(`Severity        : ${inc.severity}`);
  push(`Risk            : ${inc.risk} / 100`);
  push(`Confidence      : ${inc.confidence.toFixed(2)}`);
  push(`Status          : ${inc.status}`);
  push(`First seen      : ${fmtUtc(inc.firstSeen)}`);
  push(`Last seen       : ${fmtUtc(inc.lastSeen)}`);
  push(`Generated       : 2026-09-30 12:00 UTC`);
  push(`Sensor          : sensor-01, receive-only, TX 0 packets, egress policy DROP`);
  push();
  push("1. EXECUTIVE SUMMARY");
  push(inc.summary);
  push();
  push("2. INCIDENT TIMELINE");
  inc.riskHistory.forEach((r) => push(`  ${fmtUtc(r.ts)}  risk ${String(r.risk).padStart(3)}  ${r.label}`));
  push();
  push("3. EVIDENCE SUMMARY");
  inc.findings.forEach((f) => {
    push(`  ${f.id}  ${fmtUtc(f.ts)}  ${f.category}`);
    push(`      ${f.title}`);
    push(`      detector: ${f.detector}`);
    push(`      observed direction: ${f.direction}  confidence: ${f.confidence.toFixed(2)}  risk: ${f.risk}`);
    push(`      evidence refs: ${f.evidenceRefs.join(", ")}`);
    f.features.forEach((row) =>
      push(`        - ${row.feature}: ${row.value} (threshold ${row.threshold}, baseline ${row.baseline})`)
    );
  });
  push();
  push("4. THREAT-INTEL MATCHES");
  if (inc.tiMatches.length === 0) push("  No indicator in the active bundle matched this incident.");
  else
    inc.tiMatches.forEach((m) =>
      push(`  ${m.indicator} [${m.type}] source: ${m.source} first seen ${m.firstSeen} confidence ${m.confidence.toFixed(2)} (${m.origin})`)
    );
  push();
  push("5. RISK BREAKDOWN");
  inc.riskBreakdown.forEach((b) => push(`  ${b.label}: +${b.value} — ${b.reason}`));
  push(`  Total: ${inc.risk}`);
  push();
  push("6. RECOMMENDED ACTIONS");
  push("  Advisory only. Enforcement is performed by an authorised process outside DiodeWatch.");
  (["Immediate", "Short-term", "Hardening"] as const).forEach((g) => {
    push(`  ${g}`);
    inc.recommendedActions
      .filter((a) => a.group === g)
      .forEach((a) => push(`    - ${a.text} (${a.rationale})`));
  });
  push();
  push("7. INTEGRITY APPENDIX");
  push(`  Evidence records: 9`);
  push(`  Chain head SHA-256: ${chainHead || "not computed"}`);
  push("  Verification: recompute SHA-256(prev_hash | content) for each record in order.");
  push("  Any mismatch invalidates the record and every record that follows it.");
  push();
  push("END OF REPORT");
  return lines.join("\n");
}

export default function ResponseReports() {
  const incidents = useDemo((s) => s.incidents);
  const artifacts = useDemo((s) => s.artifacts);
  const generateArtifact = useDemo((s) => s.generateArtifact);
  const approveArtifact = useDemo((s) => s.approveArtifact);
  const exportArtifact = useDemo((s) => s.exportArtifact);
  const evidence = useDemo((s) => s.evidence);
  const verifying = useDemo((s) => s.verifying);
  const verifyIndex = useDemo((s) => s.verifyIndex);
  const chainVerified = useDemo((s) => s.chainVerified);
  const tampered = useDemo((s) => s.tampered);
  const verifyChain = useDemo((s) => s.verifyChain);
  const simulateTamper = useDemo((s) => s.simulateTamper);
  const restoreChain = useDemo((s) => s.restoreChain);
  const setSelected = useDemo((s) => s.setSelected);

  const [viewArtifact, setViewArtifact] = useState<string | null>("ART-001");
  const [newType, setNewType] = useState<ArtifactType>("IOC block list");
  const [newIncident, setNewIncident] = useState("INC-0417");
  const storeReportId = useDemo((s) => s.reportIncidentId);
  const setStoreReport = useDemo((s) => s.setReportIncident);
  const [reportIncident, setReportIncident] = useState(storeReportId ?? "INC-0417");
  const [reportGenerated, setReportGenerated] = useState(false);

  React.useEffect(() => {
    if (storeReportId) {
      setReportIncident(storeReportId);
      setReportGenerated(true);
    }
  }, [storeReportId]);

  const visible = incidents.filter((i) => !i.hiddenUntilRetroHunt);
  const chainHead = evidence.length ? evidence[evidence.length - 1].hash : "";
  const reportInc = incidents.find((i) => i.id === reportIncident) ?? visible[0];
  const report = useMemo(
    () => (reportGenerated ? reportText(reportInc, chainHead) : ""),
    [reportGenerated, reportInc, chainHead]
  );
  const viewed = artifacts.find((a) => a.id === viewArtifact) ?? artifacts[0];

  return (
    <div className="space-y-3">
      <div className="flex items-end justify-between">
        <div>
          <h1 className="text-[17px] font-semibold leading-tight text-ink">Response &amp; reports</h1>
          <p className="mt-[2px] text-[12px] text-ink2">
            DiodeWatch recommends, records and exports. Enforcement is performed by an authorised
            process outside this system.
          </p>
        </div>
        <Chip>
          <ShieldCheck size={11} strokeWidth={1.6} /> Advisory only — no return path to production
        </Chip>
      </div>

      {/* Recommended actions */}
      <Panel>
        <PanelHeader
          title="Recommended actions by incident"
          subtitle="Grouped by response horizon"
          icon={<FileText size={13} strokeWidth={1.6} />}
        />
        <div className="grid grid-cols-3 divide-x divide-border">
          {(["Immediate", "Short-term", "Hardening"] as const).map((g) => (
            <div key={g} className="px-3 py-2.5">
              <div className="mb-1.5 text-[11px] font-semibold uppercase tracking-wide text-ink2">{g}</div>
              <ul className="space-y-2">
                {visible.flatMap((i) =>
                  i.recommendedActions
                    .filter((a) => a.group === g)
                    .map((a) => (
                      <li key={`${i.id}-${a.id}`} className="rounded border border-border bg-white px-2 py-1.5">
                        <div className="flex items-center gap-2">
                          <Link
                            to="/incidents"
                            onClick={() => setSelected(i.id)}
                            className="font-mono text-[11.5px] text-link hover:underline"
                          >
                            {i.id}
                          </Link>
                          {a.artifactType ? <Chip>{a.artifactType}</Chip> : null}
                        </div>
                        <div className="mt-[3px] text-[12px] leading-snug text-ink">{a.text}</div>
                      </li>
                    ))
                )}
              </ul>
            </div>
          ))}
        </div>
      </Panel>

      {/* Mitigation artifacts */}
      <Panel data-demo-id="artifact-table">
        <PanelHeader
          title="Mitigation artifacts"
          subtitle="Proposed, approved and exported packages"
          icon={<FileText size={13} strokeWidth={1.6} />}
          right={
            <div className="flex items-center gap-2">
              <Select
                label="Incident"
                value={newIncident}
                onChange={setNewIncident}
                options={visible.map((i) => ({ value: i.id, label: i.id }))}
              />
              <Select
                label="Type"
                value={newType}
                onChange={(v) => setNewType(v as ArtifactType)}
                options={ARTIFACT_TYPES.map((t) => ({ value: t, label: t }))}
              />
              <Button variant="primary" onClick={() => void generateArtifact(newIncident, newType)}>
                Generate artifact
              </Button>
            </div>
          }
        />
        <div className="max-h-[420px] overflow-auto">
          <Table head={["ID", "Type", "Incident", "State", "SHA-256", "Created (UTC)", "Blast radius", "Rollback", "Actions"]}>
            {artifacts.map((a) => (
              <tr key={a.id} className="hover:bg-[#f7f8fa]">
                <Td mono>
                  <button
                    onClick={() => setViewArtifact(a.id)}
                    className={`text-link hover:underline ${viewed?.id === a.id ? "font-semibold" : ""}`}
                  >
                    {a.id}
                  </button>
                </Td>
                <Td>{a.type}</Td>
                <Td mono>
                  <Link to="/incidents" onClick={() => setSelected(a.incidentId)} className="text-link hover:underline">
                    {a.incidentId}
                  </Link>
                </Td>
                <Td>
                  <Stepper state={a.state} />
                </Td>
                <Td mono className="break-all">
                  {a.sha256 ? shortHash(a.sha256, 12, 6) : "—"}
                </Td>
                <Td mono>{a.created.replace("T", " ").replace("Z", "")}</Td>
                <Td className="max-w-[240px] whitespace-normal text-[11.5px] text-ink2">{a.blastRadius}</Td>
                <Td className="max-w-[200px] whitespace-normal text-[11.5px] text-ink2">{a.rollback}</Td>
                <Td>
                  <span className="flex items-center gap-1.5">
                    <Button
                      onClick={() => approveArtifact(a.id)}
                      disabled={a.state !== "Proposed"}
                      title={a.state === "Exported" ? "Already exported" : "Approve this artifact"}
                    >
                      Approve
                    </Button>
                    <Button
                      onClick={() => {
                        exportArtifact(a.id);
                        downloadText(
                          `${a.id}-${a.incidentId}.txt`,
                          a.content,
                          "text/plain"
                        );
                      }}
                      disabled={a.state !== "Approved"}
                      title="Download the artifact file for the change process"
                    >
                      Export
                    </Button>
                  </span>
                </Td>
              </tr>
            ))}
          </Table>
        </div>
        <div className="border-t border-border bg-[#f7f8fa] px-3 py-2 text-[11.5px] leading-relaxed text-ink2">
          <span className="font-medium text-ink">Exported means handed to the out-of-band change
          process.</span>{" "}
          DiodeWatch has no return path and cannot confirm enforcement. Approval and export events are
          recorded in the activity log with the acting analyst and timestamp.
        </div>
      </Panel>

      {/* Artifact viewer */}
      <Panel>
        <PanelHeader
          title="Artifact viewer"
          subtitle={viewed ? `${viewed.id} · ${viewed.type} · ${viewed.state}` : "No artifact selected"}
          icon={<FileText size={13} strokeWidth={1.6} />}
          right={
            viewed ? (
              <>
                <span className="text-[11px] text-ink2">
                  {viewed.approvedBy ? `Approved by ${viewed.approvedBy}` : "Not approved"}
                  {viewed.approvedAt ? ` at ${fmtUtc(viewed.approvedAt)}` : ""}
                  {viewed.exportedAt ? ` · exported ${fmtUtc(viewed.exportedAt)}` : ""}
                </span>
                <Button
                  onClick={() =>
                    downloadText(`${viewed.id}-${viewed.incidentId}.txt`, viewed.content, "text/plain")
                  }
                >
                  <Download size={13} strokeWidth={1.6} /> Download
                </Button>
              </>
            ) : null
          }
        />
        {viewed ? (
          <pre className="max-h-[300px] overflow-auto whitespace-pre-wrap break-words border-t border-border bg-[#fbfbfc] px-3 py-2 font-mono text-[11.5px] leading-relaxed text-ink">
            {viewed.content}
          </pre>
        ) : (
          <div className="px-3 py-6 text-[12px] text-ink2">Select an artifact to view its content.</div>
        )}
      </Panel>

      {/* Forensic report */}
      <Panel>
        <PanelHeader
          title="Forensic report"
          subtitle="Generated on screen from the incident record and the evidence chain"
          icon={<FileText size={13} strokeWidth={1.6} />}
          right={
            <>
              <Select
                label="Incident"
                value={reportIncident}
                onChange={(v) => {
                  setReportIncident(v);
                  setStoreReport(v);
                }}
                options={visible.map((i) => ({ value: i.id, label: i.id }))}
              />
              <Button
                variant="primary"
                onClick={() => setReportGenerated(true)}
                data-demo-id="generate-report"
              >
                Generate report
              </Button>
              {reportGenerated ? (
                <>
                  <Button
                    onClick={() =>
                      downloadText(
                        `DiodeWatch-${reportInc.id}-forensic-report.txt`,
                        report,
                        "text/plain"
                      )
                    }
                  >
                    <Download size={13} strokeWidth={1.6} /> Download
                  </Button>
                  <Button onClick={() => window.print()}>
                    <Printer size={13} strokeWidth={1.6} /> Print to PDF
                  </Button>
                </>
              ) : null}
            </>
          }
        />
        {reportGenerated ? (
          <div id="report-preview" className="border-t border-border px-6 py-4">
            <div className="mb-3 flex items-start justify-between border-b border-border pb-2">
              <div>
                <div className="text-[15px] font-semibold text-ink">DiodeWatch forensic report</div>
                <div className="text-[11.5px] text-ink2">
                  {reportInc.id} · {reportInc.entity} ({reportInc.hostname}) · generated 2026-09-30 12:00 UTC
                </div>
              </div>
              <div className="text-right text-[11px] text-ink2">
                <div>Prototype build. Simulated telemetry, synthetic IOCs,</div>
                <div>illustrative benchmark values.</div>
              </div>
            </div>

            <ReportSection n="1" title="Executive summary">
              <p>{reportInc.summary}</p>
            </ReportSection>

            <ReportSection n="2" title="Incident timeline">
              <table className="w-full text-[12px]">
                <tbody>
                  {reportInc.riskHistory.map((r) => (
                    <tr key={r.ts}>
                      <td className="w-[190px] py-[2px] font-mono text-ink2">{fmtUtc(r.ts)}</td>
                      <td className="w-[70px] py-[2px] font-mono tabular-nums text-ink">risk {r.risk}</td>
                      <td className="py-[2px] text-ink">{r.label}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </ReportSection>

            <ReportSection n="3" title="Evidence summary">
              <ul className="space-y-2">
                {reportInc.findings.map((f) => (
                  <li key={f.id} className="rounded border border-border px-2 py-1.5">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-mono text-[11.5px] text-ink2">{f.id}</span>
                      <span className="font-mono text-[11.5px] text-ink2">{fmtUtc(f.ts)}</span>
                      <span className="text-[12px] font-medium text-ink">{f.title}</span>
                      <span className="ml-auto font-mono text-[11px] text-ink2">
                        conf {f.confidence.toFixed(2)} · risk {f.risk} · {f.direction}
                      </span>
                    </div>
                    <div className="mt-[2px] text-[11.5px] text-ink2">Detector: {f.detector}</div>
                    <div className="mt-[2px] text-[11.5px] text-ink">Evidence refs: {f.evidenceRefs.join(", ")}</div>
                  </li>
                ))}
              </ul>
            </ReportSection>

            <ReportSection n="4" title="Threat-intel matches">
              {reportInc.tiMatches.length ? (
                <table className="w-full text-[12px]">
                  <thead>
                    <tr className="text-ink2">
                      <th className="py-[2px] text-left font-medium">Indicator</th>
                      <th className="py-[2px] text-left font-medium">Type</th>
                      <th className="py-[2px] text-left font-medium">Source</th>
                      <th className="py-[2px] text-left font-medium">First seen</th>
                      <th className="py-[2px] text-left font-medium">Confidence</th>
                      <th className="py-[2px] text-left font-medium">Origin</th>
                    </tr>
                  </thead>
                  <tbody>
                    {reportInc.tiMatches.map((m, i) => (
                      <tr key={i}>
                        <td className="py-[2px] font-mono">{m.indicator}</td>
                        <td className="py-[2px]">{m.type}</td>
                        <td className="py-[2px]">{m.source}</td>
                        <td className="py-[2px] font-mono">{m.firstSeen}</td>
                        <td className="py-[2px] font-mono tabular-nums">{m.confidence.toFixed(2)}</td>
                        <td className="py-[2px]">{m.origin}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              ) : (
                <p>No indicator in the active bundle matched this incident.</p>
              )}
            </ReportSection>

            <ReportSection n="5" title="Risk breakdown">
              <table className="w-full text-[12px]">
                <tbody>
                  {reportInc.riskBreakdown.map((b) => (
                    <tr key={b.label}>
                      <td className="w-[190px] py-[2px] text-ink">{b.label}</td>
                      <td className="w-[60px] py-[2px] font-mono tabular-nums text-ink">+{b.value}</td>
                      <td className="py-[2px] text-ink2">{b.reason}</td>
                    </tr>
                  ))}
                  <tr className="border-t border-border">
                    <td className="py-[3px] font-semibold text-ink">Total</td>
                    <td className="py-[3px] font-mono font-semibold tabular-nums text-ink">{reportInc.risk}</td>
                    <td />
                  </tr>
                </tbody>
              </table>
            </ReportSection>

            <ReportSection n="6" title="Recommended actions">
              <p className="mb-2 text-ink2">
                Advisory only. Enforcement is performed by an authorised process outside DiodeWatch.
              </p>
              {(["Immediate", "Short-term", "Hardening"] as const).map((g) => (
                <div key={g} className="mb-2">
                  <div className="text-[11px] font-semibold uppercase tracking-wide text-ink2">{g}</div>
                  <ul className="mt-1 list-disc pl-5">
                    {reportInc.recommendedActions
                      .filter((a) => a.group === g)
                      .map((a) => (
                        <li key={a.id} className="text-[12px]">
                          {a.text} <span className="text-ink2">({a.rationale})</span>
                        </li>
                      ))}
                  </ul>
                </div>
              ))}
            </ReportSection>

            <ReportSection n="7" title="Integrity appendix">
              <KeyValue
                rows={[
                  { k: "Evidence records", v: <span className="font-mono tabular-nums">{evidence.length}</span> },
                  {
                    k: "Chain head SHA-256",
                    v: <span className="font-mono break-all text-[11.5px]">{chainHead || "not computed"}</span>,
                  },
                  { k: "Verification method", v: "SHA-256(previous hash | record content), computed in the browser" },
                  { k: "Chain status", v: chainVerified ? "Verified" : tampered ? "Broken" : "Not yet verified" },
                ]}
              />
            </ReportSection>
          </div>
        ) : (
          <div className="px-3 py-6 text-[12px] text-ink2">
            Select an incident and generate the report. The preview is produced from the incident
            record, the evidence chain head and the current risk breakdown.
          </div>
        )}
      </Panel>

      {/* Evidence integrity */}
      <Panel data-demo-id="evidence-panel">
        <PanelHeader
          title="Evidence integrity"
          subtitle="Append-only record chain, SHA-256 computed with the Web Crypto API"
          icon={<Fingerprint size={13} strokeWidth={1.6} />}
          right={
            <>
              <Button variant="primary" onClick={() => void verifyChain()} disabled={verifying}>
                <CheckCircle2 size={13} strokeWidth={1.6} /> {verifying ? "Verifying…" : "Verify chain"}
              </Button>
              <Button variant="danger" onClick={simulateTamper} data-demo-id="tamper-button">
                <AlertTriangle size={13} strokeWidth={1.6} /> Demo control: simulate tampering
              </Button>
              <Button variant="default" onClick={() => void restoreChain()}>
                <Undo2 size={13} strokeWidth={1.6} /> Restore
              </Button>
            </>
          }
        />
        <div className="max-h-[360px] overflow-auto">
          <Table head={["#", "Record type", "Timestamp (UTC)", "Reference", "SHA-256", "Previous hash", "Status"]}>
            {evidence.map((r, i) => {
              const reached = verifyIndex > i;
              const status = verifying ? (reached ? "Verified" : "Pending") : r.status;
              return (
                <tr key={r.index} className="hover:bg-[#f7f8fa]">
                  <Td mono className="tabular-nums">
                    {r.index}
                  </Td>
                  <Td>{r.recordType}</Td>
                  <Td mono>{r.ts.replace("T", " ").replace("Z", "")}</Td>
                  <Td mono>{r.ref}</Td>
                  <Td mono className="break-all">
                    {shortHash(r.hash, 14, 8)}
                  </Td>
                  <Td mono className="break-all">
                    {shortHash(r.prevHash, 10, 6)}
                  </Td>
                  <Td>
                    <StatusPill status={status} />
                  </Td>
                </tr>
              );
            })}
          </Table>
        </div>
        <div className="border-t border-border bg-[#f7f8fa] px-3 py-2 text-[11.5px] leading-relaxed text-ink2">
          {chainVerified
            ? "Chain verified. Every record digest matches the recomputed SHA-256 of its content and the preceding hash."
            : tampered
            ? "Chain broken. Record 6 content does not match its stored digest, so record 6 and every record after it are flagged. Use Restore to reset the record set."
            : "Verification recomputes each digest in order. A mismatch invalidates the record and every record that follows it."}
        </div>
      </Panel>
    </div>
  );
}

function ReportSection({
  n,
  title,
  children,
}: {
  n: string;
  title: string;
  children: React.ReactNode;
}) {
  return (
    <section className="mb-4">
      <h3 className="mb-1.5 border-b border-border pb-1 text-[13px] font-semibold text-ink">
        {n}. {title}
      </h3>
      <div className="text-[12px] leading-relaxed text-ink">{children}</div>
    </section>
  );
}
