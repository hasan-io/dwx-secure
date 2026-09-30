import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  CartesianGrid,
  Line,
  LineChart,
  ReferenceDot,
  ReferenceLine,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import {
  AlertTriangle,
  ChevronDown,
  ChevronRight,
  Copy,
  FileJson,
  Layers,
  ShieldAlert,
  Target,
} from "lucide-react";
import {
  Button,
  CategoryTag,
  Chip,
  Drawer,
  KeyValue,
  Panel,
  PanelHeader,
  Select,
  SeverityBadge,
  StatusPill,
  Table,
  Tabs,
  Td,
} from "./ui";
import { AssetChip } from "./AppShell";
import { AXIS, ChartTooltip } from "./charts";
import { FeatureChart } from "./FeatureChart";
import { useDemo } from "../store/store";
import { CATEGORY_COLOR, fmtBytes, fmtTime, fmtUtc, shortHash } from "../lib/utils";
import type { Finding, Incident } from "../lib/types";

const KILL_CHAIN_STAGES = [
  "Reconnaissance",
  "Weaponisation",
  "Delivery",
  "Command & Control",
  "Persistence",
  "Exfiltration",
  "Impact",
];

const ONE_DIRECTION_FACTOR = 0.92;

function riskBand(risk: number) {
  if (risk >= 90) return "#A32020";
  if (risk >= 70) return "#C2410C";
  if (risk >= 50) return "#B7791F";
  return "#3E6B57";
}

export function Investigation({ incident }: { incident: Incident }) {
  const navigate = useNavigate();
  const visibilityMode = useDemo((s) => s.visibilityMode);
  const setStatus = useDemo((s) => s.setStatus);
  const addNote = useDemo((s) => s.addNote);
  const evidence = useDemo((s) => s.evidence);
  const [tab, setTab] = useState("findings");
  const [openFinding, setOpenFinding] = useState<string | null>(incident.findings[0]?.id ?? null);
  const [whyOpen, setWhyOpen] = useState(false);
  const [alertOpen, setAlertOpen] = useState(false);
  const [note, setNote] = useState("");
  const [copied, setCopied] = React.useState(false);

  const conf = (c: number) => (visibilityMode === "one" ? Number((c * ONE_DIRECTION_FACTOR).toFixed(2)) : c);

  const activeStages = incident.killChain.map((k) => k.stage);
  const total = incident.riskBreakdown.reduce((a, b) => a + b.value, 0);
  const chainHead = evidence.length ? evidence[evidence.length - 1].hash : "";

  const alertJson = JSON.stringify(
    {
      schema: "diode-alert/1.0",
      generated: "2026-09-30T12:00:00Z",
      incident_id: incident.id,
      entity: {
        ip: incident.entity,
        hostname: incident.hostname,
        asset_criticality: incident.entity === "10.0.5.20" ? "Critical" : incident.entity === "10.2.3.15" ? "High" : "Medium",
      },
      findings: incident.findings.map((f) => ({
        id: f.id,
        ts: f.ts,
        category: f.category,
        title: f.title,
        detector: f.detector,
        observed_direction: f.direction,
        confidence: conf(f.confidence),
        risk_contribution: f.risk,
        evidence_refs: f.evidenceRefs,
      })),
      confidence: conf(incident.confidence),
      risk: incident.risk,
      risk_breakdown: incident.riskBreakdown,
      kill_chain: incident.killChain,
      ti_matches: incident.tiMatches,
      evidence_refs: incident.findings.flatMap((f) => f.evidenceRefs),
      recommended_actions: incident.recommendedActions.map((a) => ({
        id: a.id,
        group: a.group,
        text: a.text,
        artifact_type: a.artifactType ?? null,
      })),
      integrity_hash: chainHead,
      transmit_path: "none",
      enforcement: "external — authorised change process",
    },
    null,
    2
  );

  return (
    <div className="space-y-3">
      {/* Header */}
      <Panel data-demo-id="incident-header">
        <div className="flex flex-wrap items-start justify-between gap-3 px-3 py-2.5">
          <div className="min-w-[320px]">
            <div className="flex items-center gap-2">
              <span className="font-mono text-[15px] font-semibold text-ink">{incident.id}</span>
              <SeverityBadge severity={incident.severity} />
              <StatusPill status={incident.status} />
              {incident.createdByRetroHunt ? <Chip title="Created by retro-hunt RH-2026-09-30-B">Retro-hunt</Chip> : null}
            </div>
            <div className="mt-1 text-[13px] font-medium text-ink">{incident.title}</div>
            <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-[11.5px] text-ink2">
              <span>
                Entity{" "}
                <AssetChip ip={incident.entity} />{" "}
                {incident.hostname ? <span className="text-ink">({incident.hostname})</span> : null}
              </span>
              <span>·</span>
              <span>
                First seen <span className="font-mono">{fmtUtc(incident.firstSeen)}</span>
              </span>
              <span>·</span>
              <span>
                Last seen <span className="font-mono">{fmtUtc(incident.lastSeen)}</span>
              </span>
              <span>·</span>
              <span>
                Findings <span className="font-mono tabular-nums">{incident.findings.length}</span>
              </span>
            </div>
            <p className="mt-1.5 max-w-[820px] text-[12px] leading-relaxed text-ink2">{incident.summary}</p>
          </div>
          <div className="flex items-stretch gap-3">
            <div className="rounded border border-border px-3 py-2 text-center">
              <div className="text-[10.5px] uppercase tracking-wide text-ink2">Risk</div>
              <div className="font-mono text-[26px] font-semibold leading-none tabular-nums" style={{ color: riskBand(incident.risk) }}>
                {incident.risk}
              </div>
              <div className="mt-0.5 text-[10.5px] text-ink2">{incident.severity}</div>
            </div>
            <div className="rounded border border-border px-3 py-2 text-center">
              <div className="text-[10.5px] uppercase tracking-wide text-ink2">Confidence</div>
              <div className="font-mono text-[26px] font-semibold leading-none tabular-nums text-ink">
                {conf(incident.confidence).toFixed(2)}
              </div>
              <div className="mt-0.5 text-[10.5px] text-ink2">
                {visibilityMode === "one" ? "one-direction adjusted" : "both directions"}
              </div>
            </div>
            <div className="flex flex-col justify-between gap-2">
              <Select
                label="Status"
                value={incident.status}
                onChange={(v) => setStatus(incident.id, v as Incident["status"])}
                options={[
                  { value: "Open", label: "Open" },
                  { value: "Investigating", label: "Investigating" },
                  { value: "Resolved", label: "Resolved" },
                ]}
              />
              <Button variant="default" onClick={() => setAlertOpen(true)}>
                <FileJson size={13} strokeWidth={1.6} /> Structured alert
              </Button>
            </div>
          </div>
        </div>
      </Panel>

      {/* Risk over time + breakdown */}
      <div className="grid grid-cols-3 gap-3">
        <Panel className="col-span-2" data-demo-id="risk-timeline">
          <PanelHeader
            title="Risk over time"
            subtitle="Cumulative incident risk at each finding"
            icon={<Target size={13} strokeWidth={1.6} />}
          />
          <div className="px-2 pt-3" style={{ height: 190 }}>
            <ResponsiveContainer width="100%" height="100%">
              <LineChart
                data={incident.riskHistory.map((r) => ({ ...r, label: fmtTime(r.ts) }))}
                margin={{ left: 0, right: 12, top: 8 }}
              >
                <CartesianGrid stroke="#E6E9EE" vertical={false} />
                <XAxis dataKey="label" {...AXIS} />
                <YAxis domain={[0, 100]} {...AXIS} width={28} />
                <Tooltip content={<ChartTooltip />} />
                <ReferenceLine y={90} stroke="#A32020" strokeDasharray="3 3" strokeWidth={1} />
                <ReferenceLine y={70} stroke="#C2410C" strokeDasharray="3 3" strokeWidth={1} />
                <ReferenceLine y={50} stroke="#B7791F" strokeDasharray="3 3" strokeWidth={1} />
                <Line
                  type="stepAfter"
                  dataKey="risk"
                  name="Risk"
                  stroke="#1F3A5F"
                  strokeWidth={1.6}
                  dot={{ r: 2.5, fill: "#1F3A5F" }}
                />
                {incident.riskHistory.map((r) => (
                  <ReferenceDot
                    key={r.ts}
                    x={fmtTime(r.ts)}
                    y={r.risk}
                    r={3}
                    fill={riskBand(r.risk)}
                    stroke="#fff"
                    label={{ value: r.risk, position: "top", fontSize: 10, fill: "#1F2933" }}
                  />
                ))}
              </LineChart>
            </ResponsiveContainer>
          </div>
          <div className="flex flex-wrap items-center gap-x-3 gap-y-1 border-t border-border px-3 py-1.5 text-[10.5px] text-ink2">
            <span className="inline-flex items-center gap-1">
              <span className="inline-block h-[2px] w-4" style={{ background: "#A32020" }} /> Critical ≥ 90
            </span>
            <span className="inline-flex items-center gap-1">
              <span className="inline-block h-[2px] w-4" style={{ background: "#C2410C" }} /> High ≥ 70
            </span>
            <span className="inline-flex items-center gap-1">
              <span className="inline-block h-[2px] w-4" style={{ background: "#B7791F" }} /> Medium ≥ 50
            </span>
            <span className="inline-flex items-center gap-1">
              <span className="inline-block h-[2px] w-4" style={{ background: "#3E6B57" }} /> Low
            </span>
          </div>
        </Panel>

        <Panel>
          <PanelHeader
            title="Risk breakdown"
            subtitle={`Total ${incident.risk} of 100`}
            icon={<Layers size={13} strokeWidth={1.6} />}
          />
          <div className="px-3 pt-3">
            <div className="flex h-[16px] w-full overflow-hidden rounded-[2px] border border-border">
              {incident.riskBreakdown.map((b) => (
                <div
                  key={b.label}
                  title={`${b.label} +${b.value}`}
                  style={{
                    width: `${(b.value / 100) * 100}%`,
                    backgroundColor:
                      b.label === "Detection evidence"
                        ? "#1F3A5F"
                        : b.label === "Kill-chain progression"
                        ? "#2F5D9E"
                        : b.label === "Persistence"
                        ? "#5B6773"
                        : b.label === "Asset criticality"
                        ? "#B7791F"
                        : "#A32020",
                  }}
                />
              ))}
            </div>
            <table className="mt-2 w-full text-[11.5px]">
              <tbody>
                {incident.riskBreakdown.map((b) => (
                  <tr key={b.label}>
                    <td className="py-[2px] pr-2">
                      <span className="inline-block h-2 w-2 rounded-full" style={{ backgroundColor:
                        b.label === "Detection evidence" ? "#1F3A5F" : b.label === "Kill-chain progression" ? "#2F5D9E" : b.label === "Persistence" ? "#5B6773" : b.label === "Asset criticality" ? "#B7791F" : "#A32020" }} />
                    </td>
                    <td className="py-[2px] text-ink2">{b.label}</td>
                    <td className="py-[2px] text-right font-mono tabular-nums text-ink">+{b.value}</td>
                  </tr>
                ))}
                <tr className="border-t border-border">
                  <td />
                  <td className="py-[3px] font-semibold text-ink">Total</td>
                  <td className="py-[3px] text-right font-mono font-semibold tabular-nums text-ink">{total}</td>
                </tr>
              </tbody>
            </table>
            <button
              data-demo-id="why-score"
              onClick={() => setWhyOpen((prev) => !prev)}
              className="mt-1 flex w-full items-center gap-1 rounded border border-border bg-[#f7f8fa] px-2 py-[5px] text-left text-[11.5px] font-medium text-ink hover:border-navy"
            >
              {whyOpen ? <ChevronDown size={12} strokeWidth={1.6} /> : <ChevronRight size={12} strokeWidth={1.6} />}
              Why this score?
            </button>
            {whyOpen ? (
              <ul className="mt-1.5 space-y-1.5">
                {incident.riskBreakdown.map((b) => (
                  <li key={b.label} className="rounded border border-border px-2 py-1.5">
                    <div className="flex items-center justify-between text-[11.5px]">
                      <span className="font-medium text-ink">{b.label}</span>
                      <span className="font-mono tabular-nums text-ink2">+{b.value}</span>
                    </div>
                    <p className="mt-[2px] text-[11px] leading-snug text-ink2">{b.reason}</p>
                  </li>
                ))}
              </ul>
            ) : null}
          </div>
        </Panel>
      </div>

      {/* Kill chain + findings timeline */}
      <div className="grid grid-cols-3 gap-3">
        <Panel>
          <PanelHeader title="Kill-chain progression" subtitle="Observed stages only" icon={<Layers size={13} strokeWidth={1.6} />} />
          <div className="space-y-1 px-3 py-2.5">
            {KILL_CHAIN_STAGES.map((s) => {
              const active = activeStages.includes(s);
              const stage = incident.killChain.find((k) => k.stage === s);
              return (
                <div
                  key={s}
                  className={`flex items-start gap-2 rounded-[3px] border px-2 py-[6px] ${
                    active ? "border-navy bg-navy-soft" : "border-border bg-white"
                  }`}
                >
                  <span
                    className={`mt-[3px] inline-block h-2 w-2 rounded-full ${
                      active ? "bg-navy" : "bg-[#D8DDE4]"
                    }`}
                  />
                  <div>
                    <div className={`text-[12px] ${active ? "font-semibold text-navy" : "text-ink3"}`}>{s}</div>
                    {active && stage ? (
                      <div className="mt-[2px] text-[11px] leading-snug text-ink2">
                        <span className="font-mono">{fmtUtc(stage.ts ?? "")}</span> — {stage.detail}
                      </div>
                    ) : null}
                  </div>
                </div>
              );
            })}
          </div>
        </Panel>

        <Panel className="col-span-2">
          <PanelHeader
            title="Findings timeline"
            subtitle="Chronological, one row per detection"
            icon={<ShieldAlert size={13} strokeWidth={1.6} />}
          />
          <div className="max-h-[360px] overflow-auto px-3 py-2">
            <ol className="relative space-y-2 border-l border-border pl-3">
              {incident.findings.map((f) => {
                const open = openFinding === f.id;
                return (
                  <li key={f.id} className="relative">
                    <span
                      className="absolute -left-[15px] top-[6px] inline-block h-2 w-2 rounded-full"
                      style={{ backgroundColor: CATEGORY_COLOR[f.category] }}
                    />
                    <button
                      onClick={() => setOpenFinding(open ? null : f.id)}
                      className="w-full rounded border border-border bg-white px-2 py-1.5 text-left hover:border-navy"
                    >
                      <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                        <span className="font-mono text-[11.5px] text-ink2">{fmtUtc(f.ts)}</span>
                        <CategoryTag category={f.category} />
                        <span className="text-[12px] font-medium text-ink">{f.title}</span>
                        <span className="ml-auto flex items-center gap-2 text-[11px] text-ink2">
                          <span className="font-mono tabular-nums">conf {conf(f.confidence).toFixed(2)}</span>
                          <span className="font-mono tabular-nums">risk {f.risk}</span>
                          {open ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
                        </span>
                      </div>
                    </button>
                    {open ? (
                      <div className="mt-1 space-y-2 rounded border border-border bg-[#fbfbfc] px-2 py-2">
                        <p className="text-[12px] leading-relaxed text-ink">{f.detail}</p>
                        <KeyValue
                          rows={[
                            { k: "Detector", v: <span className="font-mono text-[11.5px]">{f.detector}</span> },
                            { k: "Observed direction", v: f.direction },
                            { k: "Evidence refs", v: <span className="font-mono text-[11.5px]">{f.evidenceRefs.join(", ")}</span> },
                            { k: "Confidence", v: <span className="font-mono tabular-nums">{conf(f.confidence).toFixed(2)}</span> },
                          ]}
                        />
                        <Table head={["Feature", "Observed", "Threshold", "Baseline", "Verdict"]}>
                          {f.features.map((row) => (
                            <tr key={row.feature}>
                              <Td>{row.feature}</Td>
                              <Td mono>{row.value}</Td>
                              <Td mono>{row.threshold}</Td>
                              <Td mono>{row.baseline}</Td>
                              <Td>
                                <span
                                  className={
                                    row.verdict === "above"
                                      ? "text-[#A32020]"
                                      : row.verdict === "below"
                                      ? "text-[#2F5D9E]"
                                      : row.verdict === "match"
                                      ? "text-[#B7791F]"
                                      : "text-ink2"
                                  }
                                >
                                  {row.verdict === "above"
                                    ? "above threshold"
                                    : row.verdict === "below"
                                    ? "below threshold"
                                    : row.verdict === "match"
                                    ? "pattern match"
                                    : "neutral"}
                                </span>
                              </Td>
                            </tr>
                          ))}
                        </Table>
                        <FeatureChart kind={f.chart ?? "packet"} seed={f.id.length * 37 + f.risk} />
                      </div>
                    ) : null}
                  </li>
                );
              })}
            </ol>
          </div>
        </Panel>
      </div>

      {/* Evidence tabs */}
      <Panel>
        <PanelHeader
          title="Evidence"
          subtitle="Feature, DNS, TLS, flow and threat-intel records for this incident"
          icon={<Layers size={13} strokeWidth={1.6} />}
        />
        <Tabs
          tabs={[
            { id: "findings", label: "Findings" },
            { id: "features", label: "Features" },
            { id: "dns", label: "DNS" },
            { id: "tls", label: "TLS" },
            { id: "flows", label: "Flows" },
            { id: "ti", label: "Threat intelligence" },
          ]}
          active={tab}
          onChange={setTab}
        />
        <div className="max-h-[420px] overflow-auto">
          {tab === "findings" ? (
            <Table head={["ID", "Time (UTC)", "Category", "Detector", "Direction", "Confidence", "Risk", "Evidence"]}>
              {incident.findings.map((f) => (
                <tr key={f.id} className="hover:bg-[#f7f8fa]">
                  <Td mono>{f.id}</Td>
                  <Td mono>{fmtUtc(f.ts)}</Td>
                  <Td>
                    <CategoryTag category={f.category} />
                  </Td>
                  <Td mono>{f.detector}</Td>
                  <Td>{f.direction}</Td>
                  <Td mono className="tabular-nums">
                    {conf(f.confidence).toFixed(2)}
                  </Td>
                  <Td mono className="tabular-nums">
                    {f.risk}
                  </Td>
                  <Td mono>{f.evidenceRefs.join(", ")}</Td>
                </tr>
              ))}
            </Table>
          ) : null}

          {tab === "features" ? (
            <div className="space-y-3 p-3">
              {incident.findings.map((f) => (
                <div key={f.id} className="rounded border border-border">
                  <div className="flex items-center gap-2 border-b border-border bg-[#f7f8fa] px-2 py-[6px]">
                    <span className="font-mono text-[11.5px] text-ink2">{f.id}</span>
                    <CategoryTag category={f.category} />
                    <span className="text-[12px] font-medium text-ink">{f.title}</span>
                  </div>
                  <div className="grid grid-cols-2 gap-3 p-2">
                    <Table head={["Feature", "Observed", "Threshold", "Baseline"]}>
                      {f.features.map((row) => (
                        <tr key={row.feature}>
                          <Td>{row.feature}</Td>
                          <Td mono>{row.value}</Td>
                          <Td mono>{row.threshold}</Td>
                          <Td mono>{row.baseline}</Td>
                        </tr>
                      ))}
                    </Table>
                    <FeatureChart kind={f.chart ?? "packet"} seed={f.id.length * 53 + f.risk} />
                  </div>
                </div>
              ))}
            </div>
          ) : null}

          {tab === "dns" ? (
            <Table head={["Time (UTC)", "Query", "Type", "Response", "Label entropy", "Length", "NXDOMAIN"]}>
              {incident.dns.map((d, i) => (
                <tr key={i} className="hover:bg-[#f7f8fa]">
                  <Td mono>{fmtUtc(d.ts)}</Td>
                  <Td mono>{d.query}</Td>
                  <Td>{d.type}</Td>
                  <Td mono>{d.response}</Td>
                  <Td mono className="tabular-nums">
                    {d.entropy.toFixed(2)}
                  </Td>
                  <Td mono className="tabular-nums">
                    {d.length}
                  </Td>
                  <Td>
                    {d.nxdomain ? (
                      <span className="text-[#A32020]">NXDOMAIN</span>
                    ) : (
                      <span className="text-ink3">—</span>
                    )}
                  </Td>
                </tr>
              ))}
            </Table>
          ) : null}

          {tab === "tls" ? (
            incident.tls.length ? (
              <Table head={["Time (UTC)", "Src", "Dst", "SNI", "JA4", "ALPN", "Certificate", "Validity", "EPS score", "Bytes"]}>
                {incident.tls.map((t, i) => (
                  <tr key={i} className="hover:bg-[#f7f8fa]">
                    <Td mono>{fmtUtc(t.ts)}</Td>
                    <Td mono>{t.src}</Td>
                    <Td mono>{t.dst}</Td>
                    <Td mono>{t.sni}</Td>
                    <Td mono className="break-all">
                      {t.ja4}
                    </Td>
                    <Td>{t.alpn}</Td>
                    <Td>
                      <div className="leading-snug">
                        <div className="font-mono text-[11px]">{t.certSubject}</div>
                        <div className="text-[10.5px] text-ink2">
                          {t.certIssuer} {t.selfSigned ? "· self-signed" : ""}
                        </div>
                      </div>
                    </Td>
                    <Td mono className="tabular-nums">
                      {t.certValidityDays} d
                    </Td>
                    <Td mono className="tabular-nums">
                      {t.epsScore.toFixed(2)}
                    </Td>
                    <Td mono className="tabular-nums">
                      {fmtBytes(t.bytes)}
                    </Td>
                  </tr>
                ))}
              </Table>
            ) : (
              <div className="px-3 py-6 text-[12px] text-ink2">
                No TLS sessions recorded for this incident. The scan was carried over plain TCP.
              </div>
            )
          ) : null}

          {tab === "flows" ? (
            <Table head={["Time (UTC)", "Source", "Destination", "Proto", "Packets", "Bytes", "Duration", "Direction", "Tags"]}>
              {incident.flows.map((f, i) => (
                <tr key={i} className="hover:bg-[#f7f8fa]">
                  <Td mono>{fmtUtc(f.ts)}</Td>
                  <Td mono>
                    {f.src}:{f.srcPort}
                  </Td>
                  <Td mono>
                    {f.dst}:{f.dstPort}
                  </Td>
                  <Td>{f.proto}</Td>
                  <Td mono className="tabular-nums">
                    {f.packets}
                  </Td>
                  <Td mono className="tabular-nums">
                    {fmtBytes(f.bytes)}
                  </Td>
                  <Td mono className="tabular-nums">
                    {f.durationS} s
                  </Td>
                  <Td>{f.direction}</Td>
                  <Td>
                    <span className="flex flex-wrap gap-1">
                      {f.tags.map((t) => (
                        <span key={t} className="rounded-[3px] bg-[#f0f2f5] px-1 py-[1px] text-[10.5px] text-ink2">
                          {t}
                        </span>
                      ))}
                    </span>
                  </Td>
                </tr>
              ))}
            </Table>
          ) : null}

          {tab === "ti" ? (
            incident.tiMatches.length ? (
              <Table head={["Indicator", "Type", "Source", "First seen", "Confidence", "Origin", "Context"]}>
                {incident.tiMatches.map((m, i) => (
                  <tr key={i} className="hover:bg-[#f7f8fa]">
                    <Td mono className="break-all">
                      {m.indicator}
                    </Td>
                    <Td>{m.type}</Td>
                    <Td>{m.source}</Td>
                    <Td mono>{m.firstSeen}</Td>
                    <Td mono className="tabular-nums">
                      {m.confidence.toFixed(2)}
                    </Td>
                    <Td>
                      <Chip>{m.origin === "retro-hunt" ? "Retro-hunt" : "Current bundle"}</Chip>
                    </Td>
                    <Td className="max-w-[380px] whitespace-normal text-[11.5px] text-ink2">{m.context}</Td>
                  </tr>
                ))}
              </Table>
            ) : (
              <div className="px-3 py-6 text-[12px] text-ink2">
                No indicator in the active bundle matches this incident. Import DW-TI-2026-09-30-B and
                run the retro-hunt to extend the search window.
              </div>
            )
          ) : null}
        </div>
      </Panel>

      {/* DDoS evidence note */}
      {incident.id === "INC-0418" ? (
        <Panel data-demo-id="ddos-note">
          <PanelHeader title="Source interpretation" subtitle="Why per-source blocking is not recommended" icon={<AlertTriangle size={13} strokeWidth={1.6} />} />
          <div className="px-3 py-2.5 text-[12px] leading-relaxed text-ink2">
            The 412 UDP sources are reflectors — third-party DNS, NTP and memcached resolvers returning
            amplified responses to a spoofed victim address. The SYN flood shows 91% single-packet
            sources with high source-address entropy, which indicates spoofing. Neither population
            represents attacker infrastructure. Filtering by source address would remove legitimate
            resolver traffic without reducing the attack volume. The recommended response is upstream
            absorption and rate-limiting, requested through the out-of-band change process.
          </div>
        </Panel>
      ) : null}

      {/* Recommended actions */}
      <Panel>
        <PanelHeader
          title="Recommended actions"
          subtitle="Advisory only. Enforcement is performed by an authorised process outside DiodeWatch."
          icon={<Target size={13} strokeWidth={1.6} />}
          right={
            <Button variant="primary" onClick={() => navigate("/response")}>
              Generate mitigation package
            </Button>
          }
        />
        <div className="grid grid-cols-3 gap-0 divide-x divide-border">
          {(["Immediate", "Short-term", "Hardening"] as const).map((group) => (
            <div key={group} className="px-3 py-2.5">
              <div className="mb-1.5 text-[11px] font-semibold uppercase tracking-wide text-ink2">
                {group}
              </div>
              <ul className="space-y-2">
                {incident.recommendedActions
                  .filter((a) => a.group === group)
                  .map((a) => (
                    <li key={a.id} className="rounded border border-border bg-white px-2 py-1.5">
                      <div className="flex items-start gap-2">
                        <span className="mt-[3px] inline-block h-1.5 w-1.5 shrink-0 rounded-full bg-navy" />
                        <div>
                          <div className="text-[12px] leading-snug text-ink">{a.text}</div>
                          <div className="mt-[3px] text-[11px] leading-snug text-ink2">{a.rationale}</div>
                          {a.artifactType ? (
                            <div className="mt-1">
                              <Chip>artifact: {a.artifactType}</Chip>
                            </div>
                          ) : null}
                        </div>
                      </div>
                    </li>
                  ))}
              </ul>
            </div>
          ))}
        </div>
      </Panel>

      {/* Analyst notes */}
      <Panel>
        <PanelHeader title="Analyst notes" subtitle="Recorded with the incident, included in the forensic report" />
        <div className="grid grid-cols-2 divide-x divide-border">
          <div className="px-3 py-2.5">
            {incident.notes.length ? (
              <ul className="space-y-2">
                {incident.notes.map((n, i) => (
                  <li key={i} className="rounded border border-border bg-[#fbfbfc] px-2 py-1.5">
                    <div className="flex items-center justify-between text-[11px] text-ink2">
                      <span>{n.author}</span>
                      <span className="font-mono">{fmtUtc(n.ts)}</span>
                    </div>
                    <p className="mt-1 text-[12px] leading-snug text-ink">{n.text}</p>
                  </li>
                ))}
              </ul>
            ) : (
              <div className="text-[12px] text-ink2">No notes recorded for this incident.</div>
            )}
          </div>
          <div className="px-3 py-2.5">
            <textarea
              value={note}
              onChange={(e) => setNote(e.target.value)}
              placeholder="Add an analyst note. Notes are stored with the incident and hashed into the evidence chain."
              className="h-[92px] w-full resize-none rounded border border-border-strong bg-white px-2 py-1.5 text-[12px] text-ink placeholder:text-ink3 focus:border-navy focus:outline-none"
            />
            <div className="mt-2 flex items-center gap-2">
              <Button
                variant="primary"
                disabled={!note.trim()}
                onClick={() => {
                  addNote(incident.id, note.trim());
                  setNote("");
                }}
              >
                Save note
              </Button>
              <span className="text-[11px] text-ink2">Attributed to Analyst | SOC-1, 2026-09-30 12:00 UTC</span>
            </div>
          </div>
        </div>
      </Panel>

      {/* Structured alert drawer */}
      <Drawer
        open={alertOpen}
        onClose={() => setAlertOpen(false)}
        title={`Structured alert — ${incident.id}`}
        subtitle="Machine-readable incident record, including evidence references and integrity hash"
        footer={
          <>
            <span className="text-[11px] text-ink2">
              integrity_hash {chainHead ? shortHash(chainHead, 16, 8) : "not computed"}
            </span>
            <Button
              variant="primary"
              onClick={() => {
                void navigator.clipboard?.writeText(alertJson);
                setCopied(true);
                setTimeout(() => setCopied(false), 2000);
              }}
            >
              <Copy size={13} strokeWidth={1.6} /> {copied ? "Copied" : "Copy JSON"}
            </Button>
          </>
        }
      >
        <pre className="whitespace-pre-wrap break-all rounded border border-border bg-[#fbfbfc] p-2 font-mono text-[11px] leading-relaxed text-ink">
          {alertJson}
        </pre>
      </Drawer>
    </div>
  );
}

export function FindingBadge({ f }: { f: Finding }) {
  return <CategoryTag category={f.category} />;
}
