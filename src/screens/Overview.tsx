import { Link } from "react-router-dom";
import {
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import {
  ArrowDownRight,
  ArrowDownToLine,
  ArrowUpRight,
  CheckCircle2,
  Clock,
  Database,
  Gauge,
  Layers,
  Lock,
  Minus,
  ShieldAlert,
  Waves,
} from "lucide-react";
import {
  Button,
  CategoryTag,
  Chip,
  Panel,
  PanelHeader,
  SeverityBadge,
  Table,
  Td,
} from "../components/ui";
import { AssetChip } from "../components/AppShell";
import { AXIS, ChartTooltip, LegendRow } from "../components/charts";
import { MiniBar, Sparkline } from "../components/Sparkline";
import { PipelineStrip } from "../components/PipelineStrip";
import { useDemo } from "../store/store";
import {
  DIRECTION_COVERAGE,
  FINDINGS_BY_CATEGORY,
  ONEWAY_INTEGRITY,
  OVERVIEW_KPI,
  SENSOR,
} from "../data/metrics";
import { TI_BUNDLES } from "../data/iocs";
import { CATEGORY_COLOR, SEVERITY_COLOR } from "../lib/utils";

const CATEGORIES = [
  "Reconnaissance",
  "C2 Beaconing",
  "DGA/DNS Tunnelling",
  "Encrypted Malware",
  "Exfiltration",
  "DDoS",
];

const SPARKS = {
  incidents: [3, 4, 4, 5, 4, 5, 6, 6],
  criticalHigh: [1, 1, 2, 2, 2, 2, 3, 3],
  findings: [6, 9, 7, 11, 8, 12, 10, 14],
  mttd: [14.2, 13.1, 12.6, 12.1, 11.4, 10.2, 9.8, 9.4],
  flows: [38, 39, 41, 40, 42, 41, 43, 41],
};

function Trend({ dir, text }: { dir: "up" | "down" | "flat"; text: string }) {
  const Icon = dir === "up" ? ArrowUpRight : dir === "down" ? ArrowDownRight : Minus;
  const color = dir === "up" ? "#C2410C" : dir === "down" ? "#3E6B57" : "#5B6773";
  return (
    <span className="inline-flex items-center gap-1 text-[11px]" style={{ color }}>
      <Icon size={11} strokeWidth={1.8} />
      {text}
    </span>
  );
}

function KpiCard({
  label,
  value,
  unit,
  accent,
  spark,
  trend,
  sub,
}: {
  label: string;
  value: string | number;
  unit?: string;
  accent: string;
  spark: number[];
  trend?: { dir: "up" | "down" | "flat"; text: string };
  sub?: string;
}) {
  return (
    <div className="relative flex items-start gap-3 px-3.5 py-3">
      <span
        aria-hidden
        className="absolute left-0 top-3 bottom-3 w-[3px] rounded-r-[2px]"
        style={{ backgroundColor: accent }}
      />
      <div className="min-w-0 flex-1">
        <div className="truncate text-[10.5px] font-semibold uppercase tracking-[0.05em] text-ink2">
          {label}
        </div>
        <div className="mt-1.5 flex items-baseline gap-1">
          <span
            className="font-mono text-[26px] font-semibold leading-none tabular-nums"
            style={{ color: accent }}
          >
            {value}
          </span>
          {unit ? <span className="text-[11px] text-ink2">{unit}</span> : null}
        </div>
        <div className="mt-1.5 flex items-center gap-2">
          {trend ? <Trend dir={trend.dir} text={trend.text} /> : null}
          {sub ? <span className="truncate text-[11px] text-ink2">{sub}</span> : null}
        </div>
      </div>
      <Sparkline data={spark} color={accent} width={62} />
    </div>
  );
}

export default function Overview() {
  const incidents = useDemo((s) => s.incidents);
  const bundleImported = useDemo((s) => s.bundleImported);
  const retroHuntStatus = useDemo((s) => s.retroHuntStatus);

  const visible = incidents.filter((i) => !i.hiddenUntilRetroHunt);
  const open = visible.filter((i) => i.status !== "Resolved");
  const topRisk = [...visible].sort((a, b) => b.risk - a.risk).slice(0, 6);
  const criticalHigh = visible.filter((i) => i.severity === "Critical" || i.severity === "High").length;
  const activeBundle = bundleImported ? TI_BUNDLES[1] : TI_BUNDLES[0];

  const sevCounts = ["Critical", "High", "Medium", "Low"].map((s) => ({
    severity: s,
    count: visible.filter((i) => i.severity === s).length,
    color: SEVERITY_COLOR[s],
  }));
  const sevTotal = sevCounts.reduce((a, b) => a + b.count, 0) || 1;

  return (
    <div className="space-y-3">
      {/* Page header */}
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-[18px] font-semibold leading-tight tracking-tight text-ink">
              Monitoring overview
            </h1>
            <span className="inline-flex items-center gap-1 rounded-[3px] border border-[#3E6B57] bg-[#f1f7f3] px-1.5 py-[1px] text-[10.5px] font-semibold text-[#3E6B57]">
              <CheckCircle2 size={10} strokeWidth={2} /> Sensor healthy
            </span>
          </div>
          <p className="mt-[3px] text-[12px] text-ink2">
            Passive detection posture for {OVERVIEW_KPI.monitoredVlans} monitored segments · demo
            date 2026-09-30 · all times UTC
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Chip title="DiodeWatch observes a mirrored copy of traffic and never transmits">
            <Lock size={11} strokeWidth={1.6} /> Observation only — no return path
          </Chip>
          <Link to="/live">
            <Button variant="default">Live monitor</Button>
          </Link>
          <Link to="/incidents">
            <Button variant="primary">Open incident queue</Button>
          </Link>
        </div>
      </div>

      {/* Pipeline */}
      <PipelineStrip />

      {/* KPI strip */}
      <Panel data-demo-id="overview-status" className="grid grid-cols-5 divide-x divide-border">
        <KpiCard
          label="Active incidents"
          value={open.length}
          accent="#1F3A5F"
          spark={SPARKS.incidents}
          trend={{ dir: "up", text: "+2 / 24 h" }}
          sub={`${visible.length} in queue`}
        />
        <KpiCard
          label="Critical / High"
          value={criticalHigh}
          accent="#A32020"
          spark={SPARKS.criticalHigh}
          trend={{ dir: "up", text: "+1 / 24 h" }}
          sub="risk ≥ 70"
        />
        <KpiCard
          label="Findings, 24 h"
          value={OVERVIEW_KPI.findings24h}
          accent="#C2410C"
          spark={SPARKS.findings}
          trend={{ dir: "up", text: "+4 vs prev." }}
          sub="9 detectors"
        />
        <KpiCard
          label="Time to detect"
          value={OVERVIEW_KPI.mttdMinutes}
          unit="min"
          accent="#3E6B57"
          spark={SPARKS.mttd}
          trend={{ dir: "down", text: "−2.7 min" }}
          sub={`7-day med. ${OVERVIEW_KPI.mttdBaselineMinutes}`}
        />
        <KpiCard
          label="Observed flows"
          value={(OVERVIEW_KPI.flowsPerMin / 1000).toFixed(1)}
          unit="k / min"
          accent="#2F5D9E"
          spark={SPARKS.flows}
          trend={{ dir: "flat", text: "stable" }}
          sub={`${(OVERVIEW_KPI.packetsPerSecond / 1000).toFixed(1)}k pkt/s`}
        />
      </Panel>

      {/* Severity + category */}
      <div className="grid grid-cols-3 gap-3">
        <Panel className="flex flex-col">
          <PanelHeader
            title="Incident severity"
            subtitle="Current queue composition"
            icon={<ShieldAlert size={13} strokeWidth={1.6} />}
          />
          <div className="px-3 pt-3">
            <div className="flex h-[12px] w-full overflow-hidden rounded-[2px] border border-border">
              {sevCounts.map((s) =>
                s.count ? (
                  <div
                    key={s.severity}
                    title={`${s.severity}: ${s.count}`}
                    style={{ width: `${(s.count / sevTotal) * 100}%`, backgroundColor: s.color }}
                  />
                ) : null
              )}
            </div>
            <ul className="mt-2.5 space-y-1.5">
              {sevCounts.map((s) => (
                <li key={s.severity} className="flex items-center gap-2">
                  <span
                    className="inline-block h-2 w-2 shrink-0 rounded-full"
                    style={{ backgroundColor: s.color }}
                  />
                  <span className="text-[12px] text-ink">{s.severity}</span>
                  <MiniBar value={s.count} max={sevTotal} color={s.color} width={64} />
                  <span className="ml-auto font-mono text-[12px] font-semibold tabular-nums text-ink">
                    {s.count}
                  </span>
                </li>
              ))}
            </ul>
          </div>
          <div className="mt-auto border-t border-border px-3 py-2 text-[11px] leading-snug text-ink2">
            Severity is derived from risk: Critical ≥ 90, High ≥ 70, Medium ≥ 50, Low below 50.
          </div>
        </Panel>

        <Panel className="col-span-2">
          <PanelHeader
            title="Findings by threat category"
            subtitle="Count per 3-hour bucket, last 24 hours"
            icon={<Layers size={13} strokeWidth={1.6} />}
            right={
              <Link to="/live" className="text-[12px] text-link hover:underline">
                Live detail
              </Link>
            }
          />
          <div className="px-2 pb-1 pt-3" style={{ height: 186 }}>
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={FINDINGS_BY_CATEGORY} margin={{ left: 0, right: 6, top: 4 }}>
                <CartesianGrid stroke="#EDEFF3" vertical={false} />
                <XAxis dataKey="hour" {...AXIS} />
                <YAxis {...AXIS} allowDecimals={false} width={24} />
                <Tooltip content={<ChartTooltip />} cursor={{ fill: "#F3F5F8" }} />
                {CATEGORIES.map((c, i) => (
                  <Bar
                    key={c}
                    dataKey={c}
                    stackId="a"
                    fill={CATEGORY_COLOR[c]}
                    barSize={14}
                    radius={i === CATEGORIES.length - 1 ? [2, 2, 0, 0] : undefined}
                  />
                ))}
              </BarChart>
            </ResponsiveContainer>
          </div>
          <LegendRow items={CATEGORIES.map((c) => ({ label: c, color: CATEGORY_COLOR[c] }))} />
        </Panel>
      </div>

      {/* Top risk + traffic */}
      <div className="grid grid-cols-3 gap-3">
        <Panel className="col-span-2">
          <PanelHeader
            title="Top-risk incidents"
            subtitle="Ranked by current risk score"
            icon={<ShieldAlert size={13} strokeWidth={1.6} />}
            right={
              <Link to="/incidents" className="text-[12px] text-link hover:underline">
                View all
              </Link>
            }
          />
          <Table head={["Incident", "Entity", "Category", "Severity", "Risk", "Status", "Last activity"]}>
            {topRisk.map((i) => (
              <tr key={i.id} className="group hover:bg-[#f7f8fa]">
                <Td mono>
                  <Link
                    to="/incidents"
                    onClick={() => useDemo.getState().setSelected(i.id)}
                    className="font-semibold text-link hover:underline"
                  >
                    {i.id}
                  </Link>
                </Td>
                <Td mono>
                  <AssetChip ip={i.entity} />
                  {i.hostname ? <span className="ml-1.5 text-ink2">{i.hostname}</span> : null}
                </Td>
                <Td>
                  <CategoryTag category={i.category} />
                </Td>
                <Td>
                  <SeverityBadge severity={i.severity} />
                </Td>
                <Td>
                  <span className="flex items-center gap-2">
                    <MiniBar value={i.risk} color={SEVERITY_COLOR[i.severity]} width={48} />
                    <span
                      className="font-mono text-[12.5px] font-semibold tabular-nums"
                      style={{ color: SEVERITY_COLOR[i.severity] }}
                    >
                      {i.risk}
                    </span>
                  </span>
                </Td>
                <Td>{i.status}</Td>
                <Td mono>{i.lastSeen.replace("T", " ").replace("Z", "")} UTC</Td>
              </tr>
            ))}
          </Table>
        </Panel>

        <Panel>
          <PanelHeader
            title="Traffic and monitoring"
            subtitle={`${SENSOR.name} · ${SENSOR.site}`}
            icon={<Waves size={13} strokeWidth={1.6} />}
          />
          <div className="grid grid-cols-2 divide-x divide-border border-b border-border">
            <div className="px-3 py-2">
              <div className="text-[10.5px] uppercase tracking-wide text-ink2">Flows / min</div>
              <div className="mt-[3px] font-mono text-[16px] font-semibold tabular-nums text-ink">
                {OVERVIEW_KPI.flowsPerMin.toLocaleString("en-US")}
              </div>
            </div>
            <div className="px-3 py-2">
              <div className="text-[10.5px] uppercase tracking-wide text-ink2">Packets / s</div>
              <div className="mt-[3px] font-mono text-[16px] font-semibold tabular-nums text-ink">
                {OVERVIEW_KPI.packetsPerSecond.toLocaleString("en-US")}
              </div>
            </div>
          </div>
          <div className="px-3 py-2.5">
            <div className="mb-1.5 text-[10.5px] font-semibold uppercase tracking-wide text-ink2">
              Direction coverage
            </div>
            <div className="flex h-[10px] w-full overflow-hidden rounded-[2px]">
              {DIRECTION_COVERAGE.map((d) => (
                <div key={d.direction} style={{ width: `${d.share}%`, backgroundColor: d.color }} />
              ))}
            </div>
            <ul className="mt-2 space-y-1">
              {DIRECTION_COVERAGE.map((d) => (
                <li key={d.direction} className="flex items-center gap-2 text-[11.5px]">
                  <span
                    className="inline-block h-2 w-2 shrink-0 rounded-full"
                    style={{ backgroundColor: d.color }}
                  />
                  <span className="truncate text-ink2">{d.direction}</span>
                  <span className="ml-auto font-mono tabular-nums text-ink">{d.share}%</span>
                </li>
              ))}
            </ul>
            <p className="mt-2 border-t border-border pt-2 text-[11px] leading-snug text-ink2">
              29% of flows carry a single direction only. Detectors fall back to direction-tolerant
              features for those records.
            </p>
            <div className="mt-2 flex items-center justify-between text-[11px] text-ink2">
              <span>
                Uptime <span className="font-mono text-ink">{SENSOR.uptime}</span>
              </span>
              <Link to="/coverage" className="text-link hover:underline">
                Coverage detail
              </Link>
            </div>
          </div>
        </Panel>
      </div>

      {/* Integrity + TI */}
      <div className="grid grid-cols-2 gap-3">
        <Panel>
          <PanelHeader
            title="One-way integrity"
            subtitle="Sensor transmit path is physically absent"
            icon={<Lock size={13} strokeWidth={1.6} />}
            right={
              <span className="inline-flex items-center gap-1 rounded-[3px] border border-[#3E6B57] bg-[#f1f7f3] px-1.5 py-[1px] text-[11px] font-medium text-[#3E6B57]">
                <CheckCircle2 size={10} strokeWidth={2} /> Compliant
              </span>
            }
          />
          {/* diode visual */}
          <div className="flex items-center gap-3 border-b border-border bg-[#fbfcfd] px-3 py-2.5">
            <span className="rounded-[3px] border border-border bg-white px-2 py-1 text-[10.5px] text-ink2">
              Production
            </span>
            <span className="h-px flex-1 bg-[#c9d2dd]" />
            <svg width="30" height="18" viewBox="0 0 30 18" aria-hidden>
              <path d="M2 2 L18 9 L2 16 Z" fill="#1F3A5F" />
              <rect x="20" y="1" width="3" height="16" fill="#1F3A5F" />
            </svg>
            <span className="h-px flex-1 bg-[#c9d2dd]" />
            <span className="rounded-[3px] border border-navy bg-navy-soft px-2 py-1 text-[10.5px] font-medium text-navy">
              Enclave
            </span>
            <span className="ml-1 inline-flex items-center gap-1 text-[10.5px] font-semibold text-[#A32020]">
              <svg width="13" height="13" viewBox="0 0 13 13" aria-hidden>
                <line x1="2" y1="2" x2="11" y2="11" stroke="#A32020" strokeWidth="1.8" />
                <line x1="11" y1="2" x2="2" y2="11" stroke="#A32020" strokeWidth="1.8" />
              </svg>
              no return
            </span>
          </div>
          <div className="grid grid-cols-2 gap-x-4 gap-y-[5px] px-3 py-2.5">
            {[
              ["Capture interface", "eth1 (SPAN)"],
              ["Mode", "Receive-only"],
              ["IP address", "none"],
              ["TX packets / bytes", "0 / 0"],
              ["Egress policy", "DROP"],
              ["Active probing", "Disabled"],
              ["Handshakes", "None initiated"],
              ["TLS decryption", "Not performed"],
            ].map(([k, v]) => (
              <div key={k} className="flex items-baseline justify-between gap-2 border-b border-[#eef1f4] pb-[3px]">
                <span className="text-[11px] text-ink2">{k}</span>
                <span className="font-mono text-[11.5px] text-ink">{v}</span>
              </div>
            ))}
          </div>
          <div className="flex items-center justify-between border-t border-border px-3 py-2 text-[11px] text-ink2">
            <span className="truncate">{ONEWAY_INTEGRITY.diodeModel}</span>
            <span className="ml-2 inline-flex shrink-0 items-center gap-1 font-mono">
              <Clock size={10} strokeWidth={1.7} />
              {ONEWAY_INTEGRITY.lastIntegrityCheck}
            </span>
          </div>
        </Panel>

        <Panel className="flex flex-col">
          <PanelHeader
            title="Threat-intel bundle"
            subtitle="Signed local bundle. No live lookups."
            icon={<Database size={13} strokeWidth={1.6} />}
            right={
              <Link to="/intel" className="text-[12px] text-link hover:underline">
                Manage
              </Link>
            }
          />
          <div className="flex items-center justify-between border-b border-border px-3 py-2.5">
            <div>
              <div className="font-mono text-[13px] font-semibold text-ink">{activeBundle.version}</div>
              <div className="mt-[2px] text-[11px] text-ink2">
                {activeBundle.iocs.toLocaleString("en-US")} indicators · {activeBundle.ageDays} days old
              </div>
            </div>
            <div className="flex gap-1.5">
              <span className="inline-flex items-center gap-1 rounded-[3px] border border-[#3E6B57] bg-[#f1f7f3] px-1.5 py-[1px] text-[10.5px] font-medium text-[#3E6B57]">
                <CheckCircle2 size={10} strokeWidth={2} /> Signature
              </span>
              <span className="inline-flex items-center gap-1 rounded-[3px] border border-[#3E6B57] bg-[#f1f7f3] px-1.5 py-[1px] text-[10.5px] font-medium text-[#3E6B57]">
                <CheckCircle2 size={10} strokeWidth={2} /> Schema
              </span>
            </div>
          </div>
          <div className="grid grid-cols-4 divide-x divide-border border-b border-border">
            {[
              ["IPv4", "412k"],
              ["Domain", "689k"],
              ["JA4", "72k"],
              ["Cert hash", "31k"],
            ].map(([k, v]) => (
              <div key={k} className="px-2.5 py-2">
                <div className="text-[10.5px] uppercase tracking-wide text-ink2">{k}</div>
                <div className="mt-[2px] font-mono text-[13px] font-semibold tabular-nums text-ink">{v}</div>
              </div>
            ))}
          </div>
          <div className="mt-auto px-3 py-2.5">
            <div className="rounded border border-[#B7791F] bg-[#fdf9f0] px-2.5 py-2">
              <div className="flex items-center gap-2 text-[12px] font-medium text-ink">
                <ArrowDownToLine size={13} strokeWidth={1.7} />
                DW-TI-2026-09-30-B available
                <span className="ml-auto font-mono text-[11px] text-ink2">
                  +1,842 / ~37 / −12
                </span>
              </div>
              <p className="mt-1 text-[11.5px] leading-snug text-ink2">
                Contains the C2 address 203.0.113.47, one JA4 fingerprint and two of the 61 DGA
                domains observed today.
              </p>
              <div className="mt-2 flex items-center gap-2">
                <Link to="/intel">
                  <Button variant="primary">Import and run retro-hunt</Button>
                </Link>
                <span className="text-[11px] text-ink2">
                  {bundleImported
                    ? retroHuntStatus === "complete"
                      ? "Imported · retro-hunt complete"
                      : "Imported"
                    : "Not yet imported"}
                </span>
              </div>
            </div>
          </div>
        </Panel>
      </div>

      {/* Detector posture */}
      <Panel>
        <PanelHeader
          title="Detection posture"
          subtitle="Detectors enabled on sensor-01"
          icon={<Gauge size={13} strokeWidth={1.6} />}
          right={
            <Link to="/coverage" className="text-[12px] text-link hover:underline">
              Coverage matrix
            </Link>
          }
        />
        <div className="grid grid-cols-3 gap-x-3 gap-y-0 px-1 py-1">
          {[
            ["SIG-RECON-HSCAN-445 v2.4", "Rule", "Reconnaissance", 0.97],
            ["SIG-RECON-SLOWSCAN v1.7", "Rule", "Reconnaissance", 0.91],
            ["dga-lstm-v3.1", "Model", "DGA/DNS Tunnelling", 0.89],
            ["SIG-DNS-TUNNEL-TXT v2.1", "Rule", "DGA/DNS Tunnelling", 0.85],
            ["beacon-periodicity-v2.7", "Model", "C2 Beaconing", 0.88],
            ["tls-eps-v1.9", "Model", "Encrypted Malware", 0.83],
            ["exfil-volume-v2.2", "Model", "Exfiltration", 0.86],
            ["SIG-DDOS-UDP-REFLECT v3.1", "Rule", "DDoS", 0.94],
            ["SIG-DDOS-SYNFLOOD v2.8", "Rule", "DDoS", 0.81],
          ].map((r) => (
            <div
              key={r[0] as string}
              className="flex items-center gap-2 rounded-[3px] px-2 py-[7px] hover:bg-[#f7f8fa]"
            >
              <span
                className="inline-block h-2 w-2 shrink-0 rounded-full"
                style={{ backgroundColor: CATEGORY_COLOR[r[2] as string] }}
              />
              <span className="min-w-0 flex-1">
                <span className="block truncate font-mono text-[11.5px] text-ink">{r[0]}</span>
                <span className="block truncate text-[10.5px] text-ink2">
                  {r[1]} · {r[2]}
                </span>
              </span>
              <MiniBar
                value={(r[3] as number) * 100}
                color={CATEGORY_COLOR[r[2] as string]}
                width={38}
              />
              <span className="w-[26px] shrink-0 text-right font-mono text-[11px] tabular-nums text-ink2">
                {(r[3] as number).toFixed(2)}
              </span>
              <span className="shrink-0 text-[10.5px] text-[#3E6B57]">on</span>
            </div>
          ))}
        </div>
        <div className="border-t border-border bg-[#f7f8fa] px-3 py-2 text-[11px] text-ink2">
          Confidence shown is the typical score for the most recent finding from each detector under
          current visibility.
        </div>
      </Panel>
    </div>
  );
}
