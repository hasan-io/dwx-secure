import React from "react";
import { useMemo, useState } from "react";
import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import {
  ArrowLeftRight,
  ArrowRight,
  Pause,
  Play,
  Radio,
  Rows3,
} from "lucide-react";
import {
  CategoryDot,
  Chip,
  Panel,
  PanelHeader,
  Table,
  Td,
} from "../components/ui";
import { AXIS, ChartTooltip, LegendRow } from "../components/charts";
import { useDemo } from "../store/store";
import { DETECTION_TIMELINE, liveRows } from "../data/live";
import { CATEGORY_COLOR, fmtBytes, fmtNum } from "../lib/utils";
import { DIRECTION_COVERAGE, OVERVIEW_KPI } from "../data/metrics";
import type { Direction, LiveFlowRow } from "../lib/types";
import { ScenarioReplay } from "../components/ScenarioReplay";

const CATEGORIES = [
  "Reconnaissance",
  "C2 Beaconing",
  "DGA/DNS Tunnelling",
  "Encrypted Malware",
  "Exfiltration",
  "DDoS",
];

/** Confidence reduction applied when only one direction is visible. */
const ONE_DIRECTION_CONFIDENCE: Record<string, number> = {
  "Reconnaissance": 0.91,
  "C2 Beaconing": 0.81,
  "DGA/DNS Tunnelling": 0.83,
  "Encrypted Malware": 0.78,
  "Exfiltration": 0.79,
  "DDoS": 0.9,
};

function DirectionIcon({ direction }: { direction: Direction }) {
  if (direction === "client-to-server")
    return <ArrowRight size={12} strokeWidth={1.6} className="text-ink2" aria-label="client-to-server" />;
  if (direction === "server-to-client")
    return <ArrowRight size={12} strokeWidth={1.6} className="rotate-180 text-ink2" aria-label="server-to-client" />;
  return <ArrowLeftRight size={12} strokeWidth={1.6} className="text-ink2" aria-label="bidirectional" />;
}

export default function LiveMonitor() {
  const visibilityMode = useDemo((s) => s.visibilityMode);
  const setVisibility = useDemo((s) => s.setVisibility);
  const [rows, setRows] = useState(() => liveRows(16));
  const [paused, setPaused] = useState(false);
  const [filter, setFilter] = useState("all");
  const nextId = React.useRef(17);

  const emit = React.useCallback((newRows: LiveFlowRow[]) => {
    setRows((r) => [...newRows, ...r].slice(0, 60));
  }, []);

  React.useEffect(() => {
    if (paused) return;
    const tick = () => {
      const batch = liveRows(1, nextId.current);
      nextId.current += 1;
      setRows((r) => [...batch, ...r].slice(0, 48));
    };
    const t = setInterval(tick, 1600);
    return () => clearInterval(t);
  }, [paused]);

  const filtered = useMemo(
    () => (filter === "all" ? rows : rows.filter((r) => r.injected === filter)),
    [rows, filter]
  );

  const coverage = visibilityMode === "one" ? DIRECTION_COVERAGE.map((d) => ({ ...d })) : DIRECTION_COVERAGE;
  if (visibilityMode === "one") {
    coverage[0].share = 58;
    coverage[1].share = 37;
    coverage[2].share = 5;
  }

  return (
    <div className="space-y-3">
      <div className="flex items-end justify-between">
        <div>
          <h1 className="text-[17px] font-semibold leading-tight text-ink">Live monitor</h1>
          <p className="mt-[2px] text-[12px] text-ink2">
            Mirrored flow and event records from sensor-01. Metadata only; payloads are not retained.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Chip>
            <Radio size={11} strokeWidth={1.6} /> Streaming
          </Chip>
          <Chip title="Rows currently held in the browser view">
            <Rows3 size={11} strokeWidth={1.6} /> {rows.length} rows
          </Chip>
        </div>
      </div>

      <div className="grid grid-cols-4 gap-3">
        <Panel className="col-span-3">
          <PanelHeader
            title="Flow and event stream"
            subtitle={`${OVERVIEW_KPI.flowsPerMin.toLocaleString("en-US")} flows/min · ${OVERVIEW_KPI.packetsPerSecond.toLocaleString(
              "en-US"
            )} pkt/s observed`}
            icon={<Radio size={13} strokeWidth={1.6} />}
            right={
              <div className="flex items-center gap-2">
                <span className="text-[11px] text-ink2">Visibility mode</span>
                <div
                  data-demo-id="visibility-toggle"
                  className="inline-flex overflow-hidden rounded border border-border-strong"
                >
                  {(["both", "one"] as const).map((m) => (
                    <button
                      key={m}
                      onClick={() => setVisibility(m)}
                      className={`h-[24px] px-2 text-[11.5px] ${
                        visibilityMode === m
                          ? "bg-navy text-white"
                          : "bg-white text-ink2 hover:text-ink"
                      }`}
                    >
                      {m === "both" ? "Both directions" : "One direction only"}
                    </button>
                  ))}
                </div>
                <button
                  onClick={() => setPaused((p) => !p)}
                  className="inline-flex h-[24px] items-center gap-1 rounded border border-border-strong bg-white px-2 text-[11.5px] text-ink hover:border-navy hover:text-navy"
                >
                  {paused ? <Play size={11} strokeWidth={1.6} /> : <Pause size={11} strokeWidth={1.6} />}
                  {paused ? "Resume" : "Pause"}
                </button>
              </div>
            }
          />

          <div className="flex flex-wrap items-center gap-1.5 border-b border-border px-3 py-2">
            <span className="mr-1 text-[11px] text-ink2">Threat category</span>
            <button
              onClick={() => setFilter("all")}
              className={`rounded-[3px] border px-1.5 py-[1px] text-[11px] ${
                filter === "all"
                  ? "border-navy bg-navy-soft text-navy"
                  : "border-border bg-white text-ink2 hover:text-ink"
              }`}
            >
              All records
            </button>
            {CATEGORIES.map((c) => (
              <button
                key={c}
                onClick={() => setFilter(c)}
                className={`inline-flex items-center gap-1.5 rounded-[3px] border px-1.5 py-[1px] text-[11px] ${
                  filter === c
                    ? "border-navy bg-navy-soft text-navy"
                    : "border-border bg-white text-ink2 hover:text-ink"
                }`}
              >
                <span className="inline-block h-2 w-2 rounded-full" style={{ backgroundColor: CATEGORY_COLOR[c] }} />
                {c}
              </button>
            ))}
            {paused ? (
              <span className="ml-auto text-[11px] text-[#B7791F]">Stream paused</span>
            ) : null}
          </div>

          <div data-demo-id="live-table" className="max-h-[420px] overflow-auto">
            <Table head={["Time (UTC)", "Source", "Destination", "Proto", "Port", "Bytes", "Pkts", "Direction", "Tags"]}>
              {filtered.map((r) => {
                const dimmed = visibilityMode === "one" && r.direction === "server-to-client";
                return (
                  <tr
                    key={r.id}
                    className={`hover:bg-[#f7f8fa] ${dimmed ? "opacity-45" : ""} ${
                      r.injected ? "bg-[#fbfbfc]" : ""
                    }`}
                    style={
                      r.injected
                        ? { borderLeft: `3px solid ${CATEGORY_COLOR[r.injected]}` }
                        : undefined
                    }
                  >
                    <Td mono className="whitespace-nowrap">
                      {r.ts.slice(11)}
                    </Td>
                    <Td mono>
                      <span className="font-mono">{r.src}</span>
                      <span className="text-ink3">:{r.srcPort}</span>
                    </Td>
                    <Td mono>
                      <span className="font-mono">{r.dst}</span>
                      <span className="text-ink3">:{r.dstPort}</span>
                    </Td>
                    <Td>{r.proto}</Td>
                    <Td mono>{r.dstPort}</Td>
                    <Td mono className="tabular-nums">
                      {fmtBytes(r.bytes)}
                    </Td>
                    <Td mono className="tabular-nums">
                      {r.packets}
                    </Td>
                    <Td>
                      <span className="inline-flex items-center gap-1.5">
                        <DirectionIcon direction={r.direction} />
                        <span className="text-[11px] text-ink2">
                          {r.direction === "client-to-server"
                            ? "c2s"
                            : r.direction === "server-to-client"
                            ? "s2c"
                            : "both"}
                        </span>
                      </span>
                    </Td>
                    <Td>
                      <span className="flex flex-wrap items-center gap-1">
                        {r.injected ? <CategoryDot category={r.injected} /> : null}
                        {r.tags.map((t) => (
                          <span
                            key={t}
                            className="rounded-[3px] bg-[#f0f2f5] px-1 py-[1px] text-[10.5px] text-ink2"
                          >
                            {t}
                          </span>
                        ))}
                        {r.injected ? (
                          <span className="text-[10.5px] font-medium" style={{ color: CATEGORY_COLOR[r.injected] }}>
                            finding: {r.injected}
                          </span>
                        ) : null}
                      </span>
                    </Td>
                  </tr>
                );
              })}
            </Table>
          </div>
        </Panel>

        <div className="space-y-3">
          <Panel>
            <PanelHeader
              title="Direction coverage"
              subtitle={visibilityMode === "one" ? "One-direction visibility" : "Both directions visible"}
            />
            <div className="px-3 py-2.5">
              <div className="flex h-[10px] w-full overflow-hidden rounded-[2px]">
                {coverage.map((d) => (
                  <div key={d.direction} style={{ width: `${d.share}%`, backgroundColor: d.color }} />
                ))}
              </div>
              <ul className="mt-2 space-y-1">
                {coverage.map((d) => (
                  <li key={d.direction} className="flex items-center gap-2 text-[11.5px]">
                    <span className="inline-block h-2 w-2 rounded-full" style={{ backgroundColor: d.color }} />
                    <span className="text-ink2">{d.direction}</span>
                    <span className="ml-auto font-mono tabular-nums text-ink">{d.share}%</span>
                  </li>
                ))}
              </ul>
              {visibilityMode === "one" ? (
                <p className="mt-2 rounded border border-[#B7791F] bg-[#fdf8ee] px-2 py-1.5 text-[11px] leading-snug text-ink">
                  One-direction visibility. Reverse-direction flows are dimmed and detectors fall back
                  to direction-tolerant features. Displayed confidence is reduced accordingly.
                </p>
              ) : (
                <p className="mt-2 text-[11px] leading-snug text-ink2">
                  Both legs of each flow are visible from the mirror. 24% of flows still arrive with a
                  single direction.
                </p>
              )}
            </div>
          </Panel>

          <Panel>
            <PanelHeader title="Detector confidence" subtitle="INC-0417 findings under current visibility" />
            <div className="px-3 py-2">
              <Table head={["Category", "Both dir.", "Current"]}>
                {CATEGORIES.map((c) => {
                  const both =
                    c === "Reconnaissance" ? 0.97 : c === "C2 Beaconing" ? 0.88 : c === "DGA/DNS Tunnelling" ? 0.89 : c === "Encrypted Malware" ? 0.83 : c === "Exfiltration" ? 0.86 : 0.94;
                  const cur = visibilityMode === "one" ? ONE_DIRECTION_CONFIDENCE[c] : both;
                  return (
                    <tr key={c}>
                      <Td>
                        <span className="inline-flex items-center gap-1.5">
                          <CategoryDot category={c} />
                          {c}
                        </span>
                      </Td>
                      <Td mono className="tabular-nums">
                        {both.toFixed(2)}
                      </Td>
                      <Td mono className="font-semibold tabular-nums">
                        {cur.toFixed(2)}
                      </Td>
                    </tr>
                  );
                })}
              </Table>
            </div>
          </Panel>
        </div>
      </div>

      <ScenarioReplay onEmit={emit} />

      <Panel>
        <PanelHeader
          title="Detection timeline"
          subtitle="Findings per minute by category, last 60 minutes"
          icon={<Radio size={13} strokeWidth={1.6} />}
        />
        <div className="px-2 pt-3" style={{ height: 190 }}>
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={DETECTION_TIMELINE} margin={{ left: 0, right: 8, top: 4 }}>
              <CartesianGrid stroke="#E6E9EE" vertical={false} />
              <XAxis dataKey="minute" {...AXIS} interval={9} />
              <YAxis {...AXIS} allowDecimals={false} width={26} />
              <Tooltip content={<ChartTooltip />} />
              {CATEGORIES.map((c) => (
                <Area
                  key={c}
                  type="stepAfter"
                  dataKey={c}
                  stackId="1"
                  stroke={CATEGORY_COLOR[c]}
                  fill={CATEGORY_COLOR[c]}
                  fillOpacity={0.16}
                  strokeWidth={1}
                />
              ))}
            </AreaChart>
          </ResponsiveContainer>
        </div>
        <LegendRow items={CATEGORIES.map((c) => ({ label: c, color: CATEGORY_COLOR[c] }))} />
      </Panel>

      <Panel>
        <PanelHeader title="Ingest summary" subtitle="Rolling 5-minute window" />
        <div className="grid grid-cols-4 divide-x divide-border">
          {[
            ["Records ingested", fmtNum(206400)],
            ["Distinct internal hosts", "412"],
            ["Distinct external endpoints", "1,864"],
            ["Detection events raised", fmtNum(37)],
          ].map(([k, v]) => (
            <div key={k} className="px-3 py-2">
              <div className="text-[11px] uppercase tracking-wide text-ink2">{k}</div>
              <div className="mt-[3px] font-mono text-[15px] font-semibold tabular-nums text-ink">{v}</div>
            </div>
          ))}
        </div>
      </Panel>
    </div>
  );
}
