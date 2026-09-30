import React from "react";
import {
  CATEGORY_COLOR,
  SEVERITY_COLOR,
  cn,
  riskSeverity,
} from "../lib/utils";
import type { Category } from "../lib/types";
import {
  FLOW_LINKS,
  FLOW_NODES,
  GRAPH_EDGES,
  GRAPH_NODES,
  HEATMAP_BUCKETS,
  HEATMAP_ROWS,
  HOST_PROFILES,
  RISK_ANNOTATIONS,
  type HostProfile,
  type RiskAnnotation,
  type TimelineEvent,
  type VizEdge,
  type VizNode,
} from "../data/visualization";

/* ----------------------------- shared bits ----------------------------- */

export function VizPanel({
  title,
  subtitle,
  right,
  children,
  className,
  demoId,
}: {
  title: string;
  subtitle?: string;
  right?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
  demoId?: string;
}) {
  return (
    <section
      data-demo-id={demoId}
      className={cn("flex flex-col rounded border border-border bg-panel", className)}
    >
      <header className="flex items-start justify-between gap-3 border-b border-border px-3 py-2">
        <div>
          <h2 className="text-[12.5px] font-semibold leading-tight text-ink">{title}</h2>
          {subtitle ? <p className="mt-[2px] text-[11px] text-ink2">{subtitle}</p> : null}
        </div>
        {right ? <div className="flex shrink-0 flex-wrap items-center gap-1.5">{right}</div> : null}
      </header>
      <div className="flex-1">{children}</div>
    </section>
  );
}

export function DetailList({ rows }: { rows: { k: string; v: React.ReactNode }[] }) {
  return (
    <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-[3px]">
      {rows.map((r) => (
        <React.Fragment key={r.k}>
          <dt className="text-[10.5px] text-ink2">{r.k}</dt>
          <dd className="text-[11px] text-ink">{r.v}</dd>
        </React.Fragment>
      ))}
    </dl>
  );
}

export function Legend({ items }: { items: { label: string; color: string }[] }) {
  return (
    <div className="flex flex-wrap items-center gap-x-3 gap-y-1 px-3 pb-2">
      {items.map((i) => (
        <span key={i.label} className="inline-flex items-center gap-1.5 text-[10.5px] text-ink2">
          <span className="inline-block h-2 w-2 rounded-full" style={{ backgroundColor: i.color }} />
          {i.label}
        </span>
      ))}
    </div>
  );
}

function hexToRgba(hex: string, a: number) {
  const h = hex.replace("#", "");
  const n = parseInt(h, 16);
  return `rgba(${(n >> 16) & 255}, ${(n >> 8) & 255}, ${n & 255}, ${a})`;
}

const cat = (c?: string | null) => (c ? (CATEGORY_COLOR[c] ?? "#B9C2CC") : "#B9C2CC");

/* ========================= 1. Network activity graph ========================= */

export function NetworkGraph({
  selectedNode,
  onNodeSelect,
  selectedEdge,
  onEdgeSelect,
  highlightCategory,
  bundleImported,
}: {
  selectedNode: string | null;
  onNodeSelect: (id: string | null) => void;
  selectedEdge: string | null;
  onEdgeSelect: (id: string | null) => void;
  highlightCategory: Category | null;
  bundleImported: boolean;
}) {
  const nodes = React.useMemo(() => {
    const m = new Map<string, VizNode>();
    GRAPH_NODES.forEach((n) => m.set(n.id, n));
    return m;
  }, []);

  const visibleEdges = React.useMemo(
    () => GRAPH_EDGES.filter((e) => !e.retroHuntOnly || bundleImported),
    [bundleImported]
  );

  const linked = new Set<string>();
  if (selectedNode) {
    linked.add(selectedNode);
    visibleEdges.forEach((e) => {
      if (e.from === selectedNode) linked.add(e.to);
      if (e.to === selectedNode) linked.add(e.from);
    });
  }

  const dim = (id: string) => (selectedNode && !linked.has(id) ? 0.16 : 1);
  const edgeDim = (e: VizEdge) => {
    if (selectedEdge && selectedEdge !== e.id) return 0.12;
    if (selectedNode && e.from !== selectedNode && e.to !== selectedNode) return 0.12;
    if (highlightCategory && e.category !== highlightCategory) return 0.12;
    return e.category ? 1 : 0.42;
  };

  return (
    <div className="px-2 pb-2 pt-1">
      <svg viewBox="0 0 1040 660" width="100%" height="440" role="img" aria-label="Observed communication graph">
        {/* column captions */}
        {[
          [70, "Internal hosts"],
          [500, "Service"],
          [870, "External / context"],
        ].map(([x, label]) => (
          <text key={label as string} x={x as number} y={18} textAnchor="middle" fontSize="10" fill="#8A949F">
            {label as string}
          </text>
        ))}

        {visibleEdges.map((e) => {
          const a = nodes.get(e.from);
          const b = nodes.get(e.to);
          if (!a || !b) return null;
          const aw = a.type === "external" ? 92 : 84;
          const bw = b.type === "external" ? 92 : 84;
          const x1 = a.x + (b.x > a.x ? aw : -aw);
          const x2 = b.x - (b.x > a.x ? bw : -bw);
          const y1 = a.y;
          const y2 = b.y;
          const midX = (x1 + x2) / 2;
          const d = `M${x1} ${y1} C${midX} ${y1}, ${midX} ${y2}, ${x2} ${y2}`;
          const w = Math.max(e.category ? 1.8 : 1, Math.min(9, Math.sqrt(e.mb) * 1.35));
          const isSel = selectedEdge === e.id;
          return (
            <path
              key={e.id}
              d={d}
              fill="none"
              stroke={cat(e.category)}
              strokeWidth={isSel ? w + 1.6 : w}
              strokeOpacity={edgeDim(e)}
              strokeDasharray={e.direction === "client-to-server" ? "7 3" : e.direction === "server-to-client" ? "2 3" : undefined}
              strokeLinecap="round"
              onClick={() => onEdgeSelect(isSel ? null : e.id)}
              style={{ cursor: "pointer" }}
            />
          );
        })}

        {GRAPH_NODES.map((n) => {
          const w = n.type === "external" ? 184 : n.type === "service" ? 168 : 168;
          const h = 38;
          const isSel = selectedNode === n.id;
          const border = isSel
            ? "#1F3A5F"
            : n.category
            ? CATEGORY_COLOR[n.category]
            : "#C3CAD3";
          return (
            <g
              key={n.id}
              opacity={dim(n.id)}
              onClick={() => onNodeSelect(isSel ? null : n.id)}
              style={{ cursor: "pointer" }}
            >
              <rect
                x={n.x - w / 2}
                y={n.y - h / 2}
                width={w}
                height={h}
                rx="3"
                fill={isSel ? "#E8EDF4" : "#FFFFFF"}
                stroke={border}
                strokeWidth={isSel ? 1.6 : 1}
              />
              <text x={n.x - w / 2 + 10} y={n.y - 3} fontSize="11" fontWeight="600" fill="#1F2933">
                {n.label}
              </text>
              <text x={n.x - w / 2 + 10} y={n.y + 12} fontSize="9.5" fill="#5B6773">
                {n.sub}
              </text>
              {n.category ? (
                <circle cx={n.x + w / 2 - 10} cy={n.y} r="3.5" fill={CATEGORY_COLOR[n.category]} />
              ) : null}
            </g>
          );
        })}
      </svg>

      <div className="border-t border-border px-3 py-2">
        {selectedEdge ? (
          (() => {
            const e = GRAPH_EDGES.find((x) => x.id === selectedEdge)!;
            return (
              <div className="grid grid-cols-2 gap-x-6">
                <DetailList
                  rows={[
                    { k: "Relationship", v: <span className="font-mono">{e.from} → {e.to}</span> },
                    { k: "Service", v: <span className="font-mono">{e.proto}/{e.port}</span> },
                    { k: "Volume", v: <span className="font-mono tabular-nums">{e.mb >= 1000 ? `${(e.mb / 1000).toFixed(1)} GB` : `${e.mb} MB`}</span> },
                    { k: "Flows", v: <span className="font-mono tabular-nums">{e.flows.toLocaleString("en-US")}</span> },
                  ]}
                />
                <div>
                  <DetailList
                    rows={[
                      { k: "Direction", v: e.direction },
                      { k: "Category", v: e.category ?? <span className="text-ink2">benign / baseline</span> },
                      { k: "Confidence", v: <span className="font-mono tabular-nums">{e.confidence.toFixed(2)}</span> },
                    ]}
                  />
                  <p className="mt-1 text-[11px] leading-snug text-ink2">{e.note}</p>
                </div>
              </div>
            );
          })()
        ) : selectedNode ? (
          (() => {
            const n = GRAPH_NODES.find((x) => x.id === selectedNode)!;
            const out = GRAPH_EDGES.filter((x) => x.from === selectedNode);
            const inn = GRAPH_EDGES.filter((x) => x.to === selectedNode);
            return (
              <div className="grid grid-cols-2 gap-x-6">
                <DetailList
                  rows={[
                    { k: "Entity", v: <span className="font-mono">{n.label}</span> },
                    { k: "Class", v: n.type },
                    { k: "Relations", v: <span className="font-mono tabular-nums">{out.length} out · {inn.length} in</span> },
                    { k: "Category", v: n.category ?? <span className="text-ink2">no category</span> },
                  ]}
                />
                <div>
                  <p className="text-[11px] leading-snug text-ink2">{n.note}</p>
                  <p className="mt-1 text-[10.5px] text-ink3">
                    Click the relationship lines for flow-level detail. Edge width encodes volume;
                    dashes indicate single-direction visibility.
                  </p>
                </div>
              </div>
            );
          })()
        ) : (
          <p className="text-[11px] leading-snug text-ink2">
            Each node is an observed entity; each line is a communication relationship sized by
            traffic volume. Coloured lines carry a threat category, grey lines are baseline traffic.
            Select a node or a line to inspect it.
          </p>
        )}
      </div>
    </div>
  );
}

/* =========================== 2. Security event timeline =========================== */

export function EventTimeline({
  events,
  from,
  to,
  selectedEvent,
  onEventSelect,
  highlightCategory,
  selectedIncident,
  onIncidentSelect,
}: {
  events: TimelineEvent[];
  from: number;
  to: number;
  selectedEvent: string | null;
  onEventSelect: (id: string | null) => void;
  highlightCategory: Category | null;
  selectedIncident: string | null;
  onIncidentSelect: (id: string) => void;
}) {
  const lanes = [
    "Reconnaissance",
    "DGA/DNS Tunnelling",
    "C2 Beaconing",
    "Encrypted Malware",
    "Exfiltration",
    "DDoS",
  ] as Category[];
  const X0 = 138;
  const X1 = 1010;
  const laneH = 44;
  const px = (m: number) => X0 + ((m - from) / Math.max(1, to - from)) * (X1 - X0);
  const ticks = Array.from({ length: 7 }, (_, i) => from + ((to - from) / 6) * i);

  return (
    <div className="px-2 pb-2 pt-1">
      <svg viewBox="0 0 1030 330" width="100%" height="322" role="img" aria-label="Security event timeline">
        {lanes.map((lane, i) => {
          const y = 26 + i * laneH;
          const dimmed = highlightCategory && highlightCategory !== lane;
          return (
            <g key={lane} opacity={dimmed ? 0.28 : 1}>
              <rect x={X0} y={y - 15} width={X1 - X0} height={30} fill={i % 2 ? "#FAFBFC" : "#FFFFFF"} />
              <text x={X0 - 10} y={y + 4} textAnchor="end" fontSize="10.5" fill="#5B6773">
                {lane.replace("DGA/DNS Tunnelling", "DGA / Tunnelling").replace("Encrypted Malware", "Encrypted")}
              </text>
              <circle cx={X0 - 6} cy={y} r="0" fill="none" />
              <line x1={X0} y1={y + 15} x2={X1} y2={y + 15} stroke="#EDEFF3" />
            </g>
          );
        })}

        {ticks.map((t, i) => (
          <g key={i}>
            <line x1={px(t)} y1={12} x2={px(t)} y2={290} stroke="#E6E9EE" />
            <text x={px(t)} y={306} textAnchor="middle" fontSize="10" fill="#5B6773">
              {`${String(Math.floor(t / 60)).padStart(2, "0")}:${String(Math.round(t % 60)).padStart(2, "0")}`}
            </text>
          </g>
        ))}

        {events.map((e) => {
          const laneIndex = lanes.indexOf(e.category);
          if (laneIndex < 0) return null;
          const y = 26 + laneIndex * laneH;
          const x = px(e.minute);
          const sel = selectedEvent === e.id;
          const dimmed =
            (highlightCategory && highlightCategory !== e.category) ||
            (selectedIncident && selectedIncident !== e.incident);
          return (
            <g
              key={e.id}
              opacity={dimmed ? 0.18 : 1}
              onClick={() => {
                onEventSelect(sel ? null : e.id);
                onIncidentSelect(e.incident);
              }}
              style={{ cursor: "pointer" }}
            >
              <rect
                x={x - 7}
                y={y - 13}
                width={14}
                height={26}
                rx="2"
                fill={e.historical ? "#FFFFFF" : CATEGORY_COLOR[e.category]}
                stroke={sel ? "#1F3A5F" : e.historical ? CATEGORY_COLOR[e.category] : "none"}
                strokeWidth={sel ? 2 : e.historical ? 1.4 : 0}
                strokeDasharray={e.historical ? "3 2" : undefined}
              />
              <text x={x} y={y + 30} textAnchor="middle" fontSize="8.5" fill="#5B6773">
                {`${String(Math.floor(e.minute / 60)).padStart(2, "0")}:${String(e.minute % 60).padStart(2, "0")}`}
              </text>
            </g>
          );
        })}

        <text x={X0} y={322} fontSize="9.5" fill="#8A949F">
          Dashed outline marks the retro-hunt historical match. Times shown in UTC.
        </text>
      </svg>

      <div className="border-t border-border px-3 py-2">
        {selectedEvent ? (
          (() => {
            const e = events.find((x) => x.id === selectedEvent);
            if (!e)
              return (
                <p className="text-[11px] text-ink2">
                  The selected event is outside the current time range.
                </p>
              );
            return (
              <div className="grid grid-cols-2 gap-x-6">
                <DetailList
                  rows={[
                    {
                      k: "Time",
                      v: (
                        <span className="font-mono">
                          {`${String(Math.floor(e.minute / 60)).padStart(2, "0")}:${String(e.minute % 60).padStart(2, "0")}`} UTC
                        </span>
                      ),
                    },
                    { k: "Category", v: e.category },
                    { k: "Incident", v: <span className="font-mono">{e.incident}</span> },
                    { k: "Entity", v: <span className="font-mono">{e.entity}</span> },
                  ]}
                />
                <div>
                  <DetailList
                    rows={[
                      { k: "Finding", v: e.title },
                      { k: "Confidence", v: <span className="font-mono tabular-nums">{e.confidence.toFixed(2)}</span> },
                      { k: "Risk after", v: e.risk ? <span className="font-mono tabular-nums">{e.risk}</span> : "—" },
                    ]}
                  />
                  <p className="mt-1 text-[11px] leading-snug text-ink2">{e.detail}</p>
                </div>
              </div>
            );
          })()
        ) : (
          <p className="text-[11px] leading-snug text-ink2">
            Six event lanes over time. Markers are placed at the detection timestamp and coloured by
            threat category; the vertical position is the category lane, not a severity scale. Select
            a marker to read the finding, or select an incident chip to isolate one campaign.
          </p>
        )}
      </div>
    </div>
  );
}

/* ============================= 3. Traffic flow diagram ============================= */

interface FlowLayoutNode {
  id: string;
  label: string;
  sub?: string;
  column: number;
  x: number;
  y: number;
  h: number;
  value: number;
}

export function FlowDiagram({
  highlightCategory,
  onNodeSelect,
}: {
  highlightCategory: Category | null;
  onNodeSelect: (label: string) => void;
}) {
  const layout = React.useMemo(() => {
    const values = new Map<string, number>();
    FLOW_LINKS.forEach((l) => {
      values.set(l.source, (values.get(l.source) ?? 0) + l.mb);
      values.set(l.target, (values.get(l.target) ?? 0) + l.mb);
    });
    const colX = [46, 330, 676, 900];
    const nodes: FlowLayoutNode[] = FLOW_NODES.map((n) => {
      const v = values.get(n.id) ?? 0;
      return { ...n, x: colX[n.column], y: 0, h: 0, value: v };
    });
    const thickness = (v: number) => Math.max(1.5, Math.min(34, Math.sqrt(v) * 3.1));
    [0, 1, 2, 3].forEach((col) => {
      const inCol = nodes.filter((n) => n.column === col).sort((a, b) => b.value - a.value);
      const heights = inCol.map((n) => Math.max(14, Math.min(64, thickness(n.value) * 1.15)));
      const gap = 14;
      const total = heights.reduce((a, b) => a + b, 0) + gap * (inCol.length - 1);
      let y = 22 + Math.max(0, (400 - total) / 2);
      inCol.forEach((n, i) => {
        n.h = heights[i];
        n.y = y + heights[i] / 2;
        y += heights[i] + gap;
      });
    });
    return { nodes, thickness };
  }, []);

  const byId = new Map(layout.nodes.map((n) => [n.id, n]));

  return (
    <div className="px-2 pb-2 pt-1">
      <svg viewBox="0 0 1040 440" width="100%" height="330" role="img" aria-label="Traffic flow diagram">
        {["Internal host", "Protocol / service", "Destination", "Threat context"].map((c, i) => (
          <text key={c} x={[46, 330, 676, 900][i]} y={14} fontSize="10" fill="#8A949F">
            {c}
          </text>
        ))}

        {FLOW_LINKS.map((l, i) => {
          const a = byId.get(l.source);
          const b = byId.get(l.target);
          if (!a || !b) return null;
          const x1 = a.x + 11;
          const x2 = b.x;
          const t = layout.thickness(l.mb);
          const dimmed = highlightCategory && l.category !== highlightCategory;
          const midX = (x1 + x2) / 2;
          return (
            <path
              key={i}
              d={`M${x1} ${a.y} C${midX} ${a.y}, ${midX} ${b.y}, ${x2} ${b.y}`}
              fill="none"
              stroke={cat(l.category)}
              strokeOpacity={dimmed ? 0.1 : l.category ? 0.62 : 0.3}
              strokeWidth={t}
              strokeLinecap="round"
            />
          );
        })}

        {layout.nodes.map((n) => {
          const dimmed = highlightCategory && n.column === 3 && n.label !== highlightCategory;
          return (
            <g
              key={n.id}
              opacity={dimmed ? 0.22 : 1}
              onClick={() => onNodeSelect(n.label)}
              style={{ cursor: "pointer" }}
            >
              <rect
                x={n.x}
                y={n.y - n.h / 2}
                width="11"
                height={n.h}
                rx="2"
                fill={n.column === 3 ? cat((n.label.replace("DGA / Tunnelling", "DGA/DNS Tunnelling").replace("Encrypted anomaly", "Encrypted Malware")) as Category) : "#1F3A5F"}
              />
              <text
                x={n.column === 3 ? n.x + 17 : n.x + 17}
                y={n.y - 1}
                fontSize="10"
                fontWeight="600"
                fill="#1F2933"
              >
                {n.label}
              </text>
              {n.sub ? (
                <text x={n.x + 17} y={n.y + 11} fontSize="9" fill="#5B6773">
                  {n.sub}
                </text>
              ) : null}
            </g>
          );
        })}
      </svg>
      <div className="border-t border-border px-3 py-1.5 text-[10.5px] leading-snug text-ink2">
        Line width encodes traffic volume on a square-root scale, so the 4.8 GB exfiltration and the
        1.2 KB historical contact remain visible in the same view. Column four maps each flow to the
        threat category it was scored under.
      </div>
    </div>
  );
}

/* =========================== 4. Threat activity heatmap =========================== */

export function ThreatHeatmap({
  highlightCategory,
  onCategorySelect,
  selectedBucket,
  onBucketSelect,
}: {
  highlightCategory: Category | null;
  onCategorySelect: (c: Category | null) => void;
  selectedBucket: number | null;
  onBucketSelect: (b: number | null) => void;
}) {
  const max = 5;
  return (
    <div className="px-3 pb-2 pt-2">
      <div className="overflow-x-auto">
        <div style={{ minWidth: 520 }}>
          <div className="grid" style={{ gridTemplateColumns: "112px repeat(24, 1fr)" }}>
            <div />
            {HEATMAP_BUCKETS.map((b) => (
              <div key={b.index} className="pb-[3px] text-center text-[8px] text-ink3">
                {b.index % 3 === 0 ? b.label : ""}
              </div>
            ))}
            {HEATMAP_ROWS.map((row) => (
              <React.Fragment key={row.category}>
                <button
                  onClick={() => onCategorySelect(highlightCategory === row.category ? null : row.category)}
                  className={`flex items-center gap-1.5 pr-2 text-left text-[10.5px] ${
                    highlightCategory === row.category ? "font-semibold text-navy" : "text-ink2"
                  }`}
                >
                  <span
                    className="inline-block h-2 w-2 shrink-0 rounded-full"
                    style={{ backgroundColor: CATEGORY_COLOR[row.category] }}
                  />
                  <span className="truncate">
                    {row.category.replace("DGA/DNS Tunnelling", "DGA / Tunnelling").replace("Encrypted Malware", "Encrypted")}
                  </span>
                </button>
                {row.values.map((v, i) => {
                  const active = selectedBucket === i;
                  return (
                    <button
                      key={i}
                      title={`${row.category} · ${HEATMAP_BUCKETS[i].label}–${String(
                        Math.floor(HEATMAP_BUCKETS[i].to / 60)
                      ).padStart(2, "0")}:${String(HEATMAP_BUCKETS[i].to % 60).padStart(2, "0")} UTC · ${v} events`}
                      onClick={() => onBucketSelect(active ? null : i)}
                      className="m-[1px] h-[19px] rounded-[2px] border transition-colors"
                      style={{
                        backgroundColor:
                          v === 0 ? "#F2F4F7" : hexToRgba(CATEGORY_COLOR[row.category], 0.16 + (v / max) * 0.84),
                        borderColor: active ? "#1F3A5F" : "transparent",
                      }}
                    />
                  );
                })}
              </React.Fragment>
            ))}
          </div>
        </div>
      </div>

      <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 border-t border-border pt-2">
        <span className="text-[10.5px] text-ink2">Events per 30 min</span>
        <span className="flex items-center gap-1">
          {[0, 1, 2, 3, 4, 5].map((v) => (
            <span
              key={v}
              className="inline-block h-[11px] w-[16px] rounded-[2px]"
              style={{ backgroundColor: v === 0 ? "#F2F4F7" : hexToRgba("#5B6773", 0.16 + (v / max) * 0.84) }}
            />
          ))}
        </span>
        <span className="text-[10.5px] text-ink2">0 → 5</span>
        <span className="ml-auto text-[10.5px] text-ink2">
          {selectedBucket !== null
            ? `Bucket ${HEATMAP_BUCKETS[selectedBucket].label} selected`
            : "Select a cell to filter the workspace by category and time"}
        </span>
      </div>
    </div>
  );
}

/* ========================== 5. Incident risk evolution ========================== */

export function RiskEvolution({
  selected,
  onSelect,
  showRetro,
}: {
  selected: number | null;
  onSelect: (minute: number | null) => void;
  showRetro: boolean;
}) {
  const points = RISK_ANNOTATIONS.filter((p) => showRetro || !p.historical);
  const X0 = 52;
  const X1 = 990;
  const Y0 = 24;
  const Y1 = 232;
  const from = 505;
  const to = 735;
  const px = (m: number) => X0 + ((m - from) / (to - from)) * (X1 - X0);
  const py = (r: number) => Y1 - (r / 100) * (Y1 - Y0);

  const segments: { x1: number; y1: number; x2: number; y2: number; historical: boolean }[] = [];
  for (let i = 0; i < points.length - 1; i++) {
    const a = points[i];
    const b = points[i + 1];
    segments.push({
      x1: px(a.minute),
      y1: py(a.risk ?? 0),
      x2: px(b.minute),
      y2: py(a.risk ?? 0),
      historical: Boolean(b.historical),
    });
    segments.push({
      x1: px(b.minute),
      y1: py(a.risk ?? 0),
      x2: px(b.minute),
      y2: py(b.risk ?? 0),
      historical: Boolean(b.historical),
    });
  }

  return (
    <div className="px-2 pb-2 pt-1">
      <svg viewBox="0 0 1010 300" width="100%" height="286" role="img" aria-label="Incident risk evolution">
        {[0, 25, 50, 75, 100].map((r) => (
          <g key={r}>
            <line x1={X0} y1={py(r)} x2={X1} y2={py(r)} stroke={r === 75 || r === 50 || r === 25 ? "#E6E9EE" : "#D8DDE4"} />
            <text x={X0 - 8} y={py(r) + 3} textAnchor="end" fontSize="10" fill="#5B6773">
              {r}
            </text>
          </g>
        ))}
        <line x1={X0} y1={py(90)} x2={X1} y2={py(90)} stroke="#A32020" strokeDasharray="4 3" strokeWidth="1" />
        <text x={X1} y={py(90) - 4} textAnchor="end" fontSize="9" fill="#A32020">
          Critical threshold 90
        </text>

        {segments.map((s, i) => (
          <line
            key={i}
            x1={s.x1}
            y1={s.y1}
            x2={s.x2}
            y2={s.y2}
            stroke={s.historical ? "#7A5C7E" : "#1F3A5F"}
            strokeWidth="1.8"
            strokeDasharray={s.historical ? "5 3" : undefined}
          />
        ))}

        {points.map((p) => {
          const x = px(p.minute);
          const y = py(p.risk ?? 0);
          const active = selected === p.minute;
          const band = riskSeverity(p.risk ?? 0);
          return (
            <g key={p.minute} onClick={() => onSelect(active ? null : p.minute)} style={{ cursor: "pointer" }}>
              {p.historical ? (
                <line x1={x} y1={Y0} x2={x} y2={Y1} stroke="#7A5C7E" strokeDasharray="3 3" strokeWidth="1" />
              ) : null}
              {p.historical ? (
                <rect x={x - 5} y={y - 5} width={10} height={10} fill="#FFFFFF" stroke="#7A5C7E" strokeWidth="1.8" transform={`rotate(45 ${x} ${y})`} />
              ) : (
                <circle cx={x} cy={y} r={active ? 6 : 4.2} fill={SEVERITY_COLOR[band]} stroke="#FFFFFF" strokeWidth="1.4" />
              )}
              <text x={x} y={y - 11} textAnchor="middle" fontSize="10" fontWeight="600" fill="#1F2933">
                {p.risk}
              </text>
              <text x={x} y={Y1 + 15} textAnchor="middle" fontSize="9" fill="#5B6773">
                {`${String(Math.floor(p.minute / 60)).padStart(2, "0")}:${String(p.minute % 60).padStart(2, "0")}`}
              </text>
              <text x={x} y={Y1 + 27} textAnchor="middle" fontSize="8.5" fill="#8A949F">
                {p.historical ? "retro-hunt" : p.finding.split(" ").slice(0, 2).join(" ")}
              </text>
            </g>
          );
        })}

        <text x={X0} y={292} fontSize="9.5" fill="#8A949F">
          Risk accumulates as evidence arrives. The diamond marks the retro-hunt threat-intel match,
          which is added after the behavioural detections.
        </text>
      </svg>

      <div className="border-t border-border px-3 py-2">
        {selected !== null && RISK_ANNOTATIONS.some((x) => x.minute === selected) ? (
          (() => {
            const p = RISK_ANNOTATIONS.find((x) => x.minute === selected)!;
            return (
              <div className="grid grid-cols-2 gap-x-6">
                <DetailList
                  rows={[
                    { k: "Point", v: p.label },
                    { k: "Finding", v: p.finding },
                    { k: "Confidence", v: <span className="font-mono tabular-nums">{p.confidence.toFixed(2)}</span> },
                  ]}
                />
                <div>
                  <DetailList
                    rows={[
                      { k: "Risk change", v: <span className="font-mono tabular-nums">+{p.delta}</span> },
                      { k: "Contributing factor", v: p.contribution },
                      { k: "Source", v: p.historical ? "Retro-hunt RH-2026-09-30-B" : "Behavioural detector" },
                    ]}
                  />
                  <p className="mt-1 text-[11px] leading-snug text-ink2">
                    {p.historical
                      ? "The retro-hunt scans stored metadata against the newly imported bundle and can raise risk on an incident that was already closed for the day."
                      : "Each step is cumulative: the score never falls while new evidence of the same campaign keeps arriving."}
                  </p>
                </div>
              </div>
            );
          })()
        ) : (
          <p className="text-[11px] leading-snug text-ink2">
            INC-0417 risk progression. Select any point to see the finding, its confidence and the
            contribution that moved the score.
          </p>
        )}
      </div>
    </div>
  );
}

/* =========================== 6. Host behaviour profile =========================== */

export function HostBehaviour({
  host,
  onHostSelect,
  onIncidentSelect,
  bundleImported,
}: {
  host: string;
  onHostSelect: (ip: string) => void;
  onIncidentSelect: (id: string) => void;
  bundleImported: boolean;
}) {
  const profile = HOST_PROFILES.find((p) => p.ip === host) ?? HOST_PROFILES[0];
  const risk = profile.risk !== null && profile.incident === "INC-0417" && bundleImported ? 95 : profile.risk;
  const band = riskSeverity(risk ?? 0);

  return (
    <div className="flex h-full flex-col">
      <div className="flex flex-wrap items-center gap-1.5 border-b border-border px-3 py-2">
        {HOST_PROFILES.map((p) => (
          <button
            key={p.ip}
            onClick={() => onHostSelect(p.ip)}
            className={`rounded-[3px] border px-1.5 py-[2px] text-[10.5px] ${
              p.ip === host
                ? "border-navy bg-navy-soft font-semibold text-navy"
                : "border-border bg-white text-ink2 hover:text-ink"
            }`}
          >
            <span className="font-mono">{p.ip}</span>
          </button>
        ))}
      </div>

      <div className="border-b border-border px-3 py-2">
        <div className="flex flex-wrap items-center gap-2">
          <span className="font-mono text-[13px] font-semibold text-ink">{profile.ip}</span>
          <span className="text-[12px] text-ink2">{profile.hostname}</span>
          {profile.incident ? (
            <button
              onClick={() => onIncidentSelect(profile.incident!)}
              className="rounded-[3px] border border-border bg-white px-1.5 py-[1px] font-mono text-[10.5px] text-link hover:border-navy"
            >
              {profile.incident}
            </button>
          ) : null}
          <span className="ml-auto inline-flex items-center gap-2">
            <span className="text-[10.5px] text-ink2">Risk</span>
            <span
              className="font-mono text-[18px] font-semibold leading-none tabular-nums"
              style={{ color: SEVERITY_COLOR[band] }}
            >
              {risk ?? "—"}
            </span>
          </span>
        </div>
        <p className="mt-1 text-[11px] leading-snug text-ink2">{profile.summary}</p>
      </div>

      <div className="px-3 py-2">
        <div className="mb-1.5 flex items-center justify-between">
          <span className="text-[10.5px] font-semibold uppercase tracking-wide text-ink2">
            Baseline vs current behaviour
          </span>
          <span className="flex items-center gap-2 text-[10px] text-ink2">
            <span className="inline-flex items-center gap-1">
              <span className="inline-block h-2 w-2 rounded-[1px] bg-[#C3CAD3]" /> baseline
            </span>
            <span className="inline-flex items-center gap-1">
              <span className="inline-block h-2 w-2 rounded-[1px] bg-[#2F5D9E]" /> current
            </span>
          </span>
        </div>
        <ul className="space-y-[7px]">
          {profile.metrics.map((m) => {
            const delta = m.current - m.baseline;
            return (
              <li key={m.label}>
                <div className="flex items-baseline justify-between">
                  <span className="text-[10.5px] text-ink2">{m.label}</span>
                  <span className="flex items-baseline gap-1.5">
                    <span className="font-mono text-[10px] tabular-nums text-ink3">{m.baselineText}</span>
                    <span className="text-ink3">→</span>
                    <span className="font-mono text-[10.5px] font-semibold tabular-nums text-ink">
                      {m.currentText}
                    </span>
                    <span
                      className="ml-1 font-mono text-[9.5px] tabular-nums"
                      style={{ color: delta > 40 ? "#A32020" : delta > 15 ? "#B7791F" : "#5B6773" }}
                    >
                      {delta > 0 ? `+${delta}` : delta}
                    </span>
                  </span>
                </div>
                <div className="mt-[3px] flex h-[7px] items-center gap-[3px]">
                  <span className="h-[3px] rounded-[1px] bg-[#C3CAD3]" style={{ width: `${Math.max(1, m.baseline)}%` }} />
                  <span
                    className="h-[7px] rounded-[1px]"
                    style={{
                      width: `${Math.max(1, m.current)}%`,
                      backgroundColor: delta > 40 ? "#A32020" : delta > 15 ? "#B7791F" : "#2F5D9E",
                    }}
                  />
                </div>
              </li>
            );
          })}
        </ul>
      </div>

      <div className="mt-auto border-t border-border px-3 py-2">
        <div className="flex items-center justify-between">
          <span className="text-[10.5px] font-semibold uppercase tracking-wide text-ink2">
            Anomaly level
          </span>
          <span className="font-mono text-[11px] tabular-nums text-ink">
            {profile.anomaly} / 100
          </span>
        </div>
        <div className="mt-1 flex gap-[2px]">
          {Array.from({ length: 20 }, (_, i) => {
            const on = (i + 1) * 5 <= profile.anomaly;
            return (
              <span
                key={i}
                className="h-[8px] flex-1 rounded-[1px]"
                style={{
                  backgroundColor: on
                    ? profile.anomaly > 80
                      ? "#A32020"
                      : profile.anomaly > 55
                      ? "#C2410C"
                      : profile.anomaly > 35
                      ? "#B7791F"
                      : "#3E6B57"
                    : "#EDEFF3",
                }}
              />
            );
          })}
        </div>
        <p className="mt-1.5 text-[10.5px] leading-snug text-ink2">{profile.note}</p>
      </div>
    </div>
  );
}

export type { HostProfile, RiskAnnotation, VizEdge, VizNode };
