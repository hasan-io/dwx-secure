import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { geoGraticule10, geoNaturalEarth1, geoPath } from "d3-geo";
import { feature } from "topojson-client";
import type { GeometryCollection, Topology } from "topojson-specification";
import land110 from "world-atlas/land-110m.json";
import { Minus, Plus, RotateCcw } from "lucide-react";
import { CATEGORY_COLOR, SEVERITY_COLOR, riskSeverity } from "../lib/utils";
import type { Category, Incident } from "../lib/types";
import {
  GEO_ENTITIES,
  GEO_LINKS,
  GEO_REGIONS,
  MAP_INSIGHTS,
  NOT_PLOTTED,
  type GeoEntity,
  type GeoLink,
} from "../data/geo";
import { HOST_PROFILES } from "../data/visualization";
import { DetailList } from "./viz";

/* ------------------------------- basemap ------------------------------- */

const W = 960;
const H = 470;
const projection = geoNaturalEarth1().fitSize([W, H], { type: "Sphere" });
const pathGen = geoPath(projection);
const topo = land110 as unknown as Topology<{ land: GeometryCollection }>;
const LAND_D = pathGen(feature(topo, topo.objects.land)) ?? "";
const SPHERE_D = pathGen({ type: "Sphere" }) ?? "";
const GRATICULE_D = pathGen(geoGraticule10()) ?? "";

const REGION_XY = new Map<string, [number, number]>(
  GEO_REGIONS.map((r) => [r.id, (projection([r.lon, r.lat]) ?? [0, 0]) as [number, number]])
);

/** Stable positions: single entity at centroid, clusters on a small ring. */
const ENTITY_XY = (() => {
  const m = new Map<string, [number, number]>();
  GEO_REGIONS.forEach((r) => {
    const list = GEO_ENTITIES.filter((e) => e.regionId === r.id);
    const [cx, cy] = REGION_XY.get(r.id)!;
    if (list.length === 1) {
      m.set(list[0].id, [cx, cy]);
      return;
    }
    list.forEach((e, i) => {
      const a = -Math.PI / 2 + (i * 2 * Math.PI) / list.length;
      m.set(e.id, [cx + Math.cos(a) * 12, cy + Math.sin(a) * 12]);
    });
  });
  return m;
})();

const SITE_XY = REGION_XY.get("site")!;
const BASELINE = "#9AA5B1";

function rgba(hex: string, a: number) {
  const n = parseInt(hex.replace("#", ""), 16);
  return `rgba(${(n >> 16) & 255}, ${(n >> 8) & 255}, ${n & 255}, ${a})`;
}

function markerRadius(flows: number) {
  return 4 + Math.log10(1 + flows) * 2.2;
}

function linkWidth(mb: number) {
  return 0.9 + Math.log10(1 + mb) * 0.75;
}

/* -------------------------------- types -------------------------------- */

type Selection =
  | { type: "entity"; id: string }
  | { type: "site" }
  | { type: "region"; id: string }
  | null;

export interface ActivityMapProps {
  incidents: Incident[];
  bundleImported: boolean;
  category: Category | null;
  severity: string | null;
  incident: string | null;
  host: string | null;
  onIncidentSelect: (id: string) => void;
  onHostSelect: (ip: string) => void;
  onGraphNodeSelect: (id: string | null) => void;
}

/* ------------------------------ component ------------------------------ */

export function ActivityMap({
  incidents,
  bundleImported,
  category,
  severity,
  incident,
  host,
  onIncidentSelect,
  onHostSelect,
  onGraphNodeSelect,
}: ActivityMapProps) {
  const [mode, setMode] = useState<"all" | "suspicious">("all");
  const [view, setView] = useState({ k: 1, x: 0, y: 0 });
  const [selection, setSelection] = useState<Selection>(null);
  const [hover, setHover] = useState<{ id: string; x: number; y: number } | null>(null);
  const [armed, setArmed] = useState(false);
  const svgRef = useRef<SVGSVGElement | null>(null);
  const wrapRef = useRef<HTMLDivElement | null>(null);
  const drag = useRef<{ sx: number; sy: number; x: number; y: number; moved: boolean } | null>(null);
  const movedRef = useRef(false);

  const incidentById = useMemo(() => new Map(incidents.map((i) => [i.id, i])), [incidents]);
  const incidentVisible = useCallback(
    (id: string) => {
      const inc = incidentById.get(id);
      return Boolean(inc) && !(inc!.hiddenUntilRetroHunt && !bundleImported);
    },
    [incidentById, bundleImported]
  );
  const incidentSeverity = useCallback(
    (id: string) => {
      const inc = incidentById.get(id);
      return inc ? riskSeverity(inc.risk) : "Low";
    },
    [incidentById]
  );

  /* ------------------------------ filtering ------------------------------ */

  const visibleLinks = useMemo(
    () =>
      GEO_LINKS.filter((l) => {
        if (l.retroHuntOnly && !bundleImported) return false;
        if (!incidentVisible(l.incident)) return false;
        if (mode === "suspicious" && !l.suspicious) return false;
        if (category && l.category !== category) return false;
        if (incident && l.incident !== incident) return false;
        if (host && l.host !== host) return false;
        if (severity && incidentSeverity(l.incident) !== severity) return false;
        return true;
      }),
    [bundleImported, incidentVisible, mode, category, incident, host, severity, incidentSeverity]
  );

  const activeEntityIds = useMemo(() => new Set(visibleLinks.map((l) => l.entityId)), [visibleLinks]);

  const entitySeverity = useCallback(
    (e: GeoEntity) => {
      const sev = e.incidents
        .filter(incidentVisible)
        .map(incidentSeverity)
        .sort((a, b) => ["Critical", "High", "Medium", "Low"].indexOf(a) - ["Critical", "High", "Medium", "Low"].indexOf(b));
      return sev[0] ?? "Low";
    },
    [incidentVisible, incidentSeverity]
  );

  const entityRisk = useCallback(
    (e: GeoEntity) =>
      Math.max(0, ...e.incidents.filter(incidentVisible).map((id) => incidentById.get(id)?.risk ?? 0)),
    [incidentById, incidentVisible]
  );

  /* ---------------------------- zoom and pan ----------------------------- */

  const svgPoint = (clientX: number, clientY: number) => {
    const svg = svgRef.current;
    if (!svg) return { x: 0, y: 0 };
    const ctm = svg.getScreenCTM();
    if (!ctm) return { x: 0, y: 0 };
    const pt = new DOMPoint(clientX, clientY).matrixTransform(ctm.inverse());
    return { x: pt.x, y: pt.y };
  };

  const zoomAt = useCallback((factor: number, px: number, py: number) => {
    setView((v) => {
      const k = Math.min(8, Math.max(1, v.k * factor));
      if (k === 1) return { k: 1, x: 0, y: 0 };
      const ratio = k / v.k;
      return { k, x: px - (px - v.x) * ratio, y: py - (py - v.y) * ratio };
    });
  }, []);

  useEffect(() => {
    const el = svgRef.current;
    if (!el) return;
    const onWheel = (e: WheelEvent) => {
      if (!(e.ctrlKey || e.metaKey || armed)) return;
      e.preventDefault();
      const { x, y } = svgPoint(e.clientX, e.clientY);
      zoomAt(e.deltaY < 0 ? 1.18 : 1 / 1.18, x, y);
    };
    el.addEventListener("wheel", onWheel, { passive: false });
    return () => el.removeEventListener("wheel", onWheel);
  }, [armed, zoomAt]);

  useEffect(() => {
    const onDocDown = (e: MouseEvent) => {
      if (wrapRef.current && !wrapRef.current.contains(e.target as Node)) setArmed(false);
    };
    document.addEventListener("mousedown", onDocDown);
    return () => document.removeEventListener("mousedown", onDocDown);
  }, []);

  const onPointerDown = (e: React.PointerEvent<SVGSVGElement>) => {
    if (e.button !== 0) return;
    setArmed(true);
    drag.current = { sx: e.clientX, sy: e.clientY, x: view.x, y: view.y, moved: false };
  };
  const onPointerMove = (e: React.PointerEvent<SVGSVGElement>) => {
    if (!drag.current) return;
    const rect = e.currentTarget.getBoundingClientRect();
    const scale = W / rect.width;
    const dx = (e.clientX - drag.current.sx) * scale;
    const dy = (e.clientY - drag.current.sy) * scale;
    if (Math.abs(dx) + Math.abs(dy) > 3) drag.current.moved = true;
    if (drag.current.moved && view.k > 1) {
      const nx = drag.current.x + dx;
      const ny = drag.current.y + dy;
      setView((v) => ({ ...v, x: nx, y: ny }));
    }
  };
  const endDrag = () => {
    if (drag.current?.moved) movedRef.current = true;
    drag.current = null;
  };
  const onBackgroundClick = () => {
    if (movedRef.current) {
      movedRef.current = false;
      return;
    }
    setSelection(null);
    onGraphNodeSelect(null);
  };

  const s = 1 / Math.sqrt(view.k);

  /* ----------------------------- selection ------------------------------ */

  const selectEntity = (e: GeoEntity) => {
    setSelection({ type: "entity", id: e.id });
    onGraphNodeSelect(e.graphNodeId ?? null);
  };

  const hoverEntity = hover ? GEO_ENTITIES.find((e) => e.id === hover.id) : null;

  /* ------------------------ aggregations for panel ----------------------- */

  const regionRows = useMemo(() => {
    const rows = GEO_REGIONS.filter((r) => r.id !== "site").map((r) => {
      const links = visibleLinks.filter(
        (l) => GEO_ENTITIES.find((e) => e.id === l.entityId)?.regionId === r.id
      );
      const out = links.filter((l) => !l.inbound).reduce((a, l) => a + l.mb, 0);
      const inn = links.filter((l) => l.inbound).reduce((a, l) => a + l.mb, 0);
      const flows = links.reduce((a, l) => a + l.flows, 0);
      const cats = Array.from(new Set(links.map((l) => l.category).filter(Boolean))) as Category[];
      return { region: r, out, inn, flows, cats, links: links.length };
    });
    return rows.filter((r) => r.links > 0).sort((a, b) => b.out + b.inn - (a.out + a.inn));
  }, [visibleLinks]);

  const insights = MAP_INSIGHTS.filter((i) =>
    incident ? i.incident === incident || i.incident === null : true
  ).filter((i) => !i.incident || incidentVisible(i.incident));

  const fmtMb = (mb: number) =>
    mb >= 1000 ? `${(mb / 1000).toFixed(1)} GB` : mb >= 1 ? `${mb.toFixed(mb < 10 ? 1 : 0)} MB` : `${Math.round(mb * 1000)} KB`;

  /* -------------------------------- render ------------------------------- */

  const linkIndex = new Map<string, number>();

  return (
    <div className="grid grid-cols-12">
      {/* map */}
      <div ref={wrapRef} className="relative col-span-8 border-r border-border">
        <svg
          ref={svgRef}
          viewBox={`0 0 ${W} ${H}`}
          width="100%"
          height="470"
          role="img"
          aria-label="Network activity map"
          className={view.k > 1 ? "cursor-grab active:cursor-grabbing" : "cursor-default"}
          onPointerDown={onPointerDown}
          onPointerMove={onPointerMove}
          onPointerUp={endDrag}
          onPointerLeave={endDrag}
          onPointerCancel={endDrag}
          onClick={onBackgroundClick}
          style={{ touchAction: "none", userSelect: "none" }}
        >
          <g transform={`translate(${view.x} ${view.y}) scale(${view.k})`}>
            <path d={SPHERE_D} fill="#FFFFFF" stroke="#D8DDE4" strokeWidth={0.8 * s} />
            <path d={GRATICULE_D} fill="none" stroke="#EEF1F4" strokeWidth={0.6 * s} />
            <path d={LAND_D} fill="#E9EDF1" stroke="#CFD6DE" strokeWidth={0.6 * s} />

            {/* region labels */}
            {GEO_REGIONS.filter((r) => r.id !== "site").map((r) => {
              const [x, y] = REGION_XY.get(r.id)!;
              const total = GEO_ENTITIES.filter((e) => e.regionId === r.id).length;
              const count = GEO_ENTITIES.filter((e) => e.regionId === r.id && activeEntityIds.has(e.id)).length;
              const anyActive = count > 0;
              const off = total > 1 ? 32 : 22;
              return (
                <g
                  key={r.id}
                  opacity={anyActive ? 1 : 0.35}
                  onClick={(ev) => {
                    ev.stopPropagation();
                    setSelection({ type: "region", id: r.id });
                    onGraphNodeSelect(null);
                  }}
                  style={{ cursor: "pointer" }}
                >
                  <text
                    x={x}
                    y={y + off * s}
                    textAnchor="middle"
                    fontSize={9.5 * s}
                    fontWeight={600}
                    fill={r.policy === "approved" ? "#3E6B57" : "#1F2933"}
                  >
                    {r.label}
                  </text>
                  <text x={x} y={y + (off + 10) * s} textAnchor="middle" fontSize={8 * s} fill="#5B6773">
                    {r.policy === "approved" ? "approved region" : `${count} active entit${count === 1 ? "y" : "ies"}`}
                  </text>
                </g>
              );
            })}

            {/* links */}
            {visibleLinks.map((l) => {
              const e = GEO_ENTITIES.find((x) => x.id === l.entityId)!;
              const idx = linkIndex.get(l.entityId) ?? 0;
              linkIndex.set(l.entityId, idx + 1);
              const [ex, ey] = ENTITY_XY.get(e.id)!;
              const [sx, sy] = SITE_XY;
              const from: [number, number] = l.inbound ? [ex, ey] : [sx, sy];
              const to: [number, number] = l.inbound ? [sx, sy] : [ex, ey];
              const dx = to[0] - from[0];
              const dy = to[1] - from[1];
              const len = Math.hypot(dx, dy) || 1;
              let nx = -dy / len;
              let ny = dx / len;
              if (ny > 0) {
                nx = -nx;
                ny = -ny;
              }
              const curv = 0.14 + idx * 0.1;
              const cx = (from[0] + to[0]) / 2 + nx * len * curv;
              const cy = (from[1] + to[1]) / 2 + ny * len * curv;
              const tx = to[0] - cx;
              const ty = to[1] - cy;
              const tl = Math.hypot(tx, ty) || 1;
              const ux = tx / tl;
              const uy = ty / tl;
              const endR = (l.inbound ? 9 : markerRadius(e.flows)) * s + 2;
              const end: [number, number] = [to[0] - ux * endR, to[1] - uy * endR];
              const color = l.category ? CATEGORY_COLOR[l.category] : BASELINE;
              const w = linkWidth(l.mb) * s;
              const ah = 5.5 * s;
              const dimmed =
                selection?.type === "entity" && selection.id !== l.entityId
                  ? 0.15
                  : 1;
              return (
                <g key={l.id} opacity={dimmed}>
                  <path
                    d={`M${from[0]} ${from[1]} Q${cx} ${cy} ${end[0]} ${end[1]}`}
                    fill="none"
                    stroke={color}
                    strokeWidth={w}
                    strokeOpacity={l.suspicious ? 0.85 : 0.5}
                    strokeLinecap="round"
                    strokeDasharray={
                      l.retroHuntOnly
                        ? `${2 * s} ${3 * s}`
                        : l.direction === "client-to-server"
                        ? `${6 * s} ${3 * s}`
                        : l.direction === "server-to-client"
                        ? `${2 * s} ${3 * s}`
                        : undefined
                    }
                  />
                  <path
                    d={`M${end[0]} ${end[1]} L${end[0] - ux * ah + -uy * ah * 0.55} ${end[1] - uy * ah + ux * ah * 0.55} L${end[0] - ux * ah - -uy * ah * 0.55} ${end[1] - uy * ah - ux * ah * 0.55} Z`}
                    fill={color}
                    fillOpacity={l.suspicious ? 0.9 : 0.55}
                  />
                </g>
              );
            })}

            {/* external entities */}
            {GEO_ENTITIES.filter((e) => !e.retroHuntOnly || bundleImported).map((e) => {
              const [x, y] = ENTITY_XY.get(e.id)!;
              const active = activeEntityIds.has(e.id);
              const r = markerRadius(e.flows) * s;
              const color = e.category ? CATEGORY_COLOR[e.category] : BASELINE;
              const sev = entitySeverity(e);
              const selected = selection?.type === "entity" && selection.id === e.id;
              const ring = e.suspicious && (sev === "Critical" || sev === "High");
              return (
                <g
                  key={e.id}
                  opacity={active ? 1 : 0.18}
                  onClick={(ev) => {
                    ev.stopPropagation();
                    selectEntity(e);
                  }}
                  onMouseEnter={(ev) => setHover({ id: e.id, x: ev.clientX, y: ev.clientY })}
                  onMouseMove={(ev) => setHover({ id: e.id, x: ev.clientX, y: ev.clientY })}
                  onMouseLeave={() => setHover(null)}
                  style={{ cursor: "pointer" }}
                >
                  {ring ? (
                    <circle cx={x} cy={y} r={r + 3.2 * s} fill="none" stroke={SEVERITY_COLOR[sev]} strokeWidth={1 * s} />
                  ) : null}
                  <circle
                    cx={x}
                    cy={y}
                    r={r}
                    fill={rgba(color, e.suspicious ? 0.28 : 0.18)}
                    stroke={selected ? "#1F3A5F" : color}
                    strokeWidth={(selected ? 2 : 1.2) * s}
                  />
                  {e.suspicious ? <circle cx={x} cy={y} r={1.6 * s} fill={color} /> : null}
                </g>
              );
            })}

            {/* site */}
            <g
              onClick={(ev) => {
                ev.stopPropagation();
                setSelection({ type: "site" });
                onGraphNodeSelect(null);
              }}
              style={{ cursor: "pointer" }}
            >
              <rect
                x={SITE_XY[0] - 7 * s}
                y={SITE_XY[1] - 7 * s}
                width={14 * s}
                height={14 * s}
                rx={2 * s}
                fill="#1F3A5F"
                stroke={selection?.type === "site" ? "#2F5D9E" : "#FFFFFF"}
                strokeWidth={(selection?.type === "site" ? 3 : 1.5) * s}
              />
              <text x={SITE_XY[0]} y={SITE_XY[1] - 12 * s} textAnchor="middle" fontSize={9.5 * s} fontWeight={700} fill="#1F3A5F">
                Site A
              </text>
              <text x={SITE_XY[0] + 11 * s} y={SITE_XY[1] + 3 * s} textAnchor="start" fontSize={8 * s} fill="#5B6773">
                monitored network · sensor-01
              </text>
            </g>
          </g>
        </svg>

        {/* controls */}
        <div className="absolute right-2 top-2 flex flex-col overflow-hidden rounded border border-border-strong bg-white">
          <button
            className="flex h-[24px] w-[24px] items-center justify-center text-ink2 hover:bg-[#f2f4f7] hover:text-ink"
            onClick={() => zoomAt(1.4, W / 2, H / 2)}
            title="Zoom in"
          >
            <Plus size={12} strokeWidth={1.8} />
          </button>
          <button
            className="flex h-[24px] w-[24px] items-center justify-center border-t border-border text-ink2 hover:bg-[#f2f4f7] hover:text-ink"
            onClick={() => zoomAt(1 / 1.4, W / 2, H / 2)}
            title="Zoom out"
          >
            <Minus size={12} strokeWidth={1.8} />
          </button>
          <button
            className="flex h-[24px] w-[24px] items-center justify-center border-t border-border text-ink2 hover:bg-[#f2f4f7] hover:text-ink"
            onClick={() => setView({ k: 1, x: 0, y: 0 })}
            title="Reset view"
          >
            <RotateCcw size={11} strokeWidth={1.8} />
          </button>
        </div>
        <div className="pointer-events-none absolute right-2 bottom-2 rounded border border-border bg-white/95 px-1.5 py-[2px] font-mono text-[9.5px] text-ink2">
          {view.k.toFixed(1)}× · drag to pan · {armed ? "scroll" : "Ctrl + scroll"} to zoom
        </div>

        {/* legend */}
        <div className="pointer-events-none absolute left-2 bottom-2 rounded border border-border bg-white/95 px-2 py-1.5">
          <div className="grid grid-cols-2 gap-x-3 gap-y-[2px]">
            {(["C2 Beaconing", "Exfiltration", "DGA/DNS Tunnelling", "Encrypted Malware", "DDoS"] as Category[]).map((c) => (
              <span key={c} className="inline-flex items-center gap-1.5 text-[9.5px] text-ink2">
                <span className="inline-block h-[3px] w-4 rounded-[1px]" style={{ backgroundColor: CATEGORY_COLOR[c] }} />
                {c.replace("DGA/DNS Tunnelling", "DGA / tunnelling").replace("Encrypted Malware", "Encrypted anomaly")}
              </span>
            ))}
            <span className="inline-flex items-center gap-1.5 text-[9.5px] text-ink2">
              <span className="inline-block h-[3px] w-4 rounded-[1px]" style={{ backgroundColor: BASELINE }} />
              baseline / approved
            </span>
          </div>
          <div className="mt-1 flex items-center gap-3 border-t border-border pt-1 text-[9.5px] text-ink2">
            <span className="inline-flex items-center gap-1">
              <span className="inline-block h-2.5 w-2.5 rounded-full border border-[#C2410C]" /> High / Critical ring
            </span>
            <span>dashed = one direction</span>
            <span>size = log flows</span>
          </div>
        </div>

        {/* tooltip */}
        {hover && hoverEntity ? (
          <Tooltip x={hover.x} y={hover.y} wrap={wrapRef.current}>
            <div className="font-mono text-[11px] font-semibold text-ink">{hoverEntity.label}</div>
            <div className="text-[10.5px] text-ink2">
              {hoverEntity.sub} · {GEO_REGIONS.find((r) => r.id === hoverEntity.regionId)?.label}
            </div>
            <div className="mt-1 flex items-center gap-2 text-[10.5px]">
              {hoverEntity.category ? (
                <span className="inline-flex items-center gap-1 text-ink">
                  <span className="inline-block h-2 w-2 rounded-full" style={{ backgroundColor: CATEGORY_COLOR[hoverEntity.category] }} />
                  {hoverEntity.category}
                </span>
              ) : (
                <span className="text-ink2">baseline</span>
              )}
              <span className="font-mono tabular-nums text-ink2">
                {hoverEntity.flows.toLocaleString("en-US")} flows · {fmtMb(hoverEntity.mb)}
              </span>
            </div>
            <div className="mt-[2px] flex items-center gap-2 text-[10.5px]">
              <span className="font-mono text-ink2">{hoverEntity.incidents.filter(incidentVisible).join(", ")}</span>
              <span
                className="rounded-[2px] px-1 text-[9.5px] font-semibold text-white"
                style={{ backgroundColor: SEVERITY_COLOR[entitySeverity(hoverEntity)] }}
              >
                {entitySeverity(hoverEntity)} · risk {entityRisk(hoverEntity)}
              </span>
            </div>
          </Tooltip>
        ) : null}
      </div>

      {/* side panel */}
      <div className="col-span-4 flex flex-col">
        <div className="flex items-center justify-between border-b border-border px-3 py-1.5">
          <span className="text-[10.5px] font-semibold uppercase tracking-wide text-ink2">
            {selection?.type === "entity"
              ? "Entity"
              : selection?.type === "site"
              ? "Monitored site"
              : selection?.type === "region"
              ? "Hosting region"
              : "Egress and ingress by region"}
          </span>
          <div className="inline-flex overflow-hidden rounded border border-border-strong">
            {(["all", "suspicious"] as const).map((m) => (
              <button
                key={m}
                onClick={() => setMode(m)}
                className={`h-[20px] px-1.5 text-[10px] ${
                  mode === m ? "bg-navy text-white" : "bg-white text-ink2 hover:text-ink"
                }`}
              >
                {m === "all" ? "All observed" : "Suspicious only"}
              </button>
            ))}
          </div>
        </div>

        <div className="flex-1 overflow-auto px-3 py-2" style={{ maxHeight: 428 }}>
          {selection?.type === "entity" ? (
            <EntityDetail
              entity={GEO_ENTITIES.find((e) => e.id === selection.id)!}
              links={GEO_LINKS.filter(
                (l) => l.entityId === selection.id && (!l.retroHuntOnly || bundleImported) && incidentVisible(l.incident)
              )}
              severity={entitySeverity(GEO_ENTITIES.find((e) => e.id === selection.id)!)}
              risk={entityRisk(GEO_ENTITIES.find((e) => e.id === selection.id)!)}
              incidentVisible={incidentVisible}
              onIncidentSelect={onIncidentSelect}
              onHostSelect={onHostSelect}
              fmtMb={fmtMb}
            />
          ) : selection?.type === "site" ? (
            <SiteDetail incidents={incidents} bundleImported={bundleImported} onHostSelect={onHostSelect} onIncidentSelect={onIncidentSelect} />
          ) : selection?.type === "region" ? (
            <RegionDetail
              regionId={selection.id}
              activeIds={activeEntityIds}
              bundleImported={bundleImported}
              onEntitySelect={(e) => selectEntity(e)}
              fmtMb={fmtMb}
            />
          ) : (
            <>
              {regionRows.length ? (
                <table className="w-full text-[11px]">
                  <thead>
                    <tr className="text-[10px] text-ink2">
                      <th className="pb-1 text-left font-medium">Region</th>
                      <th className="pb-1 text-right font-medium">Out</th>
                      <th className="pb-1 text-right font-medium">In</th>
                      <th className="pb-1 text-left font-medium pl-2">Context</th>
                    </tr>
                  </thead>
                  <tbody>
                    {regionRows.map((r) => (
                      <tr
                        key={r.region.id}
                        className="cursor-pointer border-t border-border hover:bg-[#f7f8fa]"
                        onClick={() => setSelection({ type: "region", id: r.region.id })}
                      >
                        <td className="py-[4px]">
                          <div className="font-medium text-ink">{r.region.label}</div>
                          <div
                            className="text-[9.5px]"
                            style={{ color: r.region.policy === "approved" ? "#3E6B57" : "#B7791F" }}
                          >
                            {r.region.policy === "approved" ? "approved region" : "no approved relationship"}
                          </div>
                        </td>
                        <td className="py-[4px] text-right font-mono tabular-nums text-ink">
                          {r.out ? fmtMb(r.out) : "—"}
                        </td>
                        <td className="py-[4px] text-right font-mono tabular-nums text-ink">
                          {r.inn ? fmtMb(r.inn) : "—"}
                        </td>
                        <td className="py-[4px] pl-2">
                          <span className="flex flex-wrap gap-1">
                            {r.cats.length ? (
                              r.cats.map((c) => (
                                <span key={c} className="inline-block h-2 w-2 rounded-full" title={c} style={{ backgroundColor: CATEGORY_COLOR[c] }} />
                              ))
                            ) : (
                              <span className="text-[9.5px] text-ink2">baseline</span>
                            )}
                            <span className="ml-1 font-mono text-[9.5px] tabular-nums text-ink2">
                              {r.flows.toLocaleString("en-US")} fl.
                            </span>
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              ) : (
                <p className="py-2 text-[11px] text-ink2">
                  No plotted activity matches the current filters.
                </p>
              )}

              <div className="mt-2 border-t border-border pt-2">
                <div className="text-[10px] font-semibold uppercase tracking-wide text-ink2">
                  What the map shows
                </div>
                <ul className="mt-1 space-y-1">
                  {insights.map((i, n) => (
                    <li key={n} className="flex gap-1.5 text-[10.5px] leading-snug text-ink">
                      <span className="mt-[5px] inline-block h-1 w-1 shrink-0 rounded-full bg-navy" />
                      <span>
                        {i.incident ? (
                          <button
                            onClick={() => onIncidentSelect(i.incident!)}
                            className="mr-1 font-mono text-[10px] text-link hover:underline"
                          >
                            {i.incident}
                          </button>
                        ) : null}
                        {i.text}
                      </span>
                    </li>
                  ))}
                </ul>
              </div>

              <div className="mt-2 border-t border-border pt-2">
                <div className="text-[10px] font-semibold uppercase tracking-wide text-ink2">
                  Not plotted
                </div>
                <ul className="mt-1 space-y-1">
                  {NOT_PLOTTED.map((n) => (
                    <li key={n.label} className="text-[10.5px] leading-snug text-ink2">
                      <span className="font-medium text-ink">{n.label}</span>{" "}
                      <span className="font-mono text-[9.5px]">({n.incident})</span> — {n.detail}
                    </li>
                  ))}
                </ul>
              </div>
            </>
          )}
        </div>

        <div className="border-t border-border bg-[#f7f8fa] px-3 py-1.5 text-[10px] leading-snug text-ink2">
          Regions come from the ASN / prefix dataset in the local TI bundle. Documentation-range
          addresses carry synthetic associations. A hosting region indicates where rented
          infrastructure is announced from, not who operates it.
        </div>
      </div>
    </div>
  );
}

/* ------------------------------ sub-panels ------------------------------ */

function Tooltip({
  x,
  y,
  wrap,
  children,
}: {
  x: number;
  y: number;
  wrap: HTMLDivElement | null;
  children: React.ReactNode;
}) {
  const rect = wrap?.getBoundingClientRect();
  const left = rect ? x - rect.left + 12 : x;
  const top = rect ? y - rect.top + 12 : y;
  const flip = rect ? left > rect.width - 240 : false;
  return (
    <div
      className="pointer-events-none absolute z-20 w-[228px] rounded border border-border bg-white px-2 py-1.5 shadow-[0_4px_12px_rgba(31,41,51,0.10)]"
      style={{ left: flip ? left - 252 : left, top }}
    >
      {children}
    </div>
  );
}

function EntityDetail({
  entity,
  links,
  severity,
  risk,
  incidentVisible,
  onIncidentSelect,
  onHostSelect,
  fmtMb,
}: {
  entity: GeoEntity;
  links: GeoLink[];
  severity: string;
  risk: number;
  incidentVisible: (id: string) => boolean;
  onIncidentSelect: (id: string) => void;
  onHostSelect: (ip: string) => void;
  fmtMb: (mb: number) => string;
}) {
  const region = GEO_REGIONS.find((r) => r.id === entity.regionId)!;
  return (
    <div className="space-y-2">
      <div className="flex items-start justify-between gap-2">
        <div>
          <div className="font-mono text-[13px] font-semibold text-ink">{entity.label}</div>
          <div className="text-[11px] text-ink2">{entity.sub}</div>
        </div>
        <span
          className="rounded-[3px] px-1.5 py-[1px] text-[10.5px] font-semibold text-white"
          style={{ backgroundColor: SEVERITY_COLOR[severity] }}
        >
          {severity} · {risk}
        </span>
      </div>
      <DetailList
        rows={[
          {
            k: "Hosting region",
            v: (
              <span>
                {region.label}{" "}
                <span className="text-[10px]" style={{ color: region.policy === "approved" ? "#3E6B57" : "#B7791F" }}>
                  · {region.policy === "approved" ? "approved" : region.policy === "site" ? "site" : "no approved relationship"}
                </span>
              </span>
            ),
          },
          { k: "Announced by", v: <span className="font-mono text-[10.5px]">{entity.asn}</span> },
          { k: "Prefix", v: <span className="font-mono text-[10.5px]">{entity.prefix}</span> },
          {
            k: "Category",
            v: entity.category ? (
              <span className="inline-flex items-center gap-1.5">
                <span className="inline-block h-2 w-2 rounded-full" style={{ backgroundColor: CATEGORY_COLOR[entity.category] }} />
                {entity.category}
              </span>
            ) : (
              <span className="text-ink2">baseline / approved</span>
            ),
          },
          {
            k: "Incidents",
            v: (
              <span className="flex flex-wrap gap-1">
                {entity.incidents.filter(incidentVisible).map((id) => (
                  <button
                    key={id}
                    onClick={() => onIncidentSelect(id)}
                    className="rounded-[3px] border border-border bg-white px-1.5 py-[1px] font-mono text-[10px] text-link hover:border-navy"
                  >
                    {id}
                  </button>
                ))}
              </span>
            ),
          },
          { k: "Flows / volume", v: <span className="font-mono tabular-nums">{entity.flows.toLocaleString("en-US")} · {fmtMb(entity.mb)}</span> },
          { k: "First seen", v: <span className="font-mono text-[10.5px]">{entity.firstSeen}</span> },
          { k: "Last seen", v: <span className="font-mono text-[10.5px]">{entity.lastSeen}</span> },
        ]}
      />
      <p className="text-[10.5px] leading-snug text-ink2">{entity.note}</p>
      <div className="border-t border-border pt-2">
        <div className="text-[10px] font-semibold uppercase tracking-wide text-ink2">Observed relationships</div>
        <ul className="mt-1 space-y-1">
          {links.map((l) => (
            <li key={l.id} className="flex items-start gap-1.5 text-[10.5px] leading-snug">
              <span className="mt-[4px] inline-block h-1.5 w-1.5 shrink-0 rounded-full" style={{ backgroundColor: l.category ? CATEGORY_COLOR[l.category] : BASELINE }} />
              <span className="min-w-0">
                <button onClick={() => onHostSelect(l.host)} className="font-mono text-link hover:underline">
                  {l.host}
                </button>{" "}
                <span className="text-ink">{l.label.replace(`${l.host} → `, "→ ").replace(/^\d+ reflectors/, (m) => m)}</span>
                <span className="block font-mono text-[9.5px] text-ink2">
                  {l.direction}{l.retroHuntOnly ? " · retro-hunt" : ""} · {l.incident}
                </span>
              </span>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}

function SiteDetail({
  incidents,
  bundleImported,
  onHostSelect,
  onIncidentSelect,
}: {
  incidents: Incident[];
  bundleImported: boolean;
  onHostSelect: (ip: string) => void;
  onIncidentSelect: (id: string) => void;
}) {
  return (
    <div className="space-y-2">
      <div>
        <div className="text-[13px] font-semibold text-ink">Site A — monitored network</div>
        <div className="text-[11px] text-ink2">Enclave A · sensor-01 · receive-only · 22 VLANs</div>
      </div>
      <p className="text-[10.5px] leading-snug text-ink2">
        Internal assets are shown as one site: their geography is the site itself. The hosts below
        are the entities with open or recently closed incidents.
      </p>
      <table className="w-full text-[11px]">
        <thead>
          <tr className="text-[10px] text-ink2">
            <th className="pb-1 text-left font-medium">Host</th>
            <th className="pb-1 text-left font-medium">Incident</th>
            <th className="pb-1 text-right font-medium">Risk</th>
          </tr>
        </thead>
        <tbody>
          {HOST_PROFILES.map((p) => {
            const inc = incidents.find((i) => i.id === p.incident);
            if (!inc || (inc.hiddenUntilRetroHunt && !bundleImported)) return null;
            const sev = riskSeverity(inc.risk);
            return (
              <tr key={p.ip} className="border-t border-border">
                <td className="py-[4px]">
                  <button onClick={() => onHostSelect(p.ip)} className="font-mono text-link hover:underline">
                    {p.ip}
                  </button>
                  <span className="ml-1 text-[10px] text-ink2">{p.hostname}</span>
                </td>
                <td className="py-[4px]">
                  <button onClick={() => onIncidentSelect(inc.id)} className="font-mono text-[10.5px] text-link hover:underline">
                    {inc.id}
                  </button>
                </td>
                <td className="py-[4px] text-right font-mono font-semibold tabular-nums" style={{ color: SEVERITY_COLOR[sev] }}>
                  {inc.risk}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
      <div className="border-t border-border pt-2 text-[10.5px] leading-snug text-ink2">
        <span className="font-medium text-ink">Inside the site, not drawn as arcs:</span> horizontal scan of
        10.2.3.0/24 (254 hosts, INC-0417) and slow scan of 10.1.9.0/24 (96 hosts, INC-0412).
      </div>
    </div>
  );
}

function RegionDetail({
  regionId,
  activeIds,
  bundleImported,
  onEntitySelect,
  fmtMb,
}: {
  regionId: string;
  activeIds: Set<string>;
  bundleImported: boolean;
  onEntitySelect: (e: GeoEntity) => void;
  fmtMb: (mb: number) => string;
}) {
  const region = GEO_REGIONS.find((r) => r.id === regionId)!;
  const entities = GEO_ENTITIES.filter((e) => e.regionId === regionId && (!e.retroHuntOnly || bundleImported));
  const total = entities.reduce((a, e) => a + e.mb, 0);
  return (
    <div className="space-y-2">
      <div>
        <div className="text-[13px] font-semibold text-ink">{region.label}</div>
        <div className="text-[11px]" style={{ color: region.policy === "approved" ? "#3E6B57" : "#B7791F" }}>
          {region.policyText}
        </div>
      </div>
      <DetailList
        rows={[
          { k: "Entities", v: <span className="font-mono tabular-nums">{entities.length}</span> },
          { k: "Total volume", v: <span className="font-mono tabular-nums">{fmtMb(total)}</span> },
          { k: "Active in view", v: <span className="font-mono tabular-nums">{entities.filter((e) => activeIds.has(e.id)).length}</span> },
        ]}
      />
      <ul className="space-y-1 border-t border-border pt-2">
        {entities.map((e) => (
          <li key={e.id}>
            <button
              onClick={() => onEntitySelect(e)}
              className={`flex w-full items-center gap-2 rounded-[3px] border px-2 py-1 text-left hover:border-navy ${
                activeIds.has(e.id) ? "border-border bg-white" : "border-border bg-[#fbfbfc] opacity-60"
              }`}
            >
              <span className="inline-block h-2 w-2 shrink-0 rounded-full" style={{ backgroundColor: e.category ? CATEGORY_COLOR[e.category] : BASELINE }} />
              <span className="min-w-0 flex-1">
                <span className="block truncate font-mono text-[11px] text-ink">{e.label}</span>
                <span className="block truncate text-[10px] text-ink2">{e.sub}</span>
              </span>
              <span className="font-mono text-[10px] tabular-nums text-ink2">{fmtMb(e.mb)}</span>
            </button>
          </li>
        ))}
      </ul>
    </div>
  );
}
