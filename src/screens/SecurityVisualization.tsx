import { useMemo, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { Filter, RotateCcw, Share2 } from "lucide-react";
import { Chip, Panel } from "../components/ui";
import {
  EventTimeline,
  FlowDiagram,
  HostBehaviour,
  Legend,
  NetworkGraph,
  RiskEvolution,
  ThreatHeatmap,
  VizPanel,
} from "../components/viz";
import {
  HOST_PROFILES,
  TIME_RANGES,
  TIMELINE_EVENTS,
  type TimelineEvent,
} from "../data/visualization";
import { ActivityMap } from "../components/ActivityMap";
import { useDemo } from "../store/store";
import { CATEGORY_COLOR, SEVERITY_COLOR, riskSeverity } from "../lib/utils";
import type { Category } from "../lib/types";

const CATEGORIES: Category[] = [
  "Reconnaissance",
  "DGA/DNS Tunnelling",
  "C2 Beaconing",
  "Encrypted Malware",
  "Exfiltration",
  "DDoS",
];

const SEVERITIES = ["Critical", "High", "Medium", "Low"];

function FieldLabel({ children }: { children: ReactNode }) {
  return <span className="text-[10px] font-semibold uppercase tracking-wide text-ink2">{children}</span>;
}

export default function SecurityVisualization() {
  const incidents = useDemo((s) => s.incidents);
  const bundleImported = useDemo((s) => s.bundleImported);
  const visibilityMode = useDemo((s) => s.visibilityMode);
  const setVisibility = useDemo((s) => s.setVisibility);
  const setSelected = useDemo((s) => s.setSelected);

  const [rangeId, setRangeId] = useState("24h");
  const [host, setHost] = useState<string | null>("10.2.3.15");
  const [category, setCategory] = useState<Category | null>(null);
  const [severity, setSeverity] = useState<string | null>(null);
  const [incident, setIncident] = useState<string | null>("INC-0417");
  const [node, setNode] = useState<string | null>(null);
  const [edge, setEdge] = useState<string | null>(null);
  const [event, setEvent] = useState<string | null>("T-12");
  const [bucket, setBucket] = useState<number | null>(null);
  const [riskPoint, setRiskPoint] = useState<number | null>(680);

  const range = TIME_RANGES.find((r) => r.id === rangeId)!;
  const visibleIncidents = incidents.filter((i) => !i.hiddenUntilRetroHunt);

  /** Shared filters: time range, category, severity and incident context. */
  const events: TimelineEvent[] = useMemo(
    () =>
      TIMELINE_EVENTS.filter((e) => {
        if (e.minute < range.from || e.minute > range.to) return false;
        if (e.historical && !bundleImported) return false;
        if (category && e.category !== category) return false;
        if (incident && e.incident !== incident) return false;
        if (severity && riskSeverity(e.risk ?? 0) !== severity) return false;
        return true;
      }),
    [range, category, incident, severity, bundleImported]
  );

  const reset = () => {
    setRangeId("24h");
    setHost(null);
    setCategory(null);
    setSeverity(null);
    setIncident(null);
    setNode(null);
    setEdge(null);
    setEvent(null);
    setBucket(null);
    setRiskPoint(null);
  };

  const selectIncident = (id: string) => {
    const inc = incidents.find((i) => i.id === id);
    setIncident(id);
    if (inc) {
      setHost(inc.entity);
      setCategory(inc.category);
    }
  };

  const selectHost = (ip: string) => {
    setHost(ip);
    const profile = HOST_PROFILES.find((p) => p.ip === ip);
    if (profile?.incident) setIncident(profile.incident);
  };

  const activeFilters = [
    incident ? `incident ${incident}` : null,
    host ? `host ${host}` : null,
    category ? category : null,
    severity ? severity : null,
    bucket !== null ? `bucket ${String(Math.floor(bucket / 2)).padStart(2, "0")}:00` : null,
  ].filter(Boolean) as string[];

  return (
    <div className="space-y-3">
      {/* Header */}
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-[18px] font-semibold leading-tight tracking-tight text-ink">
              Security Visualization
            </h1>
            <span className="inline-flex items-center gap-1.5 rounded-[3px] border border-border bg-white px-1.5 py-[1px] text-[10.5px] text-ink2">
              <Share2 size={10} strokeWidth={1.8} /> linked views
            </span>
          </div>
          <p className="mt-[3px] text-[12px] text-ink2">
            Network activity, threat behaviour and incident evolution — the visual analytics layer
            over live monitoring and incident investigation.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Chip title="DiodeWatch observes a mirrored copy of traffic and never transmits">
            receive-only · observation
          </Chip>
          <Link to="/incidents" className="text-[12px] text-link hover:underline">
            Incident investigation
          </Link>
          <Link to="/live" className="text-[12px] text-link hover:underline">
            Live monitor
          </Link>
        </div>
      </div>

      {/* Filter / control row */}
      <Panel className="flex flex-wrap items-center gap-x-5 gap-y-2 px-3 py-2">
        <span className="inline-flex items-center gap-1.5 text-ink2">
          <Filter size={12} strokeWidth={1.7} />
          <FieldLabel>Time range</FieldLabel>
        </span>
        <div className="inline-flex overflow-hidden rounded border border-border-strong">
          {TIME_RANGES.map((r) => (
            <button
              key={r.id}
              onClick={() => setRangeId(r.id)}
              className={`h-[24px] px-2 text-[11px] ${
                rangeId === r.id ? "bg-navy text-white" : "bg-white text-ink2 hover:text-ink"
              }`}
            >
              {r.label}
            </button>
          ))}
        </div>

        <span className="inline-flex items-center gap-2">
          <FieldLabel>Host</FieldLabel>
          <select
            value={host ?? ""}
            onChange={(e) => (e.target.value ? selectHost(e.target.value) : setHost(null))}
            className="h-[24px] rounded border border-border-strong bg-white px-1.5 font-mono text-[11px] text-ink focus:border-navy focus:outline-none"
          >
            <option value="">All hosts</option>
            {HOST_PROFILES.map((p) => (
              <option key={p.ip} value={p.ip}>
                {p.ip} — {p.hostname}
              </option>
            ))}
          </select>
        </span>

        <span className="inline-flex items-center gap-2">
          <FieldLabel>Threat category</FieldLabel>
          <select
            value={category ?? ""}
            onChange={(e) => setCategory((e.target.value || null) as Category | null)}
            className="h-[24px] rounded border border-border-strong bg-white px-1.5 text-[11px] text-ink focus:border-navy focus:outline-none"
          >
            <option value="">All categories</option>
            {CATEGORIES.map((c) => (
              <option key={c} value={c}>
                {c}
              </option>
            ))}
          </select>
        </span>

        <span className="inline-flex items-center gap-2">
          <FieldLabel>Severity</FieldLabel>
          <select
            value={severity ?? ""}
            onChange={(e) => setSeverity(e.target.value || null)}
            className="h-[24px] rounded border border-border-strong bg-white px-1.5 text-[11px] text-ink focus:border-navy focus:outline-none"
          >
            <option value="">All</option>
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
        </span>

        <span className="inline-flex items-center gap-2">
          <FieldLabel>Incident</FieldLabel>
          <select
            value={incident ?? ""}
            onChange={(e) => (e.target.value ? selectIncident(e.target.value) : setIncident(null))}
            className="h-[24px] rounded border border-border-strong bg-white px-1.5 font-mono text-[11px] text-ink focus:border-navy focus:outline-none"
          >
            <option value="">All incidents</option>
            {visibleIncidents.map((i) => (
              <option key={i.id} value={i.id}>
                {i.id} — {i.title}
              </option>
            ))}
          </select>
        </span>

        <span className="inline-flex items-center gap-2">
          <FieldLabel>Visibility</FieldLabel>
          <div className="inline-flex overflow-hidden rounded border border-border-strong">
            {(["both", "one"] as const).map((m) => (
              <button
                key={m}
                onClick={() => setVisibility(m)}
                title={
                  m === "one"
                    ? "One-direction visibility: detectors fall back to direction-tolerant features"
                    : "Both directions visible from the mirror"
                }
                className={`h-[24px] px-2 text-[11px] ${
                  visibilityMode === m ? "bg-navy text-white" : "bg-white text-ink2 hover:text-ink"
                }`}
              >
                {m === "both" ? "Both directions" : "One direction"}
              </button>
            ))}
          </div>
        </span>

        <button
          onClick={reset}
          className="ml-auto inline-flex h-[24px] items-center gap-1.5 rounded border border-border-strong bg-white px-2 text-[11px] text-ink2 hover:border-navy hover:text-navy"
        >
          <RotateCcw size={11} strokeWidth={1.7} /> Clear filters
        </button>
      </Panel>

      {/* Context strip */}
      <div className="flex flex-wrap items-center gap-2 rounded border border-border bg-[#f7f8fa] px-3 py-1.5 text-[11px]">
        <span className="text-ink2">Workspace context</span>
        {activeFilters.length === 0 ? (
          <span className="text-ink3">no filters applied — all observed entities in view</span>
        ) : (
          activeFilters.map((f) => (
            <span
              key={f}
              className="rounded-[3px] border border-border bg-white px-1.5 py-[1px] font-mono text-[10.5px] text-ink"
            >
              {f}
            </span>
          ))
        )}
        <span className="ml-auto text-ink2">
          {events.length} timeline events in range
          {visibilityMode === "one" ? " · one-direction visibility, confidence shown at direction-tolerant values" : ""}
        </span>
      </div>

      {/* Row A — graph + timeline */}
      <div className="grid grid-cols-12 gap-3">
        <VizPanel
          className="col-span-7"
          title="Live network activity"
          subtitle="Observed communication between internal hosts, services and external entities"
          right={
            <>
              <span className="text-[10.5px] text-ink2">edge width = volume</span>
              <Legend
                items={[
                  { label: "suspicious", color: "#A32020" },
                  { label: "baseline", color: "#B9C2CC" },
                  { label: "single direction", color: "#B7791F" },
                ]}
              />
            </>
          }
        >
          <NetworkGraph
            selectedNode={node}
            onNodeSelect={(id) => {
              setNode(id);
              setEdge(null);
              const n = id ? HOST_PROFILES.find((p) => p.ip === id) : undefined;
              if (n) selectHost(n.ip);
            }}
            selectedEdge={edge}
            onEdgeSelect={setEdge}
            highlightCategory={category}
            bundleImported={bundleImported}
          />
        </VizPanel>

        <VizPanel
          className="col-span-5"
          title="Security event timeline"
          subtitle={`${range.label} · 2026-09-30 UTC · click a marker for finding detail`}
        >
          <EventTimeline
            events={events}
            from={range.from}
            to={range.to}
            selectedEvent={event}
            onEventSelect={(id) => {
              setEvent(id);
              const e = TIMELINE_EVENTS.find((x) => x.id === id);
              if (e) {
                setIncident(e.incident);
                setHost(e.entity);
              }
            }}
            highlightCategory={category}
            selectedIncident={incident}
            onIncidentSelect={(id) => selectIncident(id)}
          />
        </VizPanel>
      </div>

      {/* Row A2 — network activity map */}
      <VizPanel
        title="Network activity map"
        subtitle="Where observed external entities are announced from, and what moves between them and the monitored site"
        demoId="activity-map"
        right={
          <>
            <span className="rounded-[3px] border border-border bg-white px-1.5 py-[1px] text-[10.5px] text-ink2">
              region granularity · local bundle enrichment · no live lookups
            </span>
            <span className="rounded-[3px] border border-border bg-white px-1.5 py-[1px] text-[10.5px] text-ink2">
              no attribution implied
            </span>
          </>
        }
      >
        <ActivityMap
          incidents={incidents}
          bundleImported={bundleImported}
          category={category}
          severity={severity}
          incident={incident}
          host={host}
          onIncidentSelect={(id) => selectIncident(id)}
          onHostSelect={(ip) => selectHost(ip)}
          onGraphNodeSelect={(id) => {
            setNode(id);
            setEdge(null);
          }}
        />
      </VizPanel>

      {/* Row B — flow + heatmap */}
      <div className="grid grid-cols-12 gap-3">
        <VizPanel
          className="col-span-7"
          title="Traffic flow"
          subtitle="Host → protocol/service → destination → threat context"
          right={<span className="text-[10.5px] text-ink2">square-root volume scale</span>}
        >
          <FlowDiagram
            highlightCategory={category}
            onNodeSelect={(label) => {
              const profile = HOST_PROFILES.find((p) => p.ip === label);
              if (profile) selectHost(profile.ip);
              else if (CATEGORIES.includes(label.replace("DGA / Tunnelling", "DGA/DNS Tunnelling").replace("Encrypted anomaly", "Encrypted Malware") as Category))
                setCategory(label.replace("DGA / Tunnelling", "DGA/DNS Tunnelling").replace("Encrypted anomaly", "Encrypted Malware") as Category);
            }}
          />
        </VizPanel>

        <VizPanel
          className="col-span-5"
          title="Threat activity heatmap"
          subtitle="Event density by category and 30-minute bucket"
          right={
            bucket !== null ? (
              <button
                onClick={() => setBucket(null)}
                className="rounded-[3px] border border-border bg-white px-1.5 py-[1px] text-[10.5px] text-ink2 hover:border-navy"
              >
                clear bucket
              </button>
            ) : null
          }
        >
          <ThreatHeatmap
            highlightCategory={category}
            onCategorySelect={setCategory}
            selectedBucket={bucket}
            onBucketSelect={setBucket}
          />
        </VizPanel>
      </div>

      {/* Row C — risk + host profile */}
      <div className="grid grid-cols-12 gap-3">
        <VizPanel
          className="col-span-7"
          title="Incident risk evolution"
          subtitle="INC-0417 · risk accumulates as evidence arrives"
          right={
            <>
              {bundleImported ? (
                <span className="rounded-[3px] border border-[#7A5C7E] px-1.5 py-[1px] text-[10.5px] text-[#7A5C7E]">
                  retro-hunt match shown
                </span>
              ) : (
                <span className="rounded-[3px] border border-border px-1.5 py-[1px] text-[10.5px] text-ink2">
                  retro-hunt pending
                </span>
              )}
              <Link to="/incidents" onClick={() => setSelected("INC-0417")} className="text-[10.5px] text-link hover:underline">
                open INC-0417
              </Link>
            </>
          }
        >
          <RiskEvolution
            selected={riskPoint}
            onSelect={setRiskPoint}
            showRetro={bundleImported}
          />
        </VizPanel>

        <VizPanel
          className="col-span-5"
          title="Host behaviour profile"
          subtitle="Normal baseline against current behaviour for the selected host"
        >
          <HostBehaviour
            host={host ?? "10.2.3.15"}
            onHostSelect={selectHost}
            onIncidentSelect={(id) => selectIncident(id)}
            bundleImported={bundleImported}
          />
        </VizPanel>
      </div>

      {/* Reading note */}
      <Panel className="flex flex-wrap items-center gap-x-4 gap-y-1 px-3 py-2 text-[11px] text-ink2">
        <span className="font-medium text-ink">How to read this workspace</span>
        <span>Every panel is driven by the same filters and selection.</span>
        <span>Selecting a node, an event or a heatmap cell updates the related views.</span>
        <span>Colour encodes threat category; size encodes volume; position encodes time.</span>
        <span className="ml-auto">
          Prototype build. Simulated telemetry, synthetic IOCs, illustrative benchmark values.
        </span>
      </Panel>

      <div className="flex flex-wrap items-center gap-2">
        {CATEGORIES.map((c) => (
          <button
            key={c}
            onClick={() => setCategory(category === c ? null : c)}
            className={`inline-flex items-center gap-1.5 rounded-[3px] border px-1.5 py-[2px] text-[10.5px] ${
              category === c
                ? "border-navy bg-navy-soft font-semibold text-navy"
                : "border-border bg-white text-ink2 hover:text-ink"
            }`}
          >
            <span className="inline-block h-2 w-2 rounded-full" style={{ backgroundColor: CATEGORY_COLOR[c] }} />
            {c}
          </button>
        ))}
        <span className="ml-auto flex items-center gap-2">
          {SEVERITIES.map((s) => (
            <button
              key={s}
              onClick={() => setSeverity(severity === s ? null : s)}
              className={`inline-flex items-center gap-1.5 rounded-[3px] border px-1.5 py-[2px] text-[10.5px] ${
                severity === s
                  ? "border-navy bg-navy-soft font-semibold text-navy"
                  : "border-border bg-white text-ink2 hover:text-ink"
              }`}
            >
              <span className="inline-block h-2 w-2 rounded-full" style={{ backgroundColor: SEVERITY_COLOR[s] }} />
              {s}
            </button>
          ))}
        </span>
      </div>
    </div>
  );
}
