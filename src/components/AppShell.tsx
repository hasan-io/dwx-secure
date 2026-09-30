import React, { useEffect, useState } from "react";
import { NavLink, useLocation, useNavigate } from "react-router-dom";
import {
  Activity,
  Command,
  Crosshair,
  FileText,
  Gauge,
  Lock,
  Radio,
  RotateCcw,
  ScrollText,
  Search,
  Share2,
  ShieldAlert,
  ShieldCheck,
  Waypoints,
} from "lucide-react";
import { cn } from "../lib/utils";
import { useDemo } from "../store/store";
import { ASSETS } from "../data/assets";
import { TI_BUNDLES } from "../data/iocs";

export function Logo({ size = 20 }: { size?: number }) {
  return (
    <span className="inline-flex items-center gap-2">
      <svg width={size} height={size} viewBox="0 0 24 24" aria-hidden>
        <path d="M3 5 L15 12 L3 19 Z" fill="#1F3A5F" />
        <rect x="17" y="4" width="2.6" height="16" fill="#1F3A5F" />
      </svg>
      <span className="text-[15px] font-semibold tracking-tight text-navy">DiodeWatch</span>
    </span>
  );
}

export function ReceiveOnlyPill({
  className,
  compact = false,
}: {
  className?: string;
  compact?: boolean;
}) {
  return (
    <span
      className={cn(
        "inline-flex h-[24px] shrink-0 items-center gap-1.5 whitespace-nowrap rounded-[3px] border border-navy bg-navy-soft px-2 text-[11px] font-semibold leading-none text-navy",
        className
      )}
      title="The monitoring sensor has no transmit path. Nothing is ever sent to the monitored network."
    >
      <Lock size={11} strokeWidth={1.6} className="shrink-0" />
      <span>RECEIVE-ONLY</span>
      <span className="text-[#93a3b8]">|</span>
      <span className="font-mono">TX 0 pkts</span>
      {compact ? null : (
        <>
          <span className="text-[#93a3b8]">|</span>
          <span className="hidden font-mono lg:inline">Egress: DROP</span>
        </>
      )}
    </span>
  );
}

const NAV = [
  { to: "/", label: "Overview", icon: Gauge, end: true },
  { to: "/live", label: "Live Monitor", icon: Radio, end: false },
  { to: "/incidents", label: "Incidents", icon: ShieldAlert, end: false },
  { to: "/intel", label: "Threat Intelligence", icon: Waypoints, end: false },
  { to: "/visualization", label: "Security Visualization", icon: Share2, end: false },
  { to: "/response", label: "Response & Reports", icon: FileText, end: false },
  { to: "/coverage", label: "Detection Coverage", icon: Crosshair, end: false },
  { to: "/audit", label: "Activity & Audit", icon: ScrollText, end: false },
  { to: "/trust", label: "Evaluation & Trust", icon: ShieldCheck, end: false },
];

export function Sidebar() {
  const incidents = useDemo((s) => s.incidents);
  const active = incidents.filter((i) => i.status !== "Resolved" && !i.hiddenUntilRetroHunt).length;

  return (
    <aside className="dw-no-print fixed inset-y-0 left-0 z-30 flex w-[196px] flex-col border-r border-border bg-panel">
      <div className="flex h-[46px] items-center border-b border-border px-3">
        <Logo />
      </div>
      <nav className="flex-1 overflow-auto py-2">
        {NAV.map((n) => (
          <NavLink
            key={n.to}
            to={n.to}
            end={n.end}
            className={({ isActive }) =>
              cn(
                "mx-1 flex items-center gap-2 rounded-[3px] px-2 py-[7px] text-[12.5px] transition-colors",
                isActive
                  ? "border-l-[3px] border-navy bg-navy-soft font-semibold text-navy"
                  : "border-l-[3px] border-transparent text-ink2 hover:bg-[#f2f4f7] hover:text-ink"
              )
            }
          >
            <n.icon size={14} strokeWidth={1.6} />
            <span className="min-w-0 flex-1 truncate">{n.label}</span>
            {n.label === "Incidents" ? (
              <span className="rounded-[3px] bg-[#eceff3] px-1.5 text-[10px] font-semibold tabular-nums text-ink2">
                {active}
              </span>
            ) : null}
          </NavLink>
        ))}
      </nav>
      <div className="border-t border-border px-3 py-2">
        <button
          onClick={() => useDemo.getState().resetDemo()}
          className="flex w-full items-center gap-2 rounded-[3px] px-2 py-[6px] text-[12px] text-ink2 hover:bg-[#f2f4f7] hover:text-ink"
        >
          <RotateCcw size={13} strokeWidth={1.6} />
          Reset demo
        </button>
        <div className="mt-1 px-2 text-[10.5px] leading-snug text-ink3">
          Prototype build. Simulated telemetry, synthetic IOCs, illustrative benchmark values.
        </div>
      </div>
    </aside>
  );
}

/** Demo reference time: 2026-09-30 12:00:00 UTC. The clock ticks with real seconds. */
const DEMO_EPOCH = Date.UTC(2026, 8, 30, 12, 0, 0);

export function TopBar() {
  const navigate = useNavigate();
  const location = useLocation();
  const search = useDemo((s) => s.search);
  const setSearch = useDemo((s) => s.setSearch);
  const setGuidedOpen = useDemo((s) => s.setGuidedOpen);
  const guidedOpen = useDemo((s) => s.guidedOpen);
  const bundleImported = useDemo((s) => s.bundleImported);
  const [clock, setClock] = React.useState(() => new Date(DEMO_EPOCH));
  const [palOpen, setPalOpen] = React.useState(false);
  const [palQuery, setPalQuery] = React.useState("");

  React.useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setPalOpen((o) => !o);
      }
      if (e.key === "Escape") setPalOpen(false);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  React.useEffect(() => {
    const start = Date.now();
    const t = setInterval(() => setClock(new Date(DEMO_EPOCH + (Date.now() - start))), 1000);
    return () => clearInterval(t);
  }, []);

  const utc = `${String(clock.getUTCFullYear())}-${String(clock.getUTCMonth() + 1).padStart(
    2,
    "0"
  )}-${String(clock.getUTCDate()).padStart(2, "0")} ${String(clock.getUTCHours()).padStart(
    2,
    "0"
  )}:${String(clock.getUTCMinutes()).padStart(2, "0")}:${String(clock.getUTCSeconds()).padStart(2, "0")} UTC`;

  const activeBundle = bundleImported ? TI_BUNDLES[1] : TI_BUNDLES[0];

  return (
    <header
      className={cn(
        "dw-no-print fixed inset-x-0 top-0 z-30 ml-[196px] flex h-[46px] flex-nowrap items-center gap-2 overflow-hidden border-b border-border bg-panel px-3 transition-[margin]",
        guidedOpen && "mr-[318px]"
      )}
    >
      <ReceiveOnlyPill compact={guidedOpen} />
      <span
        className={cn(
          "hidden h-[22px] shrink-0 items-center gap-1.5 whitespace-nowrap rounded-[3px] border border-border bg-white px-2 text-[11px] leading-none text-ink2",
          !guidedOpen && "2xl:inline-flex"
        )}
        title="Capture sensor — Enclave A, receive-only"
      >
        <Activity size={11} strokeWidth={1.6} className="shrink-0" />
        <span className="font-mono">sensor-01</span>
      </span>
      <span
        className={cn(
          "hidden h-[22px] shrink-0 items-center whitespace-nowrap rounded-[3px] border border-border bg-white px-2 font-mono text-[11px] leading-none text-ink2",
          !guidedOpen && "xl:inline-flex"
        )}
        title={`Threat-intel bundle ${activeBundle.version} — ${activeBundle.iocs.toLocaleString(
          "en-US"
        )} indicators, signature ${activeBundle.signature.toLowerCase()}`}
      >
        {activeBundle.version}
      </span>

      <span
        className="ml-auto shrink-0 whitespace-nowrap font-mono text-[11.5px] tabular-nums text-ink2"
        title={`${utc} — displayed times are UTC`}
      >
        {guidedOpen ? utc.slice(11) : utc}
      </span>

      <div className={cn("relative shrink-0", guidedOpen ? "w-[150px]" : "w-[206px] 2xl:w-[240px]")}>
        <Search
          size={12}
          strokeWidth={1.6}
          className="pointer-events-none absolute left-2 top-1/2 -translate-y-1/2 text-ink3"
        />
        <input
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          onFocus={() => {
            if (location.pathname !== "/incidents") navigate("/incidents");
          }}
          placeholder="Search incidents"
          className="h-[26px] w-full rounded border border-border-strong bg-white pl-6 pr-2 text-[12px] text-ink placeholder:text-ink3 focus:border-navy focus:outline-none"
        />
      </div>

      <button
        onClick={() => setGuidedOpen(!guidedOpen)}
        className={cn(
          "inline-flex h-[26px] shrink-0 items-center gap-1.5 whitespace-nowrap rounded border px-2.5 text-[12px] font-medium leading-none",
          guidedOpen
            ? "border-navy bg-navy text-white"
            : "border-border-strong bg-white text-ink hover:border-navy hover:text-navy"
        )}
      >
        Guided demo
      </button>

      <button
        onClick={() => setPalOpen(true)}
        className={cn(
          "hidden h-[26px] shrink-0 items-center gap-1.5 whitespace-nowrap rounded border border-border-strong bg-white px-2 text-[11px] leading-none text-ink2 hover:border-navy hover:text-navy",
          !guidedOpen && "2xl:inline-flex"
        )}
        title="Command palette (Ctrl K)"
      >
        <Command size={11} strokeWidth={1.6} className="shrink-0" />
        <span className="font-mono">Ctrl K</span>
      </button>

      <span
        className="inline-flex h-[22px] shrink-0 items-center gap-1.5 whitespace-nowrap rounded-[3px] border border-border bg-white px-2 text-[11px] leading-none text-ink2"
        title="Signed in as Analyst, SOC tier 1"
      >
        <span className="inline-block h-1.5 w-1.5 shrink-0 rounded-full bg-[#3E6B57]" />
        {guidedOpen ? "SOC-1" : "Analyst | SOC-1"}
      </span>
      {palOpen ? (
        <CommandPalette query={palQuery} setQuery={setPalQuery} close={() => setPalOpen(false)} />
      ) : null}
    </header>
  );
}

function CommandPalette({
  query,
  setQuery,
  close,
}: {
  query: string;
  setQuery: (v: string) => void;
  close: () => void;
}) {
  const navigate = useNavigate();
  const incidents = useDemo((s) => s.incidents).filter((i) => !i.hiddenUntilRetroHunt);
  const [index, setIndex] = useState(0);

  const entries = [
    ...NAV.map((n) => ({ id: n.to, label: n.label, kind: "Screen", detail: n.to })),
    ...incidents.map((i) => ({
      id: i.id,
      label: `${i.id} · ${i.title}`,
      kind: "Incident",
      detail: `${i.entity} · risk ${i.risk} · ${i.status}`,
    })),
  ];
  const q = query.trim().toLowerCase();
  const results = entries.filter(
    (e) => !q || e.label.toLowerCase().includes(q) || e.detail.toLowerCase().includes(q)
  );

  useEffect(() => {
    setIndex(0);
  }, [query]);

  const go = (id: string, kind: string) => {
    if (kind === "Incident") {
      useDemo.getState().setSelected(id);
      navigate("/incidents");
    } else {
      navigate(id);
    }
    close();
    setQuery("");
  };

  return (
    <div className="fixed inset-0 z-[70] flex items-start justify-center bg-[#1f2933]/25 p-[96px] dw-no-print">
      <div className="w-full max-w-[520px] rounded border border-border bg-panel shadow-[0_8px_24px_rgba(31,41,51,0.12)]">
        <div className="border-b border-border px-3 py-2">
          <input
            autoFocus
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "ArrowDown") {
                e.preventDefault();
                setIndex((i) => Math.min(i + 1, results.length - 1));
              } else if (e.key === "ArrowUp") {
                e.preventDefault();
                setIndex((i) => Math.max(i - 1, 0));
              } else if (e.key === "Enter" && results[index]) {
                go(results[index].id, results[index].kind);
              } else if (e.key === "Escape") {
                close();
              }
            }}
            placeholder="Jump to a screen or incident"
            className="h-[28px] w-full rounded border border-border-strong bg-white px-2 text-[12px] text-ink placeholder:text-ink3 focus:border-navy focus:outline-none"
          />
        </div>
        <ul className="max-h-[320px] overflow-auto">
          {results.map((r, i) => (
            <li key={`${r.kind}-${r.id}`}>
              <button
                onMouseEnter={() => setIndex(i)}
                onClick={() => go(r.id, r.kind)}
                className={`flex w-full items-center gap-2 px-3 py-[7px] text-left ${
                  i === index ? "bg-navy-soft" : "hover:bg-[#f7f8fa]"
                }`}
              >
                <span className="w-[58px] shrink-0 text-[10.5px] uppercase tracking-wide text-ink3">
                  {r.kind}
                </span>
                <span className="flex-1 truncate text-[12px] text-ink">{r.label}</span>
                <span className="shrink-0 font-mono text-[10.5px] text-ink2">{r.detail}</span>
              </button>
            </li>
          ))}
          {results.length === 0 ? (
            <li className="px-3 py-4 text-center text-[12px] text-ink2">No match.</li>
          ) : null}
        </ul>
        <div className="flex items-center gap-3 border-t border-border px-3 py-1.5 text-[10.5px] text-ink3">
          <span>↑ ↓ move</span>
          <span>Enter open</span>
          <span>Esc close</span>
          <span className="ml-auto">DiodeWatch command palette</span>
        </div>
      </div>
    </div>
  );
}

export function Footer() {
  return (
    <footer className="dw-no-print ml-[196px] border-t border-border px-3 py-2 text-[11px] text-ink3">
      Prototype build. Simulated telemetry, synthetic IOCs, illustrative benchmark values.
    </footer>
  );
}

/* ------------------------------ Asset hover card --------------------------- */

export function AssetChip({ ip, className }: { ip: string; className?: string }) {
  const asset = ASSETS[ip];
  if (!asset) {
    return <span className={cn("font-mono text-[12px] text-ink", className)}>{ip}</span>;
  }
  return (
    <span className={cn("group relative inline-block", className)}>
      <span className="cursor-default border-b border-dotted border-ink3 font-mono text-[12px] text-ink">
        {ip}
      </span>
      <span className="pointer-events-none absolute left-0 top-full z-40 mt-1 hidden w-[236px] rounded border border-border bg-panel px-3 py-2 text-left shadow-[0_6px_18px_rgba(31,41,51,0.12)] group-hover:block">
        <span className="block text-[12px] font-semibold text-ink">
          {asset.hostname}{" "}
          <span className="font-mono font-normal text-ink2">{asset.ip}</span>
        </span>
        <span className="mt-1 block text-[11px] text-ink2">VLAN — {asset.vlan}</span>
        <span className="block text-[11px] text-ink2">Department — {asset.department}</span>
        <span className="block text-[11px] text-ink2">Platform — {asset.os}</span>
        <span className="block text-[11px] text-ink2">Owner — {asset.owner}</span>
        <span className="mt-1 block text-[11px] text-ink2">
          Criticality —{" "}
          <span className="font-semibold" style={{ color: "#5B6773" }}>
            {asset.criticality}
          </span>
        </span>
      </span>
    </span>
  );
}

export function Toast() {
  const toast = useDemo((s) => s.toast);
  const setToast = useDemo((s) => s.setToast);
  React.useEffect(() => {
    if (!toast) return;
    const t = setTimeout(() => setToast(null), 4200);
    return () => clearTimeout(t);
  }, [toast, setToast]);
  if (!toast) return null;
  return (
    <div className="dw-no-print fixed bottom-4 left-1/2 z-[60] -translate-x-1/2 rounded border border-border bg-panel px-3 py-2 text-[12px] text-ink shadow-[0_6px_18px_rgba(31,41,51,0.14)]">
      {toast}
    </div>
  );
}
