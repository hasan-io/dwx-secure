import { Filter, Search } from "lucide-react";
import { Link } from "react-router-dom";
import { CategoryDot, Chip, Panel, PanelHeader, Select, SeverityBadge, StatusPill } from "../components/ui";
import { AssetChip } from "../components/AppShell";
import { Investigation } from "../components/Investigation";
import { useDemo } from "../store/store";
import { riskSeverity } from "../lib/utils";

const SEVERITIES = ["all", "Critical", "High", "Medium", "Low"];
const STATUSES = ["all", "Open", "Investigating", "Resolved"];
const CATEGORIES = [
  "all",
  "Reconnaissance",
  "C2 Beaconing",
  "DGA/DNS Tunnelling",
  "Encrypted Malware",
  "Exfiltration",
  "DDoS",
];

export default function Incidents() {
  const incidents = useDemo((s) => s.incidents);
  const selectedId = useDemo((s) => s.selectedIncidentId);
  const setSelected = useDemo((s) => s.setSelected);
  const search = useDemo((s) => s.search);
  const filterSeverity = useDemo((s) => s.filterSeverity);
  const filterStatus = useDemo((s) => s.filterStatus);
  const filterCategory = useDemo((s) => s.filterCategory);
  const setFilter = useDemo((s) => s.setFilter);

  const visible = incidents.filter((i) => !i.hiddenUntilRetroHunt);
  const filtered = visible.filter((i) => {
    const q = search.trim().toLowerCase();
    const matchesSearch =
      !q ||
      i.id.toLowerCase().includes(q) ||
      i.entity.includes(q) ||
      (i.hostname ?? "").toLowerCase().includes(q) ||
      i.title.toLowerCase().includes(q);
    const matchesSev = filterSeverity === "all" || i.severity === filterSeverity;
    const matchesStatus = filterStatus === "all" || i.status === filterStatus;
    const matchesCat = filterCategory === "all" || i.category === filterCategory;
    return matchesSearch && matchesSev && matchesStatus && matchesCat;
  });

  const selected = incidents.find((i) => i.id === selectedId) ?? filtered[0] ?? visible[0];

  return (
    <div className="space-y-3">
      <div className="flex items-end justify-between">
        <div>
          <h1 className="text-[17px] font-semibold leading-tight text-ink">Incidents</h1>
          <p className="mt-[2px] text-[12px] text-ink2">
            Correlated findings, risk scores and recommended responses. Detection is advisory;
            enforcement happens outside DiodeWatch.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Chip title="Global search from the top bar applies to this list">
            <Search size={11} strokeWidth={1.6} />
            {search ? `filter: ${search}` : "no search filter"}
          </Chip>
          <Link to="/response" className="text-[12px] text-link hover:underline">
            Response &amp; reports
          </Link>
        </div>
      </div>

      <div className="grid grid-cols-[310px_1fr] gap-3">
        {/* List */}
        <Panel className="overflow-hidden">
          <PanelHeader
            title="Incident queue"
            subtitle={`${filtered.length} of ${visible.length} shown`}
            icon={<Filter size={13} strokeWidth={1.6} />}
          />
          <div className="grid grid-cols-3 gap-2 border-b border-border px-3 py-2">
            <Select
              label="Severity"
              value={filterSeverity}
              onChange={(v) => setFilter("severity", v)}
              options={SEVERITIES.map((s) => ({ value: s, label: s === "all" ? "All" : s }))}
            />
            <Select
              label="Status"
              value={filterStatus}
              onChange={(v) => setFilter("status", v)}
              options={STATUSES.map((s) => ({ value: s, label: s === "all" ? "All" : s }))}
            />
            <Select
              label="Category"
              value={filterCategory}
              onChange={(v) => setFilter("category", v)}
              options={CATEGORIES.map((s) => ({ value: s, label: s === "all" ? "All" : s }))}
            />
          </div>
          <ul className="max-h-[1100px] overflow-auto">
            {filtered.map((i) => {
              const active = i.id === selected?.id;
              return (
                <li key={i.id}>
                  <button
                    onClick={() => setSelected(i.id)}
                    className={`w-full border-b border-border px-3 py-2 text-left ${
                      active ? "border-l-[3px] border-l-navy bg-navy-soft" : "border-l-[3px] border-l-transparent hover:bg-[#f7f8fa]"
                    }`}
                  >
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-[12px] font-semibold text-ink">{i.id}</span>
                      <SeverityBadge severity={i.severity} />
                      <span className="ml-auto font-mono text-[13px] font-semibold tabular-nums" style={{ color: i.risk >= 90 ? "#A32020" : i.risk >= 70 ? "#C2410C" : i.risk >= 50 ? "#B7791F" : "#3E6B57" }}>
                        {i.risk}
                      </span>
                    </div>
                    <div className="mt-[3px] flex items-center gap-1.5 text-[11.5px] text-ink2">
                      <CategoryDot category={i.category} />
                      <span className="truncate">{i.title}</span>
                    </div>
                    <div className="mt-[3px] flex items-center gap-2 text-[11px] text-ink2">
                      <AssetChip ip={i.entity} />
                      <span>{i.hostname}</span>
                      <span className="ml-auto">
                        <StatusPill status={i.status} />
                      </span>
                    </div>
                    <div className="mt-[3px] font-mono text-[10.5px] text-ink3">
                      {i.findings.length} findings · last {i.lastSeen.replace("T", " ").slice(0, 16)} UTC
                      {i.risk >= 90 ? " · critical" : ""}
                    </div>
                  </button>
                </li>
              );
            })}
            {filtered.length === 0 ? (
              <li className="px-3 py-6 text-center text-[12px] text-ink2">
                No incident matches the current filters.
              </li>
            ) : null}
          </ul>
          <div className="border-t border-border px-3 py-2 text-[11px] text-ink3">
            Severity is derived from the risk score: Critical ≥ 90, High ≥ 70, Medium ≥ 50, Low below
            50. Current selection: {selected ? selected.id : "none"} ({selected ? riskSeverity(selected.risk) : "—"}).
          </div>
        </Panel>

        {/* Investigation */}
        <div>{selected ? <Investigation incident={selected} /> : null}</div>
      </div>
    </div>
  );
}
