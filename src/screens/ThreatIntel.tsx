import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import {
  Bar,
  BarChart,
  CartesianGrid,
  LabelList,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import {
  BadgeCheck,
  Database,
  FileDown,
  History,
  Import,
  Search,
  ShieldCheck,
  Waypoints,
} from "lucide-react";
import {
  Button,
  CategoryTag,
  Chip,
  KeyValue,
  Modal,
  Panel,
  PanelHeader,
  ProgressBar,
  Select,
  SeverityBadge,
  StatusPill,
  Table,
  Tabs,
  Td,
  TextInput,
} from "../components/ui";
import { AXIS, ChartTooltip } from "../components/charts";
import { useDemo } from "../store/store";
import { IOCS, RETRO_HUNT, RETRO_HUNT_HISTORY, SOURCES, TI_BUNDLES, BUNDLE_DIFF } from "../data/iocs";
import { downloadText, fmtUtc, toCsv } from "../lib/utils";

export default function ThreatIntel() {
  const incidents = useDemo((s) => s.incidents);
  const bundleImported = useDemo((s) => s.bundleImported);
  const retroHuntStatus = useDemo((s) => s.retroHuntStatus);
  const retroHuntProgress = useDemo((s) => s.retroHuntProgress);
  const retroHuntScanLine = useDemo((s) => s.retroHuntScanLine);
  const importBundle = useDemo((s) => s.importBundle);
  const runRetroHunt = useDemo((s) => s.runRetroHunt);
  const setSelected = useDemo((s) => s.setSelected);
  const tiTab = useDemo((s) => s.tiTab);
  const setTiTab = useDemo((s) => s.setTiTab);

  const [importOpen, setImportOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [typeFilter, setTypeFilter] = useState("all");
  const [sourceFilter, setSourceFilter] = useState("all");

  const activeBundle = bundleImported ? TI_BUNDLES[1] : TI_BUNDLES[0];

  const byType = useMemo(() => {
    const map: Record<string, number> = { IPv4: 0, Domain: 0, JA4: 0, "Cert hash": 0 };
    IOCS.forEach((i) => (map[i.type] += 1));
    return Object.entries(map).map(([type, count]) => ({ type, count }));
  }, []);

  const bySource = useMemo(() => {
    const map: Record<string, number> = {};
    SOURCES.forEach((s) => (map[s] = 0));
    IOCS.forEach((i) => (map[i.source] += 1));
    return Object.entries(map).map(([source, count]) => ({ source, count }));
  }, []);

  const filteredIocs = IOCS.filter((i) => {
    const q = query.trim().toLowerCase();
    return (
      (!q || i.indicator.toLowerCase().includes(q)) &&
      (typeFilter === "all" || i.type === typeFilter) &&
      (sourceFilter === "all" || i.source === sourceFilter)
    );
  });

  const matches = incidents
    .filter((i) => !i.hiddenUntilRetroHunt)
    .flatMap((i) =>
      i.tiMatches.map((m) => ({ incident: i.id, entity: i.entity, hostname: i.hostname, ...m }))
    );

  return (
    <div className="space-y-3">
      <div className="flex items-end justify-between">
        <div>
          <h1 className="text-[17px] font-semibold leading-tight text-ink">Threat intelligence</h1>
          <p className="mt-[2px] text-[12px] text-ink2">
            Signed indicator bundles are imported over a one-way inbound path. No live reputation
            lookups are performed.
          </p>
        </div>
        <Button
          data-demo-id="import-bundle"
          variant="primary"
          onClick={() => setImportOpen(true)}
          disabled={bundleImported}
        >
          <Import size={13} strokeWidth={1.6} />
          {bundleImported ? "Bundle DW-TI-2026-09-30-B imported" : "Import bundle"}
        </Button>
      </div>

      {/* Bundle status */}
      <div className="grid grid-cols-3 gap-3">
        <Panel>
          <PanelHeader
            title="Active bundle"
            subtitle="Locally stored, signature verified at import"
            icon={<Database size={13} strokeWidth={1.6} />}
            right={
              <span className="inline-flex items-center gap-1 rounded-[3px] border border-[#3E6B57] px-1.5 py-[1px] text-[11px] font-medium text-[#3E6B57]">
                <BadgeCheck size={11} strokeWidth={1.6} /> {activeBundle.signature}
              </span>
            }
          />
          <div className="px-3 py-2.5">
            <KeyValue
              rows={[
                { k: "Version", v: <span className="font-mono text-[12px] font-semibold">{activeBundle.version}</span> },
                { k: "Indicators", v: <span className="font-mono tabular-nums">{activeBundle.iocs.toLocaleString("en-US")}</span> },
                { k: "Signature", v: activeBundle.signature },
                { k: "Schema", v: activeBundle.schema },
                { k: "Age", v: `${activeBundle.ageDays} days` },
                { k: "Imported", v: <span className="font-mono text-[11.5px]">{activeBundle.imported}</span> },
              ]}
            />
            <div className="mt-2 rounded border border-border bg-[#f7f8fa] px-2 py-1.5 text-[11px] leading-snug text-ink2">
              Confidence decays with indicator age: effective = base × 0.985<sup>days since last seen</sup>.
              Stale indicators are retained for matching but reported with reduced confidence.
            </div>
          </div>
        </Panel>

        <Panel>
          <PanelHeader title="Indicators by type" subtitle="Seeded sample set of 60 records" />
          <div className="px-2 pt-3" style={{ height: 150 }}>
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={byType} margin={{ left: 0, right: 20, top: 4 }}>
                <CartesianGrid stroke="#E6E9EE" vertical={false} />
                <XAxis dataKey="type" {...AXIS} />
                <YAxis {...AXIS} allowDecimals={false} width={22} />
                <Tooltip content={<ChartTooltip />} cursor={{ fill: "#F1F3F6" }} />
                <Bar dataKey="count" name="Indicators" barSize={22} fill="#1F3A5F" radius={[2, 2, 0, 0]}>
                  <LabelList dataKey="count" position="top" fill="#1F2933" fontSize={10} />
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Panel>

        <Panel>
          <PanelHeader title="Indicators by source" subtitle="Generic sample feed names" />
          <div className="space-y-1.5 px-3 py-2.5">
            {bySource.map((s) => (
              <div key={s.source} className="flex items-center gap-2">
                <span className="w-[176px] shrink-0 truncate text-[11.5px] text-ink2" title={s.source}>
                  {s.source}
                </span>
                <span className="h-[8px] flex-1 overflow-hidden rounded-[2px] bg-[#eef0f3]">
                  <span
                    className="block h-full rounded-[2px] bg-[#2F5D9E]"
                    style={{ width: `${(s.count / 14) * 100}%` }}
                  />
                </span>
                <span className="w-6 text-right font-mono text-[11.5px] tabular-nums text-ink">{s.count}</span>
              </div>
            ))}
          </div>
        </Panel>
      </div>

      {/* Retro-hunt banner */}
      {retroHuntStatus === "complete" ? (
        <Panel className="border-[#A32020]">
          <div className="flex flex-wrap items-center gap-3 px-3 py-2.5">
            <SeverityBadge severity="Critical" />
            <div className="text-[13px] font-semibold text-ink">
              INC-0417 risk 86 → 95 (Critical)
            </div>
            <p className="text-[12px] text-ink2">
              Retro-hunt RH-2026-09-30-B added a threat-intel match of +9 and created INC-0419.
            </p>
            <Link
              to="/incidents"
              onClick={() => setSelected("INC-0417")}
              className="ml-auto text-[12px] text-link hover:underline"
            >
              Open INC-0417
            </Link>
            <Link
              to="/incidents"
              onClick={() => setSelected("INC-0419")}
              className="text-[12px] text-link hover:underline"
            >
              Open INC-0419
            </Link>
          </div>
        </Panel>
      ) : null}

      <Panel>
        <Tabs
          tabs={[
            { id: "iocs", label: "IOCs", badge: IOCS.length },
            { id: "matches", label: "Matches", badge: matches.length },
            { id: "retro", label: "Retro-hunt history", badge: RETRO_HUNT_HISTORY.length + (retroHuntStatus === "complete" ? 1 : 0) },
          ]}
          active={tiTab}
          onChange={setTiTab}
        />

        {tiTab === "iocs" ? (
          <>
            <div className="flex flex-wrap items-center gap-3 border-b border-border px-3 py-2">
              <span className="relative">
                <Search size={12} strokeWidth={1.6} className="pointer-events-none absolute left-2 top-1/2 -translate-y-1/2 text-ink3" />
                <TextInput
                  value={query}
                  onChange={(v) => setQuery(v)}
                  placeholder="Search indicator"
                  className="w-[240px] pl-6"
                />
              </span>
              <Select
                label="Type"
                value={typeFilter}
                onChange={setTypeFilter}
                options={[
                  { value: "all", label: "All" },
                  { value: "IPv4", label: "IPv4" },
                  { value: "Domain", label: "Domain" },
                  { value: "JA4", label: "JA4" },
                  { value: "Cert hash", label: "Cert hash" },
                ]}
              />
              <Select
                label="Source"
                value={sourceFilter}
                onChange={setSourceFilter}
                options={[{ value: "all", label: "All" }, ...SOURCES.map((s) => ({ value: s, label: s }))]}
              />
              <Button
                onClick={() =>
                  downloadText(
                    "DiodeWatch-ioc-table.csv",
                    toCsv(
                      ["Indicator", "Type", "Source", "First seen", "Last seen", "Base confidence", "Effective confidence", "Matches"],
                      filteredIocs.map((i) => [
                        i.indicator,
                        i.type,
                        i.source,
                        i.firstSeen,
                        i.lastSeen,
                        i.baseConfidence,
                        i.effectiveConfidence,
                        i.matches,
                      ])
                    )
                  )
                }
              >
                <FileDown size={12} strokeWidth={1.6} /> Export CSV
              </Button>
              <span className="ml-auto text-[11px] text-ink2">
                {filteredIocs.length} of {IOCS.length} indicators shown
              </span>
            </div>
            <div className="max-h-[520px] overflow-auto">
              <Table head={["Indicator", "Type", "Source", "First seen", "Last seen", "Base conf.", "Effective conf.", "Matches"]}>
                {filteredIocs.map((i) => (
                  <tr key={i.indicator} className="hover:bg-[#f7f8fa]">
                    <Td mono className="break-all">
                      {i.indicator}
                    </Td>
                    <Td>{i.type}</Td>
                    <Td>{i.source}</Td>
                    <Td mono>{i.firstSeen}</Td>
                    <Td mono>{i.lastSeen}</Td>
                    <Td mono className="tabular-nums">
                      {i.baseConfidence.toFixed(2)}
                    </Td>
                    <Td mono className="tabular-nums">
                      <span className={i.effectiveConfidence < i.baseConfidence ? "text-[#B7791F]" : ""}>
                        {i.effectiveConfidence.toFixed(2)}
                      </span>
                    </Td>
                    <Td mono className="tabular-nums">
                      {i.matches}
                    </Td>
                  </tr>
                ))}
              </Table>
            </div>
          </>
        ) : null}

        {tiTab === "matches" ? (
          <div className="max-h-[560px] overflow-auto">
            <Table head={["Incident", "Entity", "Indicator", "Type", "Source", "First seen", "Confidence", "Origin", "Context"]}>
              {matches.map((m, idx) => (
                <tr key={idx} className="hover:bg-[#f7f8fa]">
                  <Td mono>
                    <Link to="/incidents" onClick={() => setSelected(m.incident)} className="text-link hover:underline">
                      {m.incident}
                    </Link>
                  </Td>
                  <Td mono>
                    {m.entity} {m.hostname ? `(${m.hostname})` : ""}
                  </Td>
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
                  <Td className="max-w-[300px] whitespace-normal text-[11.5px] text-ink2">{m.context}</Td>
                </tr>
              ))}
            </Table>
          </div>
        ) : null}

        {tiTab === "retro" ? (
          <div className="space-y-3 p-3">
            {retroHuntStatus === "complete" ? (
              <Panel className="border-[#3E6B57]">
                <PanelHeader
                  title={`${RETRO_HUNT.id} — completed`}
                  subtitle="Bundle DW-TI-2026-09-30-B · 14-day window · stored metadata only"
                  icon={<History size={13} strokeWidth={1.6} />}
                  right={<StatusPill status="Verified" />}
                />
                <div className="grid grid-cols-4 divide-x divide-border">
                  {[
                    ["Flows scanned", "48.2M"],
                    ["DNS queries scanned", "2.1M"],
                    ["TLS sessions scanned", "310K"],
                    ["Total matches", "18"],
                  ].map(([k, v]) => (
                    <div key={k} className="px-3 py-2">
                      <div className="text-[11px] uppercase tracking-wide text-ink2">{k}</div>
                      <div className="mt-[2px] font-mono text-[15px] font-semibold tabular-nums text-ink">{v}</div>
                    </div>
                  ))}
                </div>
              </Panel>
            ) : null}

            <Table head={["Job", "Bundle", "Window", "Matches", "New incidents", "Completed", "Outcome"]}>
              {retroHuntStatus === "complete"
                ? [
                    {
                      id: RETRO_HUNT.id,
                      bundle: "DW-TI-2026-09-30-B",
                      windowDays: 14,
                      hits: 18,
                      newIncidents: 1,
                      completed: "2026-09-30 12:02 UTC",
                      outcome:
                        "INC-0417 risk 86 → 95. New lead INC-0419 (10.2.9.44 contacted 203.0.113.47 on 2026-09-28).",
                    },
                    ...RETRO_HUNT_HISTORY,
                  ].map((r) => (
                    <tr key={r.id} className="hover:bg-[#f7f8fa]">
                      <Td mono>{r.id}</Td>
                      <Td mono>{r.bundle}</Td>
                      <Td mono>{r.windowDays} d</Td>
                      <Td mono className="tabular-nums">
                        {r.hits}
                      </Td>
                      <Td mono className="tabular-nums">
                        {r.newIncidents}
                      </Td>
                      <Td mono>{r.completed}</Td>
                      <Td className="max-w-[340px] whitespace-normal text-[11.5px] text-ink2">{r.outcome}</Td>
                    </tr>
                  ))
                : RETRO_HUNT_HISTORY.map((r) => (
                    <tr key={r.id} className="hover:bg-[#f7f8fa]">
                      <Td mono>{r.id}</Td>
                      <Td mono>{r.bundle}</Td>
                      <Td mono>{r.windowDays} d</Td>
                      <Td mono className="tabular-nums">
                        {r.hits}
                      </Td>
                      <Td mono className="tabular-nums">
                        {r.newIncidents}
                      </Td>
                      <Td mono>{r.completed}</Td>
                      <Td className="max-w-[340px] whitespace-normal text-[11.5px] text-ink2">{r.outcome}</Td>
                    </tr>
                  ))}
            </Table>
          </div>
        ) : null}
      </Panel>

      {/* Retro-hunt results */}
      {retroHuntStatus !== "idle" ? (
        <Panel data-demo-id="retro-results">
          <PanelHeader
            title="Retro-hunt RH-2026-09-30-B"
            subtitle="Scan of stored metadata over 14 days"
            icon={<Waypoints size={13} strokeWidth={1.6} />}
            right={<ProgressBar value={retroHuntProgress} className="w-[140px]" />}
          />
          <div className="space-y-3 px-3 py-2.5">
            <div className="font-mono text-[11.5px] text-ink2">{retroHuntScanLine}</div>

            {retroHuntStatus === "complete" ? (
              <>
                <Table head={["Indicator", "Type", "Scope", "Hits", "First contact", "Entity", "Note"]}>
                  {RETRO_HUNT.results.map((r) => (
                    <tr key={r.indicator} className="hover:bg-[#f7f8fa]">
                      <Td mono className="break-all">
                        {r.indicator}
                      </Td>
                      <Td>{r.type}</Td>
                      <Td>{r.scope}</Td>
                      <Td mono className="tabular-nums">
                        {r.hits}
                      </Td>
                      <Td mono>{r.firstContact}</Td>
                      <Td mono>{r.entity}</Td>
                      <Td className="max-w-[320px] whitespace-normal text-[11.5px] text-ink2">{r.note}</Td>
                    </tr>
                  ))}
                </Table>

                <div className="grid grid-cols-2 gap-3">
                  <div className="rounded border border-border p-2">
                    <div className="mb-1.5 text-[11px] font-semibold uppercase tracking-wide text-ink2">
                      Historical contacts before incident start
                    </div>
                    <ul className="space-y-1.5">
                      {[
                        { ts: "2026-09-27 21:11", text: "10.2.3.15 resolves qx4v8mzt2kd7p1.com (retro-hunt domain match)" },
                        { ts: "2026-09-27 21:14", text: "10.2.3.15 first flow to 203.0.113.47:443 — 2.5 days before behavioural detection" },
                        { ts: "2026-09-28 14:22", text: "10.2.9.44 single flow to 203.0.113.47:443, 34 s, 1.2 KB outbound" },
                        { ts: "2026-09-30 08:47", text: "INC-0417 opens: horizontal scan on 445/tcp from 10.2.3.15" },
                        { ts: "2026-09-30 09:31", text: "C2 beaconing detected behaviourally, risk 71" },
                        { ts: "2026-09-30 12:02", text: "Retro-hunt completes. INC-0417 risk 86 → 95. INC-0419 created." },
                      ].map((e) => (
                        <li key={e.ts} className="flex gap-2 text-[11.5px]">
                          <span className="w-[112px] shrink-0 font-mono text-ink2">{e.ts}</span>
                          <span className="text-ink">{e.text}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                  <div className="rounded border border-[#B7791F] bg-[#fdf8ee] p-2">
                    <div className="text-[11px] font-semibold uppercase tracking-wide text-ink2">
                      New lead
                    </div>
                    <div className="mt-1 flex items-center gap-2">
                      <span className="font-mono text-[12.5px] font-semibold text-ink">
                        {RETRO_HUNT.newLead.incident}
                      </span>
                      <CategoryTag category="C2 Beaconing" />
                    </div>
                    <p className="mt-1 text-[12px] leading-relaxed text-ink">{RETRO_HUNT.newLead.detail}</p>
                    <div className="mt-2 flex items-center gap-2">
                      <Link to="/incidents" onClick={() => setSelected("INC-0419")}>
                        <Button variant="default">Open {RETRO_HUNT.newLead.incident}</Button>
                      </Link>
                      <span className="text-[11px] text-ink2">
                        Entity {RETRO_HUNT.newLead.entity} ({RETRO_HUNT.newLead.hostname})
                      </span>
                    </div>
                  </div>
                </div>
              </>
            ) : null}
          </div>
        </Panel>
      ) : null}

      {/* Import modal */}
      <Modal
        open={importOpen}
        onClose={() => setImportOpen(false)}
        title="Import threat-intel bundle"
        subtitle="Signed bundles arrive over the one-way inbound path only"
        width="620px"
        footer={
          <>
            <span className="mr-auto text-[11px] text-ink2">
              {bundleImported
                ? "Bundle imported. Retro-hunt complete."
                : retroHuntStatus === "importing"
                ? "Verifying…"
                : "Verification runs locally against the bundled trust anchor."}
            </span>
            <Button variant="default" onClick={() => setImportOpen(false)}>
              Close
            </Button>
            {!bundleImported && retroHuntStatus === "idle" ? (
              <Button variant="primary" onClick={() => void importBundle()}>
                <ShieldCheck size={13} strokeWidth={1.6} /> Verify and import
              </Button>
            ) : null}
            {bundleImported && retroHuntStatus === "importing" ? (
              <Button variant="primary" onClick={() => void runRetroHunt()}>
                Run retro-hunt
              </Button>
            ) : null}
            {retroHuntStatus === "scanning" ? (
              <span className="inline-flex items-center gap-2 text-[11.5px] text-ink2">
                <ProgressBar value={retroHuntProgress} className="w-[120px]" />
                Scanning stored metadata…
              </span>
            ) : null}
            {retroHuntStatus === "complete" ? (
              <Button variant="primary" onClick={() => setImportOpen(false)}>
                View results
              </Button>
            ) : null}
          </>
        }
      >
        <div className="space-y-3">
          <div className="rounded border border-border">
            <div className="border-b border-border bg-[#f7f8fa] px-2.5 py-1.5 text-[11px] font-semibold uppercase tracking-wide text-ink2">
              Available bundle files
            </div>
            <label className="flex cursor-pointer items-center gap-2 px-2.5 py-2">
              <input type="radio" name="bundle" defaultChecked className="accent-[#1F3A5F]" />
              <span className="font-mono text-[12px] text-ink">DW-TI-2026-09-30-B.dwbundle</span>
              <span className="text-[11px] text-ink2">4.1 MB · detached signature · 2026-09-30</span>
            </label>
          </div>

          {retroHuntStatus !== "idle" ? (
            <div className="rounded border border-border">
              <div className="border-b border-border bg-[#f7f8fa] px-2.5 py-1.5 text-[11px] font-semibold uppercase tracking-wide text-ink2">
                Verification and import
              </div>
              <ul className="divide-y divide-border">
                {[
                  "Signature verified against local trust anchor",
                  "Schema valid (bundle manifest v3)",
                  `Diff computed: +${BUNDLE_DIFF.added.toLocaleString("en-US")} added / ~${BUNDLE_DIFF.updated} updated / -${BUNDLE_DIFF.expired} expired`,
                  "Bundle staged in the local indicator store",
                ].map((s, i) => {
                  const done = retroHuntProgress > (i + 1) * 25 - 1 || bundleImported;
                  return (
                    <li key={s} className="flex items-center gap-2 px-2.5 py-1.5 text-[12px]">
                      <span
                        className={`inline-block h-1.5 w-1.5 rounded-full ${
                          done ? "bg-[#3E6B57]" : "bg-[#D8DDE4]"
                        }`}
                      />
                      <span className={done ? "text-ink" : "text-ink3"}>{s}</span>
                    </li>
                  );
                })}
              </ul>
              <div className="px-2.5 pb-2">
                <ProgressBar value={retroHuntProgress} />
              </div>
            </div>
          ) : null}

          {retroHuntStatus === "scanning" || retroHuntStatus === "complete" ? (
            <div className="rounded border border-border px-2.5 py-2">
              <div className="mb-1.5 text-[11px] font-semibold uppercase tracking-wide text-ink2">
                Retro-hunt RH-2026-09-30-B
              </div>
              <div className="font-mono text-[11.5px] text-ink2">{retroHuntScanLine}</div>
              <ProgressBar className="mt-2" value={retroHuntProgress} />
              {retroHuntStatus === "complete" ? (
                <div className="mt-2 text-[11.5px] leading-relaxed text-ink2">
                  18 matches across flows, DNS and TLS metadata. INC-0417 risk raised to 95 (Critical);
                  one new lead, INC-0419.
                </div>
              ) : null}
            </div>
          ) : null}

          {bundleImported ? (
            <div className="rounded border border-border bg-[#f7f8fa] px-2.5 py-2 text-[11.5px] leading-relaxed text-ink2">
              Import complete. Running the retro-hunt scans stored metadata only — 48.2M flows, 2.1M
              DNS queries and 310K TLS sessions over 14 days. No traffic is generated and no lookup
              leaves the enclave.
            </div>
          ) : null}
        </div>
      </Modal>
    </div>
  );
}

export function BundleChip() {
  return (
    <Chip>
      <FileDown size={11} strokeWidth={1.6} /> {TI_BUNDLES[0].version}
    </Chip>
  );
}

export function formatStamp(iso: string) {
  return fmtUtc(iso);
}
