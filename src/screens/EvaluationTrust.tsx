import {
  Bar,
  BarChart,
  CartesianGrid,
  Legend,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { CheckCircle2, ShieldAlert, XCircle } from "lucide-react";
import { Panel, PanelHeader, Table, Td } from "../components/ui";
import { TrustBoundary } from "../components/TrustBoundary";
import { AXIS, ChartTooltip, LegendRow } from "../components/charts";
import { CLASS_METRICS, CONSTRAINTS, DIRECTION_COMPARISON, NOT_CLAIMED } from "../data/metrics";

export default function EvaluationTrust() {
  const chartData = DIRECTION_COMPARISON.map((d) => ({ class: d.class, "Both directions": d.bi, "One direction": d.uni }));

  return (
    <div className="space-y-3">
      <div className="flex items-end justify-between">
        <div>
          <h1 className="text-[17px] font-semibold leading-tight text-ink">Evaluation &amp; trust</h1>
          <p className="mt-[2px] text-[12px] text-ink2">
            Detection quality, the effect of one-direction visibility, and the boundary between
            observation and enforcement.
          </p>
        </div>
      </div>

      {/* Class metrics */}
      <Panel>
        <PanelHeader
          title="Detection quality by threat class"
          subtitle="Illustrative values; final figures come from the labelled scenario benchmark."
          icon={<ShieldAlert size={13} strokeWidth={1.6} />}
        />
        <Table head={["Threat class", "Precision", "Recall", "F1", "Median time-to-detect", "False positives / hour"]}>
          {CLASS_METRICS.map((m) => (
            <tr key={m.class} className="hover:bg-[#f7f8fa]">
              <Td>{m.class}</Td>
              <Td mono className="tabular-nums">
                {m.precision.toFixed(2)}
              </Td>
              <Td mono className="tabular-nums">
                {m.recall.toFixed(2)}
              </Td>
              <Td mono className="font-semibold tabular-nums">
                {m.f1.toFixed(2)}
              </Td>
              <Td mono>{m.mttd}</Td>
              <Td mono className="tabular-nums">
                {m.fpPerHour.toFixed(1)}
              </Td>
            </tr>
          ))}
        </Table>
        <div className="border-t border-border bg-[#f7f8fa] px-3 py-2 text-[11.5px] leading-relaxed text-ink2">
          Values are illustrative and derived from the seeded scenario set. Benign-traffic false
          positive rates are measured over a 7-day capture window with no injected threat.
        </div>
      </Panel>

      {/* Direction comparison */}
      <div className="grid grid-cols-2 gap-3">
        <Panel>
          <PanelHeader
            title="Bidirectional versus one-direction visibility"
            subtitle="F1 per threat class"
            icon={<ShieldAlert size={13} strokeWidth={1.6} />}
          />
          <div className="px-2 pt-3" style={{ height: 250 }}>
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={chartData} margin={{ left: 0, right: 8, top: 4 }} barGap={2}>
                <CartesianGrid stroke="#E6E9EE" vertical={false} />
                <XAxis dataKey="class" {...AXIS} interval={0} tick={{ fill: "#5B6773", fontSize: 9 }} />
                <YAxis domain={[0.6, 1]} {...AXIS} width={30} />
                <Tooltip content={<ChartTooltip />} cursor={{ fill: "#F1F3F6" }} />
                <Legend content={<LegendRow items={[{ label: "Both directions", color: "#1F3A5F" }, { label: "One direction", color: "#B7791F" }]} />} />
                <Bar dataKey="Both directions" fill="#1F3A5F" barSize={11} radius={[2, 2, 0, 0]} />
                <Bar dataKey="One direction" fill="#B7791F" barSize={11} radius={[2, 2, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Panel>

        <Panel>
          <PanelHeader title="Effect of losing one direction" subtitle="F1 delta and cause" />
          <Table head={["Threat class", "Both dir.", "One dir.", "Δ F1", "Why it degrades"]}>
            {DIRECTION_COMPARISON.map((d) => (
              <tr key={d.class} className="hover:bg-[#f7f8fa]">
                <Td>{d.class}</Td>
                <Td mono className="tabular-nums">
                  {d.bi.toFixed(2)}
                </Td>
                <Td mono className="tabular-nums">
                  {d.uni.toFixed(2)}
                </Td>
                <Td mono className="font-semibold tabular-nums text-[#B7791F]">
                  −{(d.bi - d.uni).toFixed(2)}
                </Td>
                <Td className="whitespace-normal text-[11.5px] text-ink2">{d.note}</Td>
              </tr>
            ))}
          </Table>
          <div className="border-t border-border px-3 py-2 text-[11.5px] leading-relaxed text-ink2">
            One-direction visibility costs the most where a detector compares both legs of a flow —
            upload:download ratio, SYN:ACK state and early-packet ordering.
          </div>
        </Panel>
      </div>

      {/* Trust boundary */}
      <Panel data-demo-id="trust-boundary">
        <PanelHeader
          title="Trust boundary"
          subtitle="One-way observation, advisory response, external enforcement"
          icon={<ShieldAlert size={13} strokeWidth={1.6} />}
        />
        <div className="px-3 py-3">
          <TrustBoundary />
        </div>
      </Panel>

      <div className="grid grid-cols-2 gap-3">
        {/* Constraints */}
        <Panel>
          <PanelHeader title="Constraints enforced by design" subtitle="Verified at every integrity check" />
          <ul className="divide-y divide-border">
            {CONSTRAINTS.map((c) => (
              <li key={c.label} className="flex items-start gap-2 px-3 py-2">
                <XCircle size={14} strokeWidth={1.6} className="mt-[2px] shrink-0 text-[#A32020]" />
                <div>
                  <div className="text-[12px] font-medium text-ink">{c.label} — not performed</div>
                  <div className="text-[11.5px] leading-snug text-ink2">{c.detail}</div>
                </div>
              </li>
            ))}
            <li className="flex items-start gap-2 px-3 py-2">
              <CheckCircle2 size={14} strokeWidth={1.6} className="mt-[2px] shrink-0 text-[#3E6B57]" />
              <div>
                <div className="text-[12px] font-medium text-ink">Observation, correlation, scoring, recommendation — performed</div>
                <div className="text-[11.5px] leading-snug text-ink2">
                  Feature analysis, detection, threat-intel matching, incident correlation, risk
                  scoring, response advice and forensic reporting.
                </div>
              </div>
            </li>
          </ul>
        </Panel>

        {/* Not claimed */}
        <Panel>
          <PanelHeader title="What DiodeWatch does not claim" subtitle="Stated explicitly for reviewers" />
          <ul className="divide-y divide-border">
            {NOT_CLAIMED.map((n) => (
              <li key={n} className="flex items-start gap-2 px-3 py-2 text-[12px] leading-snug text-ink">
                <span className="mt-[6px] inline-block h-1.5 w-1.5 shrink-0 rounded-full bg-[#A32020]" />
                {n}
              </li>
            ))}
          </ul>
          <div className="border-t border-border bg-[#f7f8fa] px-3 py-2 text-[11.5px] leading-relaxed text-ink2">
            Prototype build. Simulated telemetry, synthetic IOCs, illustrative benchmark values. No
            production traffic is observed by this demonstration.
          </div>
        </Panel>
      </div>
    </div>
  );
}
