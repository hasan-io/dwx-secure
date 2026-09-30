import { Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { AXIS, ChartTooltip } from "./charts";
import { mulberry32 } from "../lib/utils";

export type ChartKind = "iat" | "entropy" | "packet" | "volume";

export function featureChartData(kind: ChartKind, seed: number) {
  const r = mulberry32(seed);
  if (kind === "iat") {
    const out: { bucket: string; count: number; flagged?: boolean }[] = [];
    for (let i = 0; i < 14; i++) {
      const centre = 6;
      const dist = Math.abs(i - centre);
      const count = Math.max(0, Math.round(14 * Math.exp(-(dist * dist) / 2.2)) + (r() > 0.7 ? 1 : 0));
      out.push({ bucket: `${(30 + i * 6).toFixed(0)}s`, count, flagged: dist <= 1 });
    }
    return out;
  }
  if (kind === "entropy") {
    const out: { bucket: string; count: number; flagged?: boolean }[] = [];
    for (let i = 0; i < 12; i++) {
      const centre = 8.4;
      const dist = Math.abs(i - centre);
      const count = Math.max(0, Math.round(11 * Math.exp(-(dist * dist) / 3.4)));
      out.push({ bucket: (2.0 + i * 0.2).toFixed(1), count, flagged: i >= 8 });
    }
    return out;
  }
  if (kind === "packet") {
    const out: { bucket: string; count: number; flagged?: boolean }[] = [];
    for (let i = 0; i < 12; i++) {
      const count = Math.max(1, Math.round(9 - i * 0.6 + r() * 2));
      out.push({ bucket: `${40 + i * 20}B`, count, flagged: i < 3 });
    }
    return out;
  }
  const out: { bucket: string; count: number; flagged?: boolean }[] = [];
  for (let i = 0; i < 16; i++) {
    const ramp = i < 6 ? 1 + i * 0.4 : 3.4 + Math.exp((i - 6) / 2.4) * 6;
    out.push({ bucket: `${String(11 + Math.floor(i / 2)).padStart(2, "0")}:${String((i % 2) * 30).padStart(2, "0")}`, count: Math.round(ramp * 10) / 10, flagged: i >= 12 });
  }
  return out;
}

const KIND_LABEL: Record<ChartKind, string> = {
  iat: "Inter-arrival time distribution (beacon interval)",
  entropy: "Domain label entropy distribution",
  packet: "Packet size distribution",
  volume: "Outbound volume per 30 s (MB)",
};

export function FeatureChart({ kind, seed }: { kind: ChartKind; seed: number }) {
  const data = featureChartData(kind, seed);
  return (
    <div className="rounded border border-border bg-white px-2 py-1.5">
      <div className="mb-1 flex items-center justify-between">
        <span className="text-[11px] font-medium text-ink2">{KIND_LABEL[kind]}</span>
        <span className="inline-flex items-center gap-1.5 text-[10.5px] text-ink2">
          <span className="inline-block h-2 w-2 rounded-full bg-[#2F5D9E]" /> above threshold
          <span className="ml-1 inline-block h-2 w-2 rounded-full bg-[#C3CAD3]" /> baseline
        </span>
      </div>
      <div style={{ height: 92 }}>
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={data} margin={{ left: 0, right: 4, top: 2 }}>
            <CartesianGrid stroke="#E6E9EE" vertical={false} />
            <XAxis dataKey="bucket" {...AXIS} interval={2} />
            <YAxis {...AXIS} width={24} allowDecimals={false} />
            <Tooltip content={<ChartTooltip />} cursor={{ fill: "#F1F3F6" }} />
            <Bar dataKey="count" name="Observations" barSize={9}>
              {data.map((d, i) => (
                <Cell key={i} fill={d.flagged ? "#2F5D9E" : "#C3CAD3"} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
