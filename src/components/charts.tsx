import React from "react";
import { cn } from "../lib/utils";

export const AXIS = {
  stroke: "#C3CAD3",
  tick: { fill: "#5B6773", fontSize: 10 },
  tickLine: false,
};

export function ChartTooltip({
  active,
  payload,
  label,
  unit,
  labelPrefix,
}: {
  active?: boolean;
  payload?: { name?: string; value?: number | string; color?: string; dataKey?: string }[];
  label?: string | number;
  unit?: string;
  labelPrefix?: string;
}) {
  if (!active || !payload || payload.length === 0) return null;
  return (
    <div className="rounded border border-border bg-panel px-2 py-1.5 text-[11px] shadow-[0_4px_12px_rgba(31,41,51,0.10)]">
      <div className="mb-0.5 font-mono text-ink2">
        {labelPrefix}
        {label}
      </div>
      {payload.map((p, i) => (
        <div key={i} className="flex items-center gap-1.5 text-ink">
          <span className="inline-block h-2 w-2 rounded-full" style={{ backgroundColor: p.color }} />
          <span className="text-ink2">{p.name}</span>
          <span className="ml-auto font-mono tabular-nums">
            {p.value}
            {unit}
          </span>
        </div>
      ))}
    </div>
  );
}

export function LegendRow({ items }: { items: { label: string; color: string }[] }) {
  return (
    <div className="flex flex-wrap items-center gap-x-3 gap-y-1 px-3 pb-2">
      {items.map((i) => (
        <span key={i.label} className="inline-flex items-center gap-1.5 text-[11px] text-ink2">
          <span className="inline-block h-2 w-2 rounded-full" style={{ backgroundColor: i.color }} />
          {i.label}
        </span>
      ))}
    </div>
  );
}

export function ChartFrame({
  height = 150,
  children,
  className,
}: {
  height?: number;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <div className={cn("px-2 pb-1", className)} style={{ height }}>
      {children}
    </div>
  );
}
