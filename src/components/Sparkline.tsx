/** Tiny inline sparkline. Flat stroke, no axes, no fill gradient. */
export function Sparkline({
  data,
  color = "#2F5D9E",
  width = 68,
  height = 22,
  area = true,
}: {
  data: number[];
  color?: string;
  width?: number;
  height?: number;
  area?: boolean;
}) {
  if (data.length < 2) return null;
  const min = Math.min(...data);
  const max = Math.max(...data);
  const span = max - min || 1;
  const pad = 2;
  const stepX = (width - pad * 2) / (data.length - 1);
  const pts = data.map((v, i) => {
    const x = pad + i * stepX;
    const y = pad + (1 - (v - min) / span) * (height - pad * 2);
    return [x, y] as const;
  });
  const line = pts.map(([x, y], i) => `${i === 0 ? "M" : "L"}${x.toFixed(1)} ${y.toFixed(1)}`).join(" ");
  const fill = `${line} L${pts[pts.length - 1][0].toFixed(1)} ${height} L${pts[0][0].toFixed(1)} ${height} Z`;
  const last = pts[pts.length - 1];
  return (
    <svg width={width} height={height} aria-hidden className="shrink-0">
      {area ? <path d={fill} fill={color} opacity={0.1} /> : null}
      <path d={line} fill="none" stroke={color} strokeWidth={1.2} strokeLinejoin="round" />
      <circle cx={last[0]} cy={last[1]} r={1.8} fill={color} />
    </svg>
  );
}

/** Horizontal proportion bar used inside dense tables. */
export function MiniBar({
  value,
  max = 100,
  color = "#2F5D9E",
  width = 56,
}: {
  value: number;
  max?: number;
  color?: string;
  width?: number;
}) {
  return (
    <span
      className="inline-block h-[6px] overflow-hidden rounded-[2px] bg-[#e9ecf1] align-middle"
      style={{ width }}
    >
      <span
        className="block h-full rounded-[2px]"
        style={{ width: `${Math.max(2, Math.min(100, (value / max) * 100))}%`, backgroundColor: color }}
      />
    </span>
  );
}
