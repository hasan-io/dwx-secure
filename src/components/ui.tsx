import React from "react";
import { cn } from "../lib/utils";
import { SEVERITY_COLOR, CATEGORY_COLOR } from "../lib/utils";

/* ---------------------------------- Panel --------------------------------- */

export function Panel({
  children,
  className,
  ...rest
}: React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div className={cn("rounded border border-border bg-panel", className)} {...rest}>
      {children}
    </div>
  );
}

export function PanelHeader({
  title,
  subtitle,
  right,
  icon,
  className,
}: {
  title: React.ReactNode;
  subtitle?: React.ReactNode;
  right?: React.ReactNode;
  icon?: React.ReactNode;
  className?: string;
}) {
  return (
    <div
      className={cn(
        "flex items-start justify-between gap-3 border-b border-border px-3 py-2",
        className
      )}
    >
      <div className="flex items-start gap-2">
        {icon ? <span className="mt-[2px] text-ink2">{icon}</span> : null}
        <div>
          <div className="text-[13px] font-semibold leading-tight text-ink">{title}</div>
          {subtitle ? <div className="mt-[2px] text-[11px] text-ink2">{subtitle}</div> : null}
        </div>
      </div>
      {right ? <div className="flex shrink-0 items-center gap-2">{right}</div> : null}
    </div>
  );
}

/* ---------------------------------- Button -------------------------------- */

type ButtonProps = React.ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: "primary" | "default" | "ghost" | "danger";
  size?: "sm" | "md";
};

export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  { variant = "default", size = "sm", className, ...rest },
  ref
) {
  return (
    <button
      ref={ref}
      className={cn(
        "inline-flex items-center justify-center gap-1.5 rounded border font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-45",
        size === "sm" ? "h-[26px] px-2.5 text-[12px]" : "h-[30px] px-3 text-[12px]",
        variant === "primary" &&
          "border-navy bg-navy text-white hover:bg-[#25466f]",
        variant === "default" &&
          "border-border-strong bg-white text-ink hover:border-navy hover:text-navy",
        variant === "ghost" && "border-transparent bg-transparent text-ink2 hover:bg-[#eceff3]",
        variant === "danger" && "border-[#A32020] bg-white text-[#A32020] hover:bg-[#f7ecec]",
        className
      )}
      {...rest}
    />
  );
});

/* ---------------------------------- Badges -------------------------------- */

export function SeverityBadge({
  severity,
  className,
}: {
  severity: string;
  className?: string;
}) {
  const c = SEVERITY_COLOR[severity] ?? "#5B6773";
  return (
    <span
      className={cn(
        "inline-flex h-[18px] items-center rounded-[3px] px-1.5 text-[11px] font-semibold text-white",
        className
      )}
      style={{ backgroundColor: c }}
    >
      {severity}
    </span>
  );
}

export function Chip({
  children,
  className,
  style,
  title,
}: {
  children: React.ReactNode;
  className?: string;
  style?: React.CSSProperties;
  title?: string;
}) {
  return (
    <span
      title={title}
      style={style}
      className={cn(
        "inline-flex items-center gap-1 rounded-[3px] border border-border bg-[#f7f8fa] px-1.5 py-[1px] text-[11px] text-ink2",
        className
      )}
    >
      {children}
    </span>
  );
}

export function CategoryDot({ category, className }: { category: string; className?: string }) {
  return (
    <span
      title={category}
      className={cn("inline-block h-2 w-2 shrink-0 rounded-full", className)}
      style={{ backgroundColor: CATEGORY_COLOR[category] ?? "#5B6773" }}
    />
  );
}

export function CategoryTag({ category }: { category: string }) {
  const c = CATEGORY_COLOR[category] ?? "#5B6773";
  return (
    <span className="inline-flex items-center gap-1.5 text-[12px] text-ink">
      <span className="inline-block h-2 w-2 rounded-full" style={{ backgroundColor: c }} />
      {category}
    </span>
  );
}

export function StatusPill({ status }: { status: string }) {
  const map: Record<string, string> = {
    Open: "border-[#B7791F] text-[#B7791F]",
    Investigating: "border-[#2F5D9E] text-[#2F5D9E]",
    Resolved: "border-[#3E6B57] text-[#3E6B57]",
    Proposed: "border-[#5B6773] text-[#5B6773]",
    Approved: "border-[#2F5D9E] text-[#2F5D9E]",
    Exported: "border-[#3E6B57] text-[#3E6B57]",
    Verified: "border-[#3E6B57] text-[#3E6B57]",
    Broken: "border-[#A32020] text-[#A32020]",
    Pending: "border-[#B7791F] text-[#B7791F]",
    Unverified: "border-[#A32020] text-[#A32020]",
  };
  return (
    <span
      className={cn(
        "inline-flex h-[18px] items-center rounded-[3px] border bg-white px-1.5 text-[11px] font-medium",
        map[status] ?? "border-border text-ink2"
      )}
    >
      {status}
    </span>
  );
}

/* ----------------------------------- Table -------------------------------- */

export function Table({
  head,
  children,
  className,
  dense = true,
}: {
  head: React.ReactNode[];
  children: React.ReactNode;
  className?: string;
  dense?: boolean;
}) {
  return (
    <table className={cn("w-full border-collapse text-[12px]", className)}>
      <thead>
        <tr className="border-b border-border">
          {head.map((h, i) => (
            <th
              key={i}
              className={cn(
                "bg-[#f7f8fa] px-2 py-[6px] text-left font-semibold text-ink2",
                dense ? "text-[11px]" : "text-[12px]"
              )}
            >
              {h}
            </th>
          ))}
        </tr>
      </thead>
      <tbody>{children}</tbody>
    </table>
  );
}

export function Td({
  children,
  className,
  mono,
  colSpan,
}: {
  children?: React.ReactNode;
  className?: string;
  mono?: boolean;
  colSpan?: number;
}) {
  return (
    <td
      colSpan={colSpan}
      className={cn(
        "border-b border-border px-2 py-[5px] align-top text-ink",
        mono && "font-mono text-[11.5px] tabular-nums",
        className
      )}
    >
      {children}
    </td>
  );
}

/* ----------------------------------- Modal -------------------------------- */

export function Modal({
  open,
  onClose,
  title,
  subtitle,
  children,
  footer,
  width = "560px",
}: {
  open: boolean;
  onClose: () => void;
  title: React.ReactNode;
  subtitle?: React.ReactNode;
  children: React.ReactNode;
  footer?: React.ReactNode;
  width?: string;
}) {
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center bg-[#1f2933]/25 p-8 dw-no-print">
      <div
        className="dw-fade-in w-full rounded border border-border bg-panel shadow-[0_8px_24px_rgba(31,41,51,0.12)]"
        style={{ maxWidth: width }}
      >
        <div className="flex items-start justify-between border-b border-border px-4 py-3">
          <div>
            <div className="text-[13px] font-semibold text-ink">{title}</div>
            {subtitle ? <div className="mt-[2px] text-[11px] text-ink2">{subtitle}</div> : null}
          </div>
          <Button variant="ghost" onClick={onClose} aria-label="Close">
            Close
          </Button>
        </div>
        <div className="px-4 py-3">{children}</div>
        {footer ? (
          <div className="flex items-center justify-end gap-2 border-t border-border px-4 py-3">
            {footer}
          </div>
        ) : null}
      </div>
    </div>
  );
}

export function Drawer({
  open,
  onClose,
  title,
  subtitle,
  children,
  footer,
}: {
  open: boolean;
  onClose: () => void;
  title: React.ReactNode;
  subtitle?: React.ReactNode;
  children: React.ReactNode;
  footer?: React.ReactNode;
}) {
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-40 flex justify-end bg-[#1f2933]/20 dw-no-print">
      <div className="dw-fade-in flex h-full w-[560px] flex-col border-l border-border bg-panel shadow-[0_8px_24px_rgba(31,41,51,0.12)]">
        <div className="flex items-start justify-between border-b border-border px-4 py-3">
          <div>
            <div className="text-[13px] font-semibold text-ink">{title}</div>
            {subtitle ? <div className="mt-[2px] text-[11px] text-ink2">{subtitle}</div> : null}
          </div>
          <Button variant="ghost" onClick={onClose}>
            Close
          </Button>
        </div>
        <div className="flex-1 overflow-auto px-4 py-3">{children}</div>
        {footer ? (
          <div className="flex items-center justify-between gap-2 border-t border-border px-4 py-3">
            {footer}
          </div>
        ) : null}
      </div>
    </div>
  );
}

/* ---------------------------------- Inputs -------------------------------- */

export function Select({
  value,
  onChange,
  options,
  className,
  label,
}: {
  value: string;
  onChange: (v: string) => void;
  options: { value: string; label: string }[];
  className?: string;
  label?: string;
}) {
  return (
    <label className={cn("inline-flex items-center gap-1.5 text-[11px] text-ink2", className)}>
      {label}
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="h-[26px] rounded border border-border-strong bg-white px-1.5 text-[12px] text-ink focus:border-navy focus:outline-none"
      >
        {options.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </select>
    </label>
  );
}

export function TextInput({
  value,
  onChange,
  placeholder,
  className,
  ...rest
}: Omit<React.InputHTMLAttributes<HTMLInputElement>, "onChange"> & {
  value: string;
  onChange: (v: string) => void;
}) {
  return (
    <input
      value={value}
      onChange={(e) => onChange(e.target.value)}
      placeholder={placeholder}
      className={cn(
        "h-[26px] w-full rounded border border-border-strong bg-white px-2 font-mono text-[12px] text-ink placeholder:text-ink3 focus:border-navy focus:outline-none",
        className
      )}
      {...rest}
    />
  );
}

/* ---------------------------------- Tabs ---------------------------------- */

export function Tabs({
  tabs,
  active,
  onChange,
  className,
}: {
  tabs: { id: string; label: string; badge?: number }[];
  active: string;
  onChange: (id: string) => void;
  className?: string;
}) {
  return (
    <div className={cn("flex items-center gap-0 border-b border-border", className)}>
      {tabs.map((t) => (
        <button
          key={t.id}
          onClick={() => onChange(t.id)}
          className={cn(
            "-mb-px border-b-2 px-3 py-[7px] text-[12px] font-medium transition-colors",
            active === t.id
              ? "border-navy text-navy"
              : "border-transparent text-ink2 hover:text-ink"
          )}
        >
          {t.label}
          {t.badge !== undefined ? (
            <span className="ml-1.5 rounded-[3px] bg-[#eceff3] px-1 text-[10px] text-ink2">
              {t.badge}
            </span>
          ) : null}
        </button>
      ))}
    </div>
  );
}

/* --------------------------------- Progress ------------------------------- */

export function ProgressBar({
  value,
  className,
  color = "#1F3A5F",
}: {
  value: number;
  className?: string;
  color?: string;
}) {
  return (
    <div className={cn("h-[4px] w-full overflow-hidden rounded-[2px] bg-[#e6e9ee]", className)}>
      <div className="h-full transition-all" style={{ width: `${value}%`, backgroundColor: color }} />
    </div>
  );
}

/* ---------------------------------- Stats --------------------------------- */

export function Stat({
  label,
  value,
  sub,
  accent,
  className,
}: {
  label: string;
  value: React.ReactNode;
  sub?: React.ReactNode;
  accent?: string;
  className?: string;
}) {
  return (
    <div className={cn("px-3 py-2", className)}>
      <div className="text-[11px] uppercase tracking-wide text-ink2">{label}</div>
      <div
        className="mt-[3px] text-[20px] font-semibold leading-none tabular-nums"
        style={{ color: accent ?? "#1F2933" }}
      >
        {value}
      </div>
      {sub ? <div className="mt-1 text-[11px] text-ink2">{sub}</div> : null}
    </div>
  );
}

export function KeyValue({
  rows,
  className,
}: {
  rows: { k: string; v: React.ReactNode }[];
  className?: string;
}) {
  return (
    <dl className={cn("grid grid-cols-[minmax(120px,auto)_1fr] gap-x-4 gap-y-[3px]", className)}>
      {rows.map((r) => (
        <div key={r.k} className="col-span-2 grid grid-cols-subgrid items-baseline">
          <dt className="text-[11px] text-ink2">{r.k}</dt>
          <dd className="text-[12px] text-ink">{r.v}</dd>
        </div>
      ))}
    </dl>
  );
}

export function Empty({ children }: { children: React.ReactNode }) {
  return (
    <div className="px-3 py-6 text-center text-[12px] text-ink2">{children}</div>
  );
}
