import { Link } from "react-router-dom";
import {
  Binary,
  Database,
  FileText,
  GitMerge,
  Radio,
  ScanLine,
  Target,
  Waypoints,
} from "lucide-react";

const STAGES = [
  { label: "Passive traffic", value: "41,280 flows/min", to: "/live", icon: Radio },
  { label: "Feature analysis", value: "38 features", to: "/coverage", icon: Binary },
  { label: "Threat detection", value: "9 detectors", to: "/coverage", icon: ScanLine },
  { label: "Threat intelligence", value: "1.2M indicators", to: "/intel", icon: Database },
  { label: "Incident correlation", value: "6 incidents", to: "/incidents", icon: GitMerge },
  { label: "Risk scoring", value: "max 86", to: "/incidents", icon: Target },
  { label: "Response advice", value: "4 artifacts", to: "/response", icon: Waypoints },
  { label: "Forensic report", value: "chain verified", to: "/response", icon: FileText },
];

export function PipelineStrip() {
  return (
    <div className="rounded border border-border bg-panel">
      <div className="flex items-center gap-2 border-b border-border px-3 py-1.5">
        <span className="text-[11px] font-semibold uppercase tracking-wide text-ink2">
          Analysis pipeline
        </span>
        <span className="text-[11px] text-ink3">
          one direction of data flow, from the mirror to the report
        </span>
        <span className="ml-auto inline-flex items-center gap-1.5 rounded-[3px] border border-navy bg-navy-soft px-1.5 py-[1px] text-[10.5px] font-semibold text-navy">
          no path back to production
        </span>
      </div>
      <div className="flex items-stretch overflow-hidden">
        {STAGES.map((s, i) => (
          <Link
            key={s.label}
            to={s.to}
            className="group relative flex flex-1 items-center gap-2 px-3 py-2 transition-colors hover:bg-[#f5f7fa]"
          >
            {i > 0 ? (
              <span
                aria-hidden
                className="absolute left-0 top-1/2 h-[9px] w-[9px] -translate-x-1/2 -translate-y-1/2 rotate-45 border-r border-t border-border bg-panel group-hover:bg-[#f5f7fa]"
              />
            ) : null}
            <span className="flex h-[22px] w-[22px] shrink-0 items-center justify-center rounded-[3px] bg-navy-soft text-navy">
              <s.icon size={12} strokeWidth={1.7} />
            </span>
            <span className="min-w-0">
              <span className="block truncate text-[11px] font-medium leading-tight text-ink group-hover:text-navy">
                {s.label}
              </span>
              <span className="block truncate font-mono text-[10.5px] leading-tight text-ink2">
                {s.value}
              </span>
            </span>
          </Link>
        ))}
      </div>
    </div>
  );
}
