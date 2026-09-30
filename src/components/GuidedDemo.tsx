import React from "react";
import { useNavigate } from "react-router-dom";
import { ChevronLeft, ChevronRight, X } from "lucide-react";
import { DEMO_STEPS } from "../data/demoSteps";
import { useDemo } from "../store/store";
import { Button, ProgressBar } from "./ui";

export function GuidedDemo() {
  const navigate = useNavigate();
  const open = useDemo((s) => s.guidedOpen);
  const step = useDemo((s) => s.demoStep);
  const setStep = useDemo((s) => s.setDemoStep);
  const setOpen = useDemo((s) => s.setGuidedOpen);
  const setHighlight = useDemo((s) => s.setHighlight);
  const setSelected = useDemo((s) => s.setSelected);
  const setVisibility = useDemo((s) => s.setVisibility);
  const setReportIncident = useDemo((s) => s.setReportIncident);
  const importBundle = useDemo((s) => s.importBundle);
  const runRetroHunt = useDemo((s) => s.runRetroHunt);
  const generateArtifact = useDemo((s) => s.generateArtifact);
  const verifyChain = useDemo((s) => s.verifyChain);
  const simulateTamper = useDemo((s) => s.simulateTamper);
  const retroHuntStatus = useDemo((s) => s.retroHuntStatus);
  const artifacts = useDemo((s) => s.artifacts);

  const current = DEMO_STEPS[Math.min(step, DEMO_STEPS.length - 1)];

  const runAction = React.useCallback(
    (action?: string) => {
      switch (action) {
        case "select-0417":
          setSelected("INC-0417");
          break;
        case "select-0418":
          setSelected("INC-0418");
          break;
        case "visibility-one":
          setVisibility("one");
          break;
        case "import-retrohunt":
          if (retroHuntStatus === "idle") {
            void importBundle().then(() => runRetroHunt());
          }
          break;
        case "mitigation":
          if (!artifacts.some((a) => a.incidentId === "INC-0417" && a.type === "IOC block list")) {
            void generateArtifact("INC-0417", "IOC block list");
          }
          break;
        case "report-verify":
          setReportIncident("INC-0417");
          void verifyChain();
          break;
        case "tamper":
          simulateTamper();
          setTimeout(() => void verifyChain(), 260);
          break;
        default:
          break;
      }
    },
    [
      artifacts,
      generateArtifact,
      importBundle,
      retroHuntStatus,
      runRetroHunt,
      setReportIncident,
      setSelected,
      setVisibility,
      simulateTamper,
      verifyChain,
    ]
  );

  React.useEffect(() => {
    if (!open) {
      setHighlight(null);
      return;
    }
    navigate(current.path);
    runAction(current.action);
    const t = setTimeout(() => {
      const el = document.querySelector(`[data-demo-id="${current.target}"]`);
      if (el) {
        el.classList.add("dw-highlight");
        el.scrollIntoView({ behavior: "smooth", block: "center" });
      }
      setHighlight(current.target);
    }, 260);
    return () => {
      clearTimeout(t);
      document.querySelectorAll(".dw-highlight").forEach((e) => e.classList.remove("dw-highlight"));
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, step]);

  if (!open) return null;

  return (
    <aside className="dw-no-print fixed inset-y-0 right-0 z-40 flex w-[318px] flex-col border-l border-border bg-panel">
      <div className="flex h-[46px] items-center justify-between border-b border-border px-3">
        <div className="text-[12.5px] font-semibold text-ink">Guided demo</div>
        <button
          onClick={() => setOpen(false)}
          className="rounded p-1 text-ink2 hover:bg-[#f2f4f7] hover:text-ink"
          aria-label="Close guided demo"
        >
          <X size={14} strokeWidth={1.6} />
        </button>
      </div>
      <div className="border-b border-border px-3 py-2">
        <div className="flex items-center justify-between text-[11px] text-ink2">
          <span>
            Step {current.n} of {DEMO_STEPS.length}
          </span>
          <span className="tabular-nums">{Math.round((current.n / DEMO_STEPS.length) * 100)}%</span>
        </div>
        <ProgressBar className="mt-1.5" value={(current.n / DEMO_STEPS.length) * 100} />
      </div>
      <div className="border-b border-border px-3 py-3">
        <div className="text-[13px] font-semibold leading-snug text-ink">{current.title}</div>
        <p className="mt-1.5 text-[12px] leading-relaxed text-ink2">{current.instruction}</p>
      </div>
      <div className="flex-1 overflow-auto px-3 py-2">
        <div className="text-[11px] font-semibold uppercase tracking-wide text-ink3">
          Sequence
        </div>
        <ol className="mt-1.5 space-y-[2px]">
          {DEMO_STEPS.map((s) => (
            <li key={s.n}>
              <button
                onClick={() => setStep(s.n - 1)}
                className={`flex w-full items-start gap-2 rounded-[3px] px-2 py-[5px] text-left text-[11.5px] ${
                  s.n === current.n
                    ? "bg-navy-soft font-semibold text-navy"
                    : "text-ink2 hover:bg-[#f2f4f7]"
                }`}
              >
                <span className="w-[14px] shrink-0 tabular-nums">{s.n}</span>
                <span className="leading-snug">{s.title}</span>
              </button>
            </li>
          ))}
        </ol>
      </div>
      <div className="flex items-center justify-between border-t border-border px-3 py-2">
        <Button
          onClick={() => setStep(Math.max(0, step - 1))}
          disabled={step === 0}
          variant="default"
        >
          <ChevronLeft size={13} strokeWidth={1.6} /> Back
        </Button>
        <Button
          onClick={() => {
            if (step < DEMO_STEPS.length - 1) setStep(step + 1);
            else setOpen(false);
          }}
          variant="primary"
        >
          {step < DEMO_STEPS.length - 1 ? "Next" : "Finish"}{" "}
          <ChevronRight size={13} strokeWidth={1.6} />
        </Button>
      </div>
    </aside>
  );
}
