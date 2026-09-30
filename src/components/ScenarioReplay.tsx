import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { ChevronLeft, ChevronRight, Pause, Play, RotateCcw, SkipForward } from "lucide-react";
import { Button, Chip, Panel, PanelHeader, ProgressBar } from "./ui";
import type { Direction, LiveFlowRow } from "../lib/types";
import { CATEGORY_COLOR, riskSeverity } from "../lib/utils";

type RowSpec = [string, number, string, number, string, number, number, Direction, string[]];

interface Stage {
  time: string;
  label: string;
  title: string;
  detail: string;
  risk: number;
  category: string;
  rows: RowSpec[];
}

interface Scenario {
  id: string;
  label: string;
  entity: string;
  outcome: string;
  stages: Stage[];
}

const SCENARIOS: Scenario[] = [
  {
    id: "INC-0417",
    label: "INC-0417 — multi-stage compromise of WKS-FIN-015",
    entity: "10.2.3.15",
    outcome: "Risk 34 → 86 (High). Retro-hunt raises it to 95 (Critical).",
    stages: [
      {
        time: "2026-09-30T08:47:12Z",
        label: "Reconnaissance",
        title: "Horizontal scan on 445/tcp",
        detail:
          "254 hosts probed in 90 s, 12,208 SYN packets, 3 completed handshakes. Rule SIG-RECON-HSCAN-445 v2.4, confidence 0.97.",
        risk: 34,
        category: "Reconnaissance",
        rows: [
          ["10.2.3.15", 44120, "10.2.3.21", 445, "TCP", 60, 1, "client-to-server", ["scan", "no-handshake"]],
          ["10.2.3.15", 44121, "10.2.3.22", 445, "TCP", 60, 1, "client-to-server", ["scan", "no-handshake"]],
          ["10.2.3.15", 44122, "10.2.3.23", 445, "TCP", 60, 1, "client-to-server", ["scan", "no-handshake"]],
          ["10.2.3.15", 44123, "10.2.3.24", 445, "TCP", 62, 1, "client-to-server", ["scan", "monotonic"]],
        ],
      },
      {
        time: "2026-09-30T09:05:40Z",
        label: "DGA resolution",
        title: "61 algorithmically generated domains queried",
        detail:
          "62% NXDOMAIN, mean label entropy 3.62, model probability 0.89. Detectors dga-lstm-v3.1 and SIG-DNS-DGA-ENTROPY.",
        risk: 52,
        category: "DGA/DNS Tunnelling",
        rows: [
          ["10.2.3.15", 49650, "10.2.3.9", 53, "UDP", 112, 2, "bidirectional", ["dns", "dga-candidate"]],
          ["10.2.3.15", 49652, "10.2.3.9", 53, "UDP", 118, 2, "bidirectional", ["dns", "nxdomain"]],
          ["10.2.3.15", 49654, "10.2.3.9", 53, "UDP", 124, 2, "bidirectional", ["dns", "high-entropy"]],
        ],
      },
      {
        time: "2026-09-30T09:31:05Z",
        label: "Command & Control",
        title: "Periodic beaconing to 203.0.113.47:443",
        detail:
          "Interval 60.1 s, CV 0.03, payload 212 ± 6 bytes, periodicity score 0.93. 142 connections by 11:53. Model beacon-periodicity-v2.7.",
        risk: 71,
        category: "C2 Beaconing",
        rows: [
          ["10.2.3.15", 49712, "203.0.113.47", 443, "TCP", 212, 9, "bidirectional", ["tls", "beacon"]],
          ["203.0.113.47", 443, "10.2.3.15", 49712, "TCP", 198, 8, "server-to-client", ["tls", "beacon"]],
          ["10.2.3.15", 49732, "203.0.113.47", 443, "TCP", 212, 9, "bidirectional", ["tls", "beacon"]],
        ],
      },
      {
        time: "2026-09-30T09:52:19Z",
        label: "Encrypted session",
        title: "Self-signed certificate, JA4 match",
        detail:
          "3,650-day validity, ALPN http/1.1, JA4 t13d1715h2_5b57614c22b0_a1c94e30f7d2, early-packet-sequence p = 0.83.",
        risk: 79,
        category: "Encrypted Malware",
        rows: [
          ["10.2.3.15", 49800, "203.0.113.47", 443, "TCP", 209, 12, "bidirectional", ["tls", "self-signed"]],
          ["203.0.113.47", 443, "10.2.3.15", 49800, "TCP", 221, 11, "server-to-client", ["tls", "self-signed"]],
        ],
      },
      {
        time: "2026-09-30T11:20:44Z",
        label: "Exfiltration",
        title: "4.8 GB outbound to 198.51.100.88:443",
        detail:
          "38 flows in 41 minutes, 27× host baseline, upload:download 312:1, destination never seen before. Model exfil-volume-v2.2.",
        risk: 86,
        category: "Exfiltration",
        rows: [
          ["10.2.3.15", 49880, "198.51.100.88", 443, "TCP", 1418, 41, "client-to-server", ["tls", "exfil-candidate"]],
          ["10.2.3.15", 49884, "198.51.100.88", 443, "TCP", 1462, 38, "client-to-server", ["tls", "exfil-candidate"]],
          ["198.51.100.88", 443, "10.2.3.15", 49880, "TCP", 66, 3, "server-to-client", ["tls", "ack-only"]],
        ],
      },
    ],
  },
  {
    id: "INC-0418",
    label: "INC-0418 — DDoS against WEB-PUB-02",
    entity: "10.0.5.20",
    outcome: "Risk 74 → 82 (High). Upstream rate-limit recommended.",
    stages: [
      {
        time: "2026-09-30T10:12:03Z",
        label: "Impact",
        title: "UDP reflection and amplification",
        detail:
          "412 distinct reflectors, source ports 53 / 123 / 11211, peak 3.1 Gbps equivalent sustained 21 minutes. Confidence 0.94.",
        risk: 74,
        category: "DDoS",
        rows: [
          ["192.0.2.31", 53, "10.0.5.20", 443, "UDP", 1412, 1, "server-to-client", ["reflector", "amplified"]],
          ["198.51.100.7", 123, "10.0.5.20", 443, "UDP", 1388, 1, "server-to-client", ["reflector", "amplified"]],
          ["203.0.113.19", 11211, "10.0.5.20", 80, "UDP", 1412, 1, "server-to-client", ["reflector", "amplified"]],
        ],
      },
      {
        time: "2026-09-30T10:31:47Z",
        label: "Impact",
        title: "SYN flood with source-address entropy",
        detail:
          "SYN:ACK 14:1, source-address entropy 7.9 bits, 91% single-packet sources, 48,213 half-open connections. Confidence 0.81.",
        risk: 82,
        category: "DDoS",
        rows: [
          ["10.0.5.20", 443, "192.0.2.55", 38912, "TCP", 74, 1, "server-to-client", ["syn-flood", "spoofed-source"]],
          ["10.0.5.20", 443, "198.51.100.77", 39110, "TCP", 74, 1, "server-to-client", ["syn-flood", "spoofed-source"]],
          ["10.0.5.20", 443, "203.0.113.66", 39220, "TCP", 74, 1, "server-to-client", ["syn-flood", "spoofed-source"]],
        ],
      },
    ],
  },
];

function buildRows(stage: Stage, scenario: Scenario, seed: number): LiveFlowRow[] {
  return stage.rows.map((r, i) => ({
    id: seed * 100 + i,
    ts: `${stage.time.slice(0, 10)} ${stage.time.slice(11, 19)}Z`,
    src: r[0],
    srcPort: r[1],
    dst: r[2],
    dstPort: r[3],
    proto: r[4],
    bytes: r[5],
    packets: r[6],
    direction: r[7],
    tags: [...r[8], `replay ${scenario.id}`],
    injected: stage.category as LiveFlowRow["injected"],
  }));
}

export function ScenarioReplay({ onEmit }: { onEmit: (rows: LiveFlowRow[]) => void }) {
  const [scenarioIdx, setScenarioIdx] = useState(0);
  const [step, setStep] = useState(-1);
  const [playing, setPlaying] = useState(false);
  const scenario = SCENARIOS[scenarioIdx];
  const total = scenario.stages.length;
  const stage = step >= 0 ? scenario.stages[step] : null;

  useEffect(() => {
    if (!playing) return;
    const t = setInterval(() => {
      setStep((prev) => {
        const next = prev + 1;
        if (next >= total) {
          setPlaying(false);
          return prev;
        }
        onEmit(buildRows(scenario.stages[next], scenario, scenarioIdx * 10 + next + 1));
        return next;
      });
    }, 1800);
    return () => clearInterval(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [playing, total, scenario, scenarioIdx]);

  const goto = (next: number) => {
    if (next < 0 || next >= total) return;
    setStep(next);
    onEmit(buildRows(scenario.stages[next], scenario, scenarioIdx * 10 + next + 1));
  };

  return (
    <Panel data-demo-id="scenario-replay">
      <PanelHeader
        title="Scenario replay"
        subtitle="Deterministic replay of the seeded incident timeline into the flow stream"
        icon={<Play size={13} strokeWidth={1.6} />}
        right={
          <div className="flex items-center gap-2">
            <select
              value={scenarioIdx}
              onChange={(e) => {
                setScenarioIdx(Number(e.target.value));
                setStep(-1);
                setPlaying(false);
              }}
              className="h-[24px] rounded border border-border-strong bg-white px-1.5 text-[11.5px] text-ink focus:border-navy focus:outline-none"
            >
              {SCENARIOS.map((s, i) => (
                <option key={s.id} value={i}>
                  {s.label}
                </option>
              ))}
            </select>
            <Button onClick={() => setStep(-1)} title="Reset replay">
              <RotateCcw size={12} strokeWidth={1.6} /> Reset
            </Button>
            <Button onClick={() => goto(step - 1)} disabled={step <= 0} title="Previous stage">
              <ChevronLeft size={12} strokeWidth={1.6} />
            </Button>
            <Button variant="primary" onClick={() => setPlaying((p) => !p)} disabled={step >= total - 1 && !playing}>
              {playing ? <Pause size={12} strokeWidth={1.6} /> : <Play size={12} strokeWidth={1.6} />}
              {playing ? "Pause" : "Play"}
            </Button>
            <Button onClick={() => goto(step + 1)} disabled={step >= total - 1} title="Next stage">
              <ChevronRight size={12} strokeWidth={1.6} />
            </Button>
            <Button onClick={() => goto(total - 1)} disabled={step >= total - 1} title="Run to end">
              <SkipForward size={12} strokeWidth={1.6} />
            </Button>
          </div>
        }
      />
      <div className="px-3 py-2.5">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-1.5">
            {scenario.stages.map((s, i) => (
              <button
                key={s.time}
                onClick={() => goto(i)}
                className={`inline-flex items-center gap-1.5 rounded-[3px] border px-2 py-[3px] text-[11px] ${
                  i <= step ? "border-navy bg-navy-soft text-navy" : "border-border bg-white text-ink2 hover:text-ink"
                }`}
              >
                <span
                  className="inline-block h-2 w-2 rounded-full"
                  style={{
                    backgroundColor: i <= step ? CATEGORY_COLOR[s.category] : "#D8DDE4",
                  }}
                />
                {s.label}
              </button>
            ))}
          </div>
          <div className="flex items-center gap-2 text-[11px] text-ink2">
            <Chip>{scenario.id}</Chip>
            <Chip>{scenario.entity}</Chip>
            <span>Replayed rows carry their original incident timestamps.</span>
          </div>
        </div>

        <ProgressBar
          className="mt-2"
          value={step < 0 ? 0 : ((step + 1) / total) * 100}
          color={stage ? CATEGORY_COLOR[stage.category] : "#1F3A5F"}
        />

        <div className="mt-2 grid grid-cols-4 gap-3">
          <div className="col-span-3 rounded border border-border bg-[#fbfbfc] px-3 py-2">
            {stage ? (
              <>
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-mono text-[11.5px] text-ink2">{stage.time.slice(11, 19)} UTC</span>
                  <span
                    className="inline-flex items-center gap-1.5 rounded-[3px] px-1.5 py-[1px] text-[11px] font-medium"
                    style={{
                      color: CATEGORY_COLOR[stage.category],
                      backgroundColor: `${CATEGORY_COLOR[stage.category]}18`,
                    }}
                  >
                    {stage.category}
                  </span>
                  <span className="text-[12.5px] font-medium text-ink">{stage.title}</span>
                </div>
                <p className="mt-1 text-[12px] leading-relaxed text-ink2">{stage.detail}</p>
              </>
            ) : (
              <div className="text-[12px] leading-relaxed text-ink2">
                Press <span className="font-medium text-ink">Play</span> to replay the incident
                stage by stage. Each stage appends its flow records to the stream above and raises
                the incident risk. Replay is deterministic and does not observe real traffic.
              </div>
            )}
          </div>
          <div className="rounded border border-border px-3 py-2">
            <div className="text-[10.5px] uppercase tracking-wide text-ink2">Incident risk</div>
            <div
              className="mt-1 font-mono text-[24px] font-semibold leading-none tabular-nums"
              style={{ color: stage ? (stage.risk >= 70 ? "#C2410C" : stage.risk >= 50 ? "#B7791F" : "#3E6B57") : "#8A949F" }}
            >
              {stage ? stage.risk : "—"}
            </div>
            <div className="mt-1 text-[11px] text-ink2">
              {stage ? `band: ${riskSeverity(stage.risk)}` : "no stage selected"}
            </div>
            <div className="mt-1 text-[11px] leading-snug text-ink2">{scenario.outcome}</div>
            <Link to="/incidents" className="mt-1 inline-block text-[11.5px] text-link hover:underline">
              Open {scenario.id}
            </Link>
          </div>
        </div>
      </div>
    </Panel>
  );
}
