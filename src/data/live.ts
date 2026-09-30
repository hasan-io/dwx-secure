import type { Category, Direction, LiveFlowRow } from "../lib/types";
import { mulberry32 } from "../lib/utils";

interface Seed {
  src: string;
  srcPort: number;
  dst: string;
  dstPort: number;
  proto: string;
  bytes: number;
  packets: number;
  direction: Direction;
  tags: string[];
  injected?: Category;
}

/**
 * Deterministic seed pool for the Live Monitor stream. Rows are appended in
 * order; the only variability is the arrival interval, which is bounded.
 */
export const LIVE_POOL: Seed[] = [
  { src: "10.2.3.15", srcPort: 49712, dst: "203.0.113.47", dstPort: 443, proto: "TCP", bytes: 212, packets: 9, direction: "bidirectional", tags: ["tls", "beacon"], injected: "C2 Beaconing" },
  { src: "10.0.5.20", srcPort: 443, dst: "192.0.2.31", dstPort: 37912, proto: "UDP", bytes: 1412, packets: 1, direction: "server-to-client", tags: ["reflector", "amplified"], injected: "DDoS" },
  { src: "10.2.9.44", srcPort: 49288, dst: "10.2.9.9", dstPort: 53, proto: "UDP", bytes: 148, packets: 2, direction: "bidirectional", tags: ["dns"] },
  { src: "10.4.7.33", srcPort: 53210, dst: "192.0.2.77", dstPort: 53, proto: "UDP", bytes: 218, packets: 2, direction: "bidirectional", tags: ["dns", "txt", "high-entropy"], injected: "DGA/DNS Tunnelling" },
  { src: "10.2.3.15", srcPort: 49880, dst: "198.51.100.88", dstPort: 443, proto: "TCP", bytes: 1418, packets: 41, direction: "client-to-server", tags: ["tls", "exfil-candidate"], injected: "Exfiltration" },
  { src: "10.3.2.71", srcPort: 51420, dst: "203.0.113.91", dstPort: 8443, proto: "TCP", bytes: 41200, packets: 128, direction: "bidirectional", tags: ["tls", "self-signed"], injected: "Encrypted Malware" },
  { src: "10.1.9.8", srcPort: 44120, dst: "10.1.9.21", dstPort: 445, proto: "TCP", bytes: 60, packets: 1, direction: "client-to-server", tags: ["scan", "no-handshake"], injected: "Reconnaissance" },
  { src: "10.2.8.14", srcPort: 51001, dst: "198.51.100.140", dstPort: 443, proto: "TCP", bytes: 1460, packets: 22, direction: "client-to-server", tags: ["backup-window", "scheduled"] },
  { src: "10.0.5.20", srcPort: 443, dst: "198.51.100.7", dstPort: 38912, proto: "TCP", bytes: 74, packets: 1, direction: "server-to-client", tags: ["syn-flood", "spoofed-source"], injected: "DDoS" },
  { src: "10.2.3.15", srcPort: 49650, dst: "10.2.3.9", dstPort: 88, proto: "TCP", bytes: 320, packets: 6, direction: "bidirectional", tags: ["kerberos", "internal"] },
  { src: "10.2.9.44", srcPort: 49310, dst: "203.0.113.47", dstPort: 443, proto: "TCP", bytes: 1204, packets: 18, direction: "client-to-server", tags: ["tls", "known-c2"], injected: "C2 Beaconing" },
  { src: "10.0.5.20", srcPort: 80, dst: "192.0.2.55", dstPort: 51220, proto: "TCP", bytes: 512, packets: 8, direction: "server-to-client", tags: ["http", "public"] },
  { src: "10.4.7.33", srcPort: 53244, dst: "192.0.2.77", dstPort: 53, proto: "UDP", bytes: 1104, packets: 2, direction: "server-to-client", tags: ["dns", "txt", "response"] },
  { src: "10.3.2.71", srcPort: 51455, dst: "10.3.2.9", dstPort: 53, proto: "UDP", bytes: 96, packets: 2, direction: "bidirectional", tags: ["dns"] },
  { src: "10.1.9.8", srcPort: 44124, dst: "10.1.9.22", dstPort: 3389, proto: "TCP", bytes: 60, packets: 1, direction: "client-to-server", tags: ["scan", "no-handshake"], injected: "Reconnaissance" },
  { src: "10.2.8.14", srcPort: 51020, dst: "10.2.8.9", dstPort: 445, proto: "TCP", bytes: 210, packets: 5, direction: "bidirectional", tags: ["smb", "internal"] },
  { src: "10.2.3.15", srcPort: 49740, dst: "10.2.3.9", dstPort: 389, proto: "TCP", bytes: 480, packets: 10, direction: "bidirectional", tags: ["ldap", "internal"] },
  { src: "10.0.5.20", srcPort: 443, dst: "203.0.113.19", dstPort: 44990, proto: "UDP", bytes: 1412, packets: 1, direction: "server-to-client", tags: ["reflector", "amplified"], injected: "DDoS" },
  { src: "10.2.9.44", srcPort: 49330, dst: "10.2.9.10", dstPort: 443, proto: "TCP", bytes: 8120, packets: 42, direction: "bidirectional", tags: ["internal", "tls"] },
  { src: "10.4.7.33", srcPort: 53260, dst: "10.4.7.9", dstPort: 53, proto: "UDP", bytes: 88, packets: 2, direction: "bidirectional", tags: ["dns"] },
  { src: "10.3.2.71", srcPort: 51480, dst: "10.3.2.9", dstPort: 88, proto: "TCP", bytes: 360, packets: 7, direction: "bidirectional", tags: ["kerberos", "internal"] },
  { src: "10.2.3.15", srcPort: 49820, dst: "10.2.3.9", dstPort: 53, proto: "UDP", bytes: 112, packets: 2, direction: "bidirectional", tags: ["dns", "dga-candidate"], injected: "DGA/DNS Tunnelling" },
  { src: "10.1.9.8", srcPort: 44131, dst: "10.1.9.33", dstPort: 22, proto: "TCP", bytes: 60, packets: 1, direction: "client-to-server", tags: ["scan", "no-handshake"], injected: "Reconnaissance" },
  { src: "10.0.5.20", srcPort: 443, dst: "192.0.2.31", dstPort: 38001, proto: "UDP", bytes: 1412, packets: 1, direction: "server-to-client", tags: ["reflector", "amplified"], injected: "DDoS" },
  { src: "10.2.8.14", srcPort: 51040, dst: "198.51.100.140", dstPort: 443, proto: "TCP", bytes: 1462, packets: 24, direction: "client-to-server", tags: ["backup-window", "scheduled"] },
];

export function liveRows(count: number, startId = 1, startSeconds = 0): LiveFlowRow[] {
  const out: LiveFlowRow[] = [];
  let t = 1767115200 + startSeconds; // 2026-09-30 12:00:00 UTC
  for (let i = 0; i < count; i++) {
    const s = LIVE_POOL[(startId + i - 1) % LIVE_POOL.length];
    t += 1 + Math.floor(i % 2);
    const d = new Date(t * 1000);
    const p = (n: number) => String(n).padStart(2, "0");
    out.push({
      id: startId + i,
      ts: `${d.getUTCFullYear()}-${p(d.getUTCMonth() + 1)}-${p(d.getUTCDate())} ${p(
        d.getUTCHours()
      )}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())}Z`,
      src: s.src,
      srcPort: s.srcPort,
      dst: s.dst,
      dstPort: s.dstPort,
      proto: s.proto,
      bytes: s.bytes,
      packets: s.packets,
      direction: s.direction,
      tags: s.tags,
      injected: s.injected,
    });
  }
  return out;
}

/** Findings per minute by category — used by the detection timeline chart. */
export const DETECTION_TIMELINE: { minute: string; [k: string]: number | string }[] = (() => {
  const r = mulberry32(77);
  const cats = ["Reconnaissance", "C2 Beaconing", "DGA/DNS Tunnelling", "Encrypted Malware", "Exfiltration", "DDoS"];
  const out: { minute: string; [k: string]: number | string }[] = [];
  for (let m = 0; m < 60; m++) {
    const row: { minute: string; [k: string]: number | string } = {
      minute: `${String(11 + Math.floor(m / 60)).padStart(2, "0")}:${String(m % 60).padStart(2, "0")}`,
    };
    for (const c of cats) {
      let v = r() > 0.82 ? 1 : 0;
      if (m >= 7 && m <= 12 && c === "Reconnaissance") v = 2 + Math.floor(r() * 3);
      if (m >= 19 && m <= 26 && c === "C2 Beaconing") v = 3 + Math.floor(r() * 4);
      if (m >= 25 && m <= 31 && c === "DGA/DNS Tunnelling") v = 2 + Math.floor(r() * 3);
      if (m >= 52 && m <= 58 && c === "DDoS") v = 4 + Math.floor(r() * 5);
      if (m >= 80 && m <= 95 && c === "Exfiltration") v = 2 + Math.floor(r() * 3);
      row[c] = v;
    }
    out.push(row);
  }
  return out;
})();
