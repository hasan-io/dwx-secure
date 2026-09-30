export function TrustBoundary() {
  const box = "fill-white stroke-[#C3CAD3]";
  return (
    <svg viewBox="0 0 1240 480" width="100%" height="480" role="img" aria-label="Trust boundary diagram">
      <defs>
        <marker id="dw-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
          <path d="M0 0 L10 5 L0 10 z" fill="#1F3A5F" />
        </marker>
        <marker id="dw-arrow-dashed" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
          <path d="M0 0 L10 5 L0 10 z" fill="#5B6773" />
        </marker>
      </defs>

      {/* Production side */}
      <rect x="16" y="60" width="170" height="64" rx="4" className={box} strokeWidth="1" />
      <text x="101" y="86" textAnchor="middle" className="fill-[#1F2933] text-[12px] font-semibold">
        Production network
      </text>
      <text x="101" y="103" textAnchor="middle" className="fill-[#5B6773] text-[10px]">
        monitored segments
      </text>
      <text x="101" y="117" textAnchor="middle" className="fill-[#5B6773] text-[10px]">
        no DiodeWatch agent
      </text>

      <line x1="186" y1="92" x2="232" y2="92" stroke="#1F3A5F" strokeWidth="1.2" markerEnd="url(#dw-arrow)" />
      <text x="209" y="82" textAnchor="middle" className="fill-[#5B6773] text-[10px]">
        mirror
      </text>

      <rect x="240" y="60" width="120" height="64" rx="4" className={box} strokeWidth="1" />
      <text x="300" y="88" textAnchor="middle" className="fill-[#1F2933] text-[12px] font-semibold">
        TAP / mirror
      </text>
      <text x="300" y="105" textAnchor="middle" className="fill-[#5B6773] text-[10px]">
        read-only copy
      </text>

      <line x1="360" y1="92" x2="404" y2="92" stroke="#1F3A5F" strokeWidth="1.2" markerEnd="url(#dw-arrow)" />

      {/* Diode symbol */}
      <path d="M414 78 L446 92 L414 106 Z" fill="#1F3A5F" />
      <rect x="452" y="76" width="7" height="32" fill="#1F3A5F" />
      <text x="432" y="128" textAnchor="middle" className="fill-[#1F2933] text-[10.5px] font-medium">
        data diode
      </text>
      <text x="432" y="141" textAnchor="middle" className="fill-[#5B6773] text-[10px]">
        one-way, 10 Gbps
      </text>

      <line x1="466" y1="92" x2="554" y2="92" stroke="#1F3A5F" strokeWidth="1.2" markerEnd="url(#dw-arrow)" />

      {/* Enclave */}
      <rect x="560" y="20" width="600" height="280" rx="4" fill="#F7F9FC" stroke="#1F3A5F" strokeWidth="1" />
      <text x="572" y="38" className="fill-[#1F3A5F] text-[11.5px] font-semibold">
        Monitoring enclave
      </text>
      <text x="572" y="52" className="fill-[#5B6773] text-[10px]">
        receive-only sensor · no IP address · TX 0 packets · egress DROP
      </text>

      {/* Row 1 */}
      <rect x="576" y="64" width="148" height="50" rx="4" className={box} strokeWidth="1" />
      <text x="650" y="86" textAnchor="middle" className="fill-[#1F2933] text-[11px] font-medium">
        Receive-only sensor
      </text>
      <text x="650" y="101" textAnchor="middle" className="fill-[#5B6773] text-[9.5px]">
        mirrored copy only
      </text>

      <line x1="724" y1="89" x2="736" y2="89" stroke="#1F3A5F" strokeWidth="1.2" markerEnd="url(#dw-arrow)" />
      <rect x="740" y="64" width="138" height="50" rx="4" className={box} strokeWidth="1" />
      <text x="809" y="86" textAnchor="middle" className="fill-[#1F2933] text-[11px] font-medium">
        Feature engine
      </text>
      <text x="809" y="101" textAnchor="middle" className="fill-[#5B6773] text-[9.5px]">
        flow, DNS, TLS metadata
      </text>

      <line x1="878" y1="89" x2="890" y2="89" stroke="#1F3A5F" strokeWidth="1.2" markerEnd="url(#dw-arrow)" />
      <rect x="894" y="64" width="138" height="50" rx="4" className={box} strokeWidth="1" />
      <text x="963" y="86" textAnchor="middle" className="fill-[#1F2933] text-[11px] font-medium">
        Detection engine
      </text>
      <text x="963" y="101" textAnchor="middle" className="fill-[#5B6773] text-[9.5px]">
        rules and models
      </text>

      <line x1="1032" y1="89" x2="1044" y2="89" stroke="#1F3A5F" strokeWidth="1.2" markerEnd="url(#dw-arrow)" />
      <rect x="1048" y="64" width="152" height="50" rx="4" className={box} strokeWidth="1" />
      <text x="1124" y="86" textAnchor="middle" className="fill-[#1F2933] text-[11px] font-medium">
        Incident and risk engine
      </text>
      <text x="1124" y="101" textAnchor="middle" className="fill-[#5B6773] text-[9.5px]">
        correlation, scoring
      </text>

      {/* Wrap arrow */}
      <path
        d="M1124 114 L1124 136 L650 136 L650 158"
        fill="none"
        stroke="#1F3A5F"
        strokeWidth="1.2"
        markerEnd="url(#dw-arrow)"
      />

      {/* Row 2 */}
      <rect x="576" y="160" width="148" height="50" rx="4" className={box} strokeWidth="1" />
      <text x="650" y="182" textAnchor="middle" className="fill-[#1F2933] text-[11px] font-medium">
        Response advisor
      </text>
      <text x="650" y="197" textAnchor="middle" className="fill-[#5B6773] text-[9.5px]">
        recommends, never enforces
      </text>

      <line x1="724" y1="185" x2="736" y2="185" stroke="#1F3A5F" strokeWidth="1.2" markerEnd="url(#dw-arrow)" />
      <rect x="740" y="160" width="138" height="50" rx="4" className={box} strokeWidth="1" />
      <text x="809" y="182" textAnchor="middle" className="fill-[#1F2933] text-[11px] font-medium">
        Report generator
      </text>
      <text x="809" y="197" textAnchor="middle" className="fill-[#5B6773] text-[9.5px]">
        evidence chain, SHA-256
      </text>

      <line x1="878" y1="185" x2="890" y2="185" stroke="#1F3A5F" strokeWidth="1.2" markerEnd="url(#dw-arrow)" />
      <rect x="894" y="160" width="138" height="50" rx="4" className={box} strokeWidth="1" />
      <text x="963" y="182" textAnchor="middle" className="fill-[#1F2933] text-[11px] font-medium">
        Threat-intel store
      </text>
      <text x="963" y="197" textAnchor="middle" className="fill-[#5B6773] text-[9.5px]">
        signed local bundles
      </text>

      <line x1="1032" y1="185" x2="1044" y2="185" stroke="#1F3A5F" strokeWidth="1.2" markerEnd="url(#dw-arrow)" />
      <rect x="1048" y="160" width="152" height="50" rx="4" className={box} strokeWidth="1" />
      <text x="1124" y="182" textAnchor="middle" className="fill-[#1F2933] text-[11px] font-medium">
        Analyst dashboard
      </text>
      <text x="1124" y="197" textAnchor="middle" className="fill-[#5B6773] text-[9.5px]">
        SOC-1 workstation
      </text>

      {/* No return path */}
      <path
        d="M560 250 L101 250 L101 130"
        fill="none"
        stroke="#A32020"
        strokeWidth="1.2"
        strokeDasharray="5 4"
        markerEnd="url(#dw-arrow)"
      />
      <g stroke="#A32020" strokeWidth="2">
        <line x1="308" y1="240" x2="322" y2="260" />
        <line x1="322" y1="240" x2="308" y2="260" />
      </g>
      <text x="330" y="246" className="fill-[#A32020] text-[11px] font-semibold">
        No return path
      </text>
      <text x="330" y="260" className="fill-[#5B6773] text-[10px]">
        no packets, no handshakes, no mitigation push from the enclave to production
      </text>

      {/* Outside DiodeWatch */}
      <text x="60" y="332" className="fill-[#1F2933] text-[11px] font-semibold">
        Outside DiodeWatch — authorised human process
      </text>
      <path
        d="M650 300 L650 320 L160 320 L160 336"
        fill="none"
        stroke="#5B6773"
        strokeWidth="1.2"
        strokeDasharray="5 4"
        markerEnd="url(#dw-arrow-dashed)"
      />
      <rect x="60" y="340" width="200" height="44" rx="4" className={box} strokeWidth="1" />
      <text x="160" y="360" textAnchor="middle" className="fill-[#1F2933] text-[11px] font-medium">
        Approved mitigation package
      </text>
      <text x="160" y="375" textAnchor="middle" className="fill-[#5B6773] text-[9.5px]">
        exported file, signed digest
      </text>

      <line x1="260" y1="362" x2="292" y2="362" stroke="#5B6773" strokeWidth="1.2" strokeDasharray="5 4" markerEnd="url(#dw-arrow-dashed)" />
      <rect x="296" y="340" width="230" height="44" rx="4" className={box} strokeWidth="1" />
      <text x="411" y="360" textAnchor="middle" className="fill-[#1F2933] text-[11px] font-medium">
        Change management
      </text>
      <text x="411" y="375" textAnchor="middle" className="fill-[#5B6773] text-[9.5px]">
        review, approval, scheduling
      </text>

      <line x1="526" y1="362" x2="558" y2="362" stroke="#5B6773" strokeWidth="1.2" strokeDasharray="5 4" markerEnd="url(#dw-arrow-dashed)" />
      <rect x="562" y="340" width="220" height="44" rx="4" className={box} strokeWidth="1" />
      <text x="672" y="360" textAnchor="middle" className="fill-[#1F2933] text-[11px] font-medium">
        Enforcement
      </text>
      <text x="672" y="375" textAnchor="middle" className="fill-[#5B6773] text-[9.5px]">
        firewall, DNS, host isolation
      </text>

      <text x="800" y="366" className="fill-[#5B6773] text-[10px]">
        DiodeWatch cannot confirm that any of these steps were applied.
      </text>

      {/* Signed TI bundle import */}
      <text x="60" y="432" className="fill-[#1F2933] text-[11px] font-semibold">
        Signed TI bundle import (inbound only)
      </text>
      <rect x="60" y="442" width="220" height="44" rx="4" className={box} strokeWidth="1" />
      <text x="170" y="462" textAnchor="middle" className="fill-[#1F2933] text-[11px] font-medium">
        DW-TI-2026-09-30-B
      </text>
      <text x="170" y="477" textAnchor="middle" className="fill-[#5B6773] text-[9.5px]">
        offline media, signature verified
      </text>
      <path
        d="M280 464 L880 464 L880 302"
        fill="none"
        stroke="#5B6773"
        strokeWidth="1.2"
        strokeDasharray="5 4"
        markerEnd="url(#dw-arrow-dashed)"
      />
      <text x="560" y="456" textAnchor="middle" className="fill-[#5B6773] text-[10px]">
        bundle crosses the diode inward only; no indicator lookup leaves the enclave
      </text>

      {/* Flow pipeline caption */}
      <text x="16" y="30" className="fill-[#1F3A5F] text-[11px] font-semibold">
        Passive traffic → feature analysis → threat detection → threat intelligence → incident correlation → risk scoring → response recommendation → forensic report
      </text>
    </svg>
  );
}
