import { useEffect } from "react";
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { Sidebar, TopBar, Footer, Toast } from "./components/AppShell";
import { GuidedDemo } from "./components/GuidedDemo";
import { initEvidence, useDemo } from "./store/store";
import Overview from "./screens/Overview";
import LiveMonitor from "./screens/LiveMonitor";
import Incidents from "./screens/Incidents";
import ThreatIntel from "./screens/ThreatIntel";
import ResponseReports from "./screens/ResponseReports";
import Coverage from "./screens/Coverage";
import SecurityVisualization from "./screens/SecurityVisualization";
import ActivityAudit from "./screens/ActivityAudit";
import EvaluationTrust from "./screens/EvaluationTrust";

function Shell() {
  const guidedOpen = useDemo((s) => s.guidedOpen);

  useEffect(() => {
    void initEvidence();
  }, []);

  return (
    <div className="min-h-screen bg-bg">
      <Sidebar />
      <TopBar />
      <main
        className={`ml-[196px] pt-[46px] transition-[margin] print:ml-0 print:pt-0 ${
          guidedOpen ? "mr-[318px]" : ""
        }`}
      >
        <div className="p-3">
          <Routes>
            <Route path="/" element={<Overview />} />
            <Route path="/live" element={<LiveMonitor />} />
            <Route path="/incidents" element={<Incidents />} />
            <Route path="/intel" element={<ThreatIntel />} />
            <Route path="/response" element={<ResponseReports />} />
            <Route path="/visualization" element={<SecurityVisualization />} />
            <Route path="/coverage" element={<Coverage />} />
            <Route path="/audit" element={<ActivityAudit />} />
            <Route path="/trust" element={<EvaluationTrust />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </div>
        <Footer />
      </main>
      <GuidedDemo />
      <Toast />
    </div>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <Shell />
    </BrowserRouter>
  );
}
