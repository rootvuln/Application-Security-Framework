
import { BrowserRouter, Routes, Route } from "react-router-dom";

import AppLayout from "./components/layout/AppLayout";
import Dashboard from "./pages/Dashboard";
import Settings from "./pages/Settings";
import NotFound from "./pages/NotFound";

import WebNetwork from "./features/web-network/WebNetwork";
import Forensics from "./features/forensics/Forensics";
import OSINT from "./features/osint/OSINT";
import Cryptography from "./features/cryptography/Cryptography";
import LogAnalysis from "./features/log-analysis/LogAnalysis";
import Malware from "./features/malware/Malware";

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route element={<AppLayout />}>
          <Route path="/" element={<Dashboard />} />
          <Route path="/settings" element={<Settings />} />
          <Route path="/web-network" element={<WebNetwork />} />
          <Route path="/forensics" element={<Forensics />} />
          <Route path="/osint" element={<OSINT />} />
          <Route path="/cryptography" element={<Cryptography />} />
          <Route path="/log-analysis" element={<LogAnalysis />} />
          <Route path="/malware" element={<Malware />} />
          <Route path="*" element={<NotFound />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
