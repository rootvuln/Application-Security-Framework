import { useEffect, useState } from "react";
import { ShieldCheck, Bell, Search, Menu, Command } from "lucide-react";
import { useLocation } from "react-router-dom";
import { analysisService } from "../../services/analysisService";

const titles = {
  "/": ["Overview", "Your security operations at a glance"],
  "/web-network": ["Web & Network", "Inspect infrastructure and network exposure"],
  "/forensics": ["Digital Forensics", "Examine files and digital evidence"],
  "/osint": ["OSINT Intelligence", "Investigate publicly available intelligence"],
  "/cryptography": ["Cryptography", "Encoding, hashing and cryptographic utilities"],
  "/log-analysis": ["Log Analysis", "Review events and identify suspicious activity"],
  "/malware": ["Malware Analysis", "Inspect files for suspicious indicators"],
  "/settings": ["Settings", "Manage your workspace preferences"],
};

export default function Header({ onMenuClick }) {
  const [status, setStatus] = useState("connecting");
  const location = useLocation();
  const [title, subtitle] = titles[location.pathname] || ["Workspace", "Cybersecurity analysis workspace"];

  useEffect(() => {
    let isMounted = true;
    analysisService.checkHealth().then(data => { if (isMounted) setStatus(data.success ? "online" : "offline"); }).catch(() => { if (isMounted) setStatus("offline"); });
    return () => { isMounted = false; };
  }, []);

  return <header className="topbar">
    <button className="mobile-menu" onClick={onMenuClick} aria-label="Open navigation"><Menu size={20}/></button>
    <div className="page-heading"><div className="breadcrumb">CYBERSUITE <span>/</span> WORKSPACE</div><h1>{title}</h1><p>{subtitle}</p></div>
    <div className="topbar-actions">
      <div className="search-shell"><Search size={16}/><span>Search workspace</span><kbd><Command size={11}/> K</kbd></div>
      <div className={`backend-pill ${status}`}><i/>{status === "online" ? "API CONNECTED" : status === "offline" ? "API OFFLINE" : "CONNECTING"}</div>
      <button className="icon-button" aria-label="Notifications"><Bell size={17}/><i/></button>
      <div className="topbar-avatar">VG</div>
    </div>
  </header>;
}
