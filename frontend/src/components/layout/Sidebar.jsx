import { NavLink } from "react-router-dom";
import { LayoutDashboard, Network, FileSearch, Globe, LockKeyhole, ScrollText, ShieldAlert, Settings, Shield, ChevronRight } from "lucide-react";

const links = [
  { section: "WORKSPACE", items: [
    { name: "Overview", path: "/", icon: LayoutDashboard },
    { name: "Web & Network", path: "/web-network", icon: Network },
    { name: "Digital Forensics", path: "/forensics", icon: FileSearch },
    { name: "OSINT Intelligence", path: "/osint", icon: Globe },
  ]},
  { section: "ANALYSIS TOOLS", items: [
    { name: "Cryptography", path: "/cryptography", icon: LockKeyhole },
    { name: "Log Analysis", path: "/log-analysis", icon: ScrollText },
    { name: "Malware Analysis", path: "/malware", icon: ShieldAlert },
  ]},
];

export default function Sidebar({ onNavigate }) {
  return (
    <aside className="app-sidebar">
      <div className="brand">
        <div className="brand-mark"><Shield size={21} strokeWidth={2.2}/></div>
        <div><div className="brand-name">Cyber<span>Suite</span></div><div className="brand-caption">THREAT INTELLIGENCE PLATFORM</div></div>
      </div>
      <div className="workspace-switch">
        <div className="workspace-avatar">CS</div>
        <div className="workspace-copy"><strong>Security Workspace</strong><span>Personal environment</span></div>
        <ChevronRight size={15}/>
      </div>
      <nav className="side-nav">
        {links.map(group => <div className="nav-group" key={group.section}>
          <div className="nav-label">{group.section}</div>
          {group.items.map(({name,path,icon:Icon}) => <NavLink key={path} to={path} end={path === "/"} onClick={onNavigate} className={({isActive}) => `nav-link ${isActive ? "active" : ""}`}>
            <Icon size={17}/><span>{name}</span>{path === "/" ? null : <span className="nav-indicator"/>}
          </NavLink>)}
        </div>)}
      </nav>
      <div className="sidebar-bottom">
        <NavLink to="/settings" onClick={onNavigate} className={({isActive}) => `nav-link ${isActive ? "active" : ""}`}><Settings size={17}/><span>Settings</span></NavLink>
        <div className="sidebar-user"><div className="user-avatar">VG</div><div className="user-copy"><strong>Analyst Workspace</strong><span>Security analyst</span></div><span className="user-status"/></div>
      </div>
    </aside>
  );
}
