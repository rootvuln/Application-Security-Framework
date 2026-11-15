import { Link } from "react-router-dom";
import { Network, FileSearch, Globe, LockKeyhole, ScrollText, ShieldAlert, ArrowUpRight, ShieldCheck, Activity, ScanSearch, Fingerprint, Terminal, Clock3, CircleCheck, Zap } from "lucide-react";

const features = [
  { title: "Web & Network", description: "Inspect domains, DNS records, HTTP headers, TLS and open ports.", path: "/web-network", icon: Network, number: "01", tag: "RECONNAISSANCE" },
  { title: "Digital Forensics", description: "Extract file metadata, inspect artifacts and generate evidence hashes.", path: "/forensics", icon: FileSearch, number: "02", tag: "EVIDENCE" },
  { title: "OSINT Intelligence", description: "Collect and correlate publicly available information on a target.", path: "/osint", icon: Globe, number: "03", tag: "INTELLIGENCE" },
  { title: "Cryptography", description: "Work with hashes, encodings, ciphers and key utilities.", path: "/cryptography", icon: LockKeyhole, number: "04", tag: "CRYPTOGRAPHY" },
  { title: "Log Analysis", description: "Review system events and surface potentially suspicious activity.", path: "/log-analysis", icon: ScrollText, number: "05", tag: "DETECTION" },
  { title: "Malware Analysis", description: "Examine file properties and static indicators in a safe workflow.", path: "/malware", icon: ShieldAlert, number: "06", tag: "THREAT ANALYSIS" },
];

const events = [
  { icon: ShieldCheck, title: "Workspace initialized", detail: "CyberSuite analysis environment is ready", time: "SYSTEM", tone: "purple" },
  { icon: Activity, title: "Analysis modules available", detail: "Six investigation modules configured", time: "READY", tone: "green" },
  { icon: Fingerprint, title: "Evidence integrity tools", detail: "Hash generation and file analysis tools", time: "TOOLS", tone: "blue" },
];

export default function Dashboard() {
  return <div className="dashboard">
    <section className="welcome-panel">
      <div className="welcome-grid"/>
      <div className="welcome-content">
        <div className="eyebrow"><span className="eyebrow-dot"/> SECURITY OPERATIONS CENTER <span className="eyebrow-line"/></div>
        <h2>See the signal.<br/><em>Secure the surface.</em></h2>
        <p>A unified environment for reconnaissance, digital forensics and threat investigation. Choose a workspace to start your analysis.</p>
        <div className="welcome-meta"><span><span className="live-dot"/> Workspace active</span><b/> <span>06 intelligence modules</span><b/> <span>Unified analysis console</span></div>
      </div>
      <div className="hero-orbit" aria-hidden="true"><div className="orbit orbit-one"/><div className="orbit orbit-two"/><div className="orbit-core"><ShieldCheck size={38}/></div><span className="orbit-node node-a"/><span className="orbit-node node-b"/><span className="orbit-node node-c"/></div>
      <div className="hero-index">CS / 001</div>
    </section>

    <section className="metric-grid">
      <div className="metric-card"><div className="metric-top"><span>AVAILABLE MODULES</span><div className="metric-icon"><ScanSearch size={16}/></div></div><div className="metric-value">06 <small>/ 06</small></div><div className="metric-foot"><span className="metric-good"><CircleCheck size={12}/> All systems configured</span></div></div>
      <div className="metric-card"><div className="metric-top"><span>WORKSPACE STATUS</span><div className="metric-icon"><Activity size={16}/></div></div><div className="metric-value status-value"><i/>Operational</div><div className="metric-foot">Ready for investigation</div></div>
      <div className="metric-card"><div className="metric-top"><span>ANALYSIS ENGINE</span><div className="metric-icon"><Zap size={16}/></div></div><div className="metric-value">Unified</div><div className="metric-foot">Connected service layer</div></div>
      <div className="metric-card"><div className="metric-top"><span>SESSION</span><div className="metric-icon"><Clock3 size={16}/></div></div><div className="metric-value">Active</div><div className="metric-foot">Local analyst workspace</div></div>
    </section>

    <section className="modules-section">
      <div className="section-heading"><div><div className="section-kicker">YOUR TOOLKIT</div><h3>Analysis workspaces</h3><p>Select a module to launch a focused investigation.</p></div><span className="section-count">01 — 06</span></div>
      <div className="module-grid">
        {features.map(({title,description,path,icon:Icon,number,tag}) => <Link key={path} to={path} className="module-card">
          <div className="module-card-top"><div className="module-icon"><Icon size={20}/></div><span className="module-number">{number}</span></div>
          <div className="module-tag">{tag}</div><h4>{title}</h4><p>{description}</p>
          <div className="module-card-bottom"><span>OPEN WORKSPACE</span><ArrowUpRight size={16}/></div>
        </Link>)}
      </div>
    </section>

    <section className="bottom-grid">
      <div className="activity-panel"><div className="panel-heading"><div><span className="section-kicker">SYSTEM FEED</span><h3>Workspace activity</h3></div><span className="feed-live"><i/> LIVE</span></div>
        {events.map(({icon:Icon,title,detail,time,tone}) => <div className="activity-row" key={title}><div className={`activity-icon ${tone}`}><Icon size={15}/></div><div className="activity-copy"><strong>{title}</strong><span>{detail}</span></div><small>{time}</small></div>)}
      </div>
      <div className="quick-panel"><div className="section-kicker">QUICK ACCESS</div><h3>Investigation console</h3><p>Jump straight into a common analysis workflow.</p><Link to="/web-network"><span className="quick-icon"><Network size={16}/></span><span><strong>Network reconnaissance</strong><small>DNS, TLS, headers and ports</small></span><ArrowUpRight size={16}/></Link><Link to="/forensics"><span className="quick-icon"><FileSearch size={16}/></span><span><strong>File investigation</strong><small>Inspect digital evidence</small></span><ArrowUpRight size={16}/></Link><Link to="/cryptography"><span className="quick-icon"><Terminal size={16}/></span><span><strong>Cryptographic utilities</strong><small>Hash and decode data</small></span><ArrowUpRight size={16}/></Link></div>
    </section>
    <footer className="dashboard-footer"><span>CYBERSUITE <b>•</b> SECURITY ANALYSIS PLATFORM</span><span>BUILT FOR INVESTIGATION. DESIGNED FOR CLARITY.</span></footer>
  </div>;
}
