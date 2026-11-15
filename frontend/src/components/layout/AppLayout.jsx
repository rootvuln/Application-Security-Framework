import { useState } from "react";
import { Outlet } from "react-router-dom";
import Sidebar from "./Sidebar";
import Header from "./Header";

export default function AppLayout() {
  const [menuOpen, setMenuOpen] = useState(false);
  return <div className="app-shell">
    {menuOpen && <button className="sidebar-scrim" aria-label="Close navigation" onClick={() => setMenuOpen(false)}/>}
    <div className={`sidebar-wrap ${menuOpen ? "open" : ""}`}><Sidebar onNavigate={() => setMenuOpen(false)}/></div>
    <div className="main-column"><Header onMenuClick={() => setMenuOpen(!menuOpen)}/><main className="page-content"><Outlet/></main></div>
  </div>;
}
