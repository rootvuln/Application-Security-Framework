import { useState } from "react";
import { Network } from "lucide-react";
import { analysisService } from "../../services/analysisService";
import LoadingState from "../../components/common/LoadingState";
import ErrorMessage from "../../components/common/ErrorMessage";
import ResultCard from "../../components/common/ResultCard";

// ─── Helpers ──────────────────────────────────────────────────────────────────

const SEVERITY_COLORS = {
  critical: "border-red-500/40 bg-red-500/15 text-red-400",
  high: "border-orange-500/40 bg-orange-500/15 text-orange-400",
  medium: "border-yellow-500/40 bg-yellow-500/15 text-yellow-400",
  low: "border-blue-400/40 bg-blue-400/15 text-blue-400",
  info: "border-slate-500/40 bg-slate-500/15 text-slate-400",
  unknown: "border-slate-600/40 bg-slate-600/15 text-slate-500",
};

function SeverityBadge({ severity = "unknown" }) {
  const cls = SEVERITY_COLORS[(severity || "unknown").toLowerCase()] || SEVERITY_COLORS.unknown;
  return (
    <span className={`rounded-full border px-2 py-0.5 text-xs font-semibold uppercase ${cls}`}>
      {severity}
    </span>
  );
}

function FindingsList({ findings }) {
  if (!findings || findings.length === 0) return null;
  return (
    <div className="mt-4 space-y-2">
      <p className="text-xs font-semibold uppercase text-slate-500">Findings</p>
      {findings.map((f, i) => (
        <div key={i} className="rounded-lg border border-slate-800 bg-slate-900/60 p-3 text-xs">
          <div className="flex items-center justify-between gap-2 mb-1">
            <span className="font-semibold text-slate-200">{f.title}</span>
            <SeverityBadge severity={f.severity} />
          </div>
          {f.description && <p className="text-slate-400 leading-5">{f.description}</p>}
          {f.evidence && (
            <pre className="mt-1 font-mono text-slate-500 whitespace-pre-wrap break-all">
              {f.evidence}
            </pre>
          )}
        </div>
      ))}
    </div>
  );
}

function DetailsBlock({ details }) {
  if (!details || Object.keys(details).length === 0) return null;
  return (
    <div className="mt-4">
      <p className="mb-2 text-xs font-semibold uppercase text-slate-500">Details</p>
      <pre className="rounded-lg border border-slate-800 bg-slate-900/60 p-3 text-xs font-mono text-slate-300 overflow-auto whitespace-pre-wrap break-all">
        {JSON.stringify(details, null, 2)}
      </pre>
    </div>
  );
}

function AnalysisResult({ data }) {
  if (!data) return null;
  return (
    <ResultCard title="Analysis Result" badge={data.risk_level}>
      {data.summary && (
        <p className="text-sm text-slate-300 leading-6">{data.summary}</p>
      )}
      <FindingsList findings={data.findings} />
      <DetailsBlock details={data.details} />
      {data.errors && data.errors.length > 0 && (
        <div className="mt-3 rounded-lg border border-red-500/20 bg-red-500/10 p-3 text-xs text-red-400">
          {data.errors.join(", ")}
        </div>
      )}
    </ResultCard>
  );
}

// ─── Individual tab panels ─────────────────────────────────────────────────────

function TargetInput({ value, onChange, placeholder = "e.g. example.com or 1.2.3.4" }) {
  return (
    <div>
      <label className="mb-1.5 block text-xs font-semibold uppercase text-slate-500">Target</label>
      <input
        type="text"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        className="w-full rounded-lg border border-slate-800 bg-slate-900 px-4 py-2.5 text-sm text-slate-100 placeholder-slate-600 focus:border-cyan-500 focus:outline-none"
      />
    </div>
  );
}

function PortsInput({ value, onChange }) {
  return (
    <div>
      <label className="mb-1.5 block text-xs font-semibold uppercase text-slate-500">
        Ports (comma-separated)
      </label>
      <input
        type="text"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder="22,80,443,8080"
        className="w-full rounded-lg border border-slate-800 bg-slate-900 px-4 py-2.5 text-sm text-slate-100 placeholder-slate-600 focus:border-cyan-500 focus:outline-none"
      />
    </div>
  );
}

function SubmitButton({ loading, label, loadingLabel }) {
  return (
    <button
      type="submit"
      disabled={loading}
      className="flex items-center gap-2 rounded-lg bg-cyan-600 px-5 py-2.5 text-sm font-medium text-white transition hover:bg-cyan-500 disabled:opacity-50"
    >
      {loading ? loadingLabel || "Running…" : label || "Analyze"}
    </button>
  );
}

function parsePorts(raw) {
  return raw
    .split(",")
    .map((p) => p.trim())
    .filter(Boolean)
    .map((p) => (isNaN(Number(p)) ? p : Number(p)));
}

function useAnalysis(apiFn) {
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  const run = async (...args) => {
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const res = await apiFn(...args);
      setResult(res);
    } catch (err) {
      setError(err.message || "An unexpected error occurred.");
    } finally {
      setLoading(false);
    }
  };

  return { loading, result, error, run, setError };
}

// ── DNS ───────────────────────────────────────────────────────────────────────
function DnsTab() {
  const [target, setTarget] = useState("");
  const { loading, result, error, run, setError } = useAnalysis(analysisService.scanDns);

  const handleSubmit = (e) => {
    e.preventDefault();
    if (!target.trim()) return;
    run(target.trim());
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <TargetInput value={target} onChange={setTarget} placeholder="e.g. example.com" />
      <SubmitButton loading={loading} label="Scan DNS" loadingLabel="Scanning…" />
      {error && <ErrorMessage message={error} onDismiss={() => setError(null)} />}
      {loading && <LoadingState message="Performing DNS analysis…" />}
      <AnalysisResult data={result} />
    </form>
  );
}

// ── Headers ───────────────────────────────────────────────────────────────────
function HeadersTab() {
  const [target, setTarget] = useState("");
  const { loading, result, error, run, setError } = useAnalysis(analysisService.inspectHeaders);

  const handleSubmit = (e) => {
    e.preventDefault();
    if (!target.trim()) return;
    run(target.trim());
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <TargetInput value={target} onChange={setTarget} placeholder="e.g. https://example.com" />
      <SubmitButton loading={loading} label="Inspect Headers" loadingLabel="Inspecting…" />
      {error && <ErrorMessage message={error} onDismiss={() => setError(null)} />}
      {loading && <LoadingState message="Fetching HTTP headers…" />}
      <AnalysisResult data={result} />
    </form>
  );
}

// ── TLS ───────────────────────────────────────────────────────────────────────
function TlsTab() {
  const [target, setTarget] = useState("");
  const { loading, result, error, run, setError } = useAnalysis(analysisService.scanTls);

  const handleSubmit = (e) => {
    e.preventDefault();
    if (!target.trim()) return;
    run(target.trim());
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <TargetInput value={target} onChange={setTarget} placeholder="e.g. example.com" />
      <SubmitButton loading={loading} label="Inspect TLS" loadingLabel="Inspecting…" />
      {error && <ErrorMessage message={error} onDismiss={() => setError(null)} />}
      {loading && <LoadingState message="Analyzing TLS certificate…" />}
      <AnalysisResult data={result} />
    </form>
  );
}

// ── TCP Port Scan ─────────────────────────────────────────────────────────────
function TcpTab() {
  const [target, setTarget] = useState("");
  const [ports, setPorts] = useState("22,80,443,8080");
  const { loading, result, error, run, setError } = useAnalysis(
    (t, p) => analysisService.scanTcp(t, p)
  );

  const handleSubmit = (e) => {
    e.preventDefault();
    if (!target.trim()) return;
    run(target.trim(), parsePorts(ports));
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <TargetInput value={target} onChange={setTarget} />
      <PortsInput value={ports} onChange={setPorts} />
      <SubmitButton loading={loading} label="Scan TCP Ports" loadingLabel="Scanning…" />
      {error && <ErrorMessage message={error} onDismiss={() => setError(null)} />}
      {loading && <LoadingState message="Running TCP port scan…" />}
      <AnalysisResult data={result} />
    </form>
  );
}

// ─── Main Component ───────────────────────────────────────────────────────────

const TABS = [
  { id: "dns", label: "DNS" },
  { id: "headers", label: "HTTP Headers" },
  { id: "tls", label: "TLS" },
  { id: "tcp", label: "TCP Ports" },
];

export default function WebNetwork() {
  const [activeTab, setActiveTab] = useState("dns");

  return (
    <div className="max-w-4xl space-y-6">
      {/* Header */}
      <div>
        <h2 className="flex items-center gap-2 text-2xl font-bold">
          <Network className="text-cyan-400" size={24} /> Web &amp; Network
        </h2>
        <p className="mt-1 text-sm text-slate-400">
          Analyze DNS records, HTTP headers, TLS certificates, and open TCP ports.
        </p>
      </div>

      {/* Tab nav */}
      <div className="flex flex-wrap gap-2">
        {TABS.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`rounded-full px-4 py-1.5 text-sm font-medium transition ${
              activeTab === tab.id
                ? "bg-cyan-500/15 text-cyan-300 ring-1 ring-cyan-500/30"
                : "text-slate-400 hover:text-slate-200"
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* Panel */}
      <div className="rounded-xl border border-slate-800 bg-slate-950 p-6">
        {activeTab === "dns" && <DnsTab />}
        {activeTab === "headers" && <HeadersTab />}
        {activeTab === "tls" && <TlsTab />}
        {activeTab === "tcp" && <TcpTab />}
      </div>
    </div>
  );
}
