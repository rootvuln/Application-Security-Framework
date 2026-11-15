import { useState } from "react";
import { Globe } from "lucide-react";
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
  const cls =
    SEVERITY_COLORS[(severity || "unknown").toLowerCase()] || SEVERITY_COLORS.unknown;
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
          <div className="mb-1 flex items-center justify-between gap-2">
            <span className="font-semibold text-slate-200">{f.title}</span>
            <SeverityBadge severity={f.severity} />
          </div>
          {f.category && (
            <span className="text-slate-600 text-[11px]">{f.category}</span>
          )}
          {f.description && (
            <p className="mt-1 text-slate-400 leading-5">{f.description}</p>
          )}
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

// ─── Component ────────────────────────────────────────────────────────────────

export default function OSINT() {
  const [target, setTarget] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!target.trim()) return;

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const data = await analysisService.analyzeOsint(target.trim());
      setResult(data);
    } catch (err) {
      setError(err.message || "OSINT analysis failed.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-4xl space-y-6">
      {/* Header */}
      <div>
        <h2 className="flex items-center gap-2 text-2xl font-bold">
          <Globe className="text-cyan-400" size={24} /> OSINT Analysis
        </h2>
        <p className="mt-1 text-sm text-slate-400">
          Gather open-source intelligence on IPs, domains, and URLs from public sources.
        </p>
      </div>

      {/* Form */}
      <div className="rounded-xl border border-slate-800 bg-slate-950 p-6">
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="mb-1.5 block text-xs font-semibold uppercase text-slate-500">
              Target
            </label>
            <input
              type="text"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="e.g. 1.1.1.1  |  example.com  |  https://example.com"
              className="w-full rounded-lg border border-slate-800 bg-slate-900 px-4 py-2.5 text-sm text-slate-100 placeholder-slate-600 focus:border-cyan-500 focus:outline-none"
            />
          </div>

          <button
            type="submit"
            disabled={loading || !target.trim()}
            className="flex items-center gap-2 rounded-lg bg-cyan-600 px-5 py-2.5 text-sm font-medium text-white transition hover:bg-cyan-500 disabled:opacity-50"
          >
            {loading ? "Analyzing…" : "Run OSINT"}
          </button>
        </form>

        {error && (
          <div className="mt-4">
            <ErrorMessage message={error} onDismiss={() => setError(null)} />
          </div>
        )}
      </div>

      {/* Loading */}
      {loading && <LoadingState message="Gathering open-source intelligence…" />}

      {/* Results */}
      {result && (
        <ResultCard title="OSINT Report" badge={result.risk_level}>
          {result.summary && (
            <p className="text-sm text-slate-300 leading-6">{result.summary}</p>
          )}
          <FindingsList findings={result.findings} />
          <DetailsBlock details={result.details} />
          {result.errors && result.errors.length > 0 && (
            <div className="mt-3 rounded-lg border border-red-500/20 bg-red-500/10 p-3 text-xs text-red-400">
              {result.errors.join(", ")}
            </div>
          )}
        </ResultCard>
      )}
    </div>
  );
}
