import { useState, useRef } from "react";
import { ScrollText, Upload, X } from "lucide-react";
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
          <div className="mb-1 flex items-center justify-between gap-2">
            <span className="font-semibold text-slate-200">{f.title}</span>
            <SeverityBadge severity={f.severity} />
          </div>
          {f.category && <span className="text-slate-600 text-[11px]">{f.category}</span>}
          {f.description && <p className="mt-1 text-slate-400 leading-5">{f.description}</p>}
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
      <div className="grid gap-2 sm:grid-cols-2">
        {Object.entries(details).map(([k, v]) => (
          <div key={k} className="rounded-lg border border-slate-800/80 bg-slate-900/50 p-3">
            <span className="text-xs font-semibold uppercase text-slate-500">{k}</span>
            <div className="mt-0.5 font-mono text-xs break-all text-slate-200">
              {typeof v === "object" ? JSON.stringify(v, null, 2) : String(v)}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ─── Component ────────────────────────────────────────────────────────────────

export default function LogAnalysis() {
  const [file, setFile] = useState(null);
  const [dragging, setDragging] = useState(false);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const inputRef = useRef(null);

  const selectFile = (f) => {
    if (!f) return;
    setFile(f);
    setResult(null);
    setError(null);
  };

  const handleDrop = (e) => {
    e.preventDefault();
    setDragging(false);
    const f = e.dataTransfer.files[0];
    if (f) selectFile(f);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!file) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const data = await analysisService.analyzeFile("/log-analysis/analyze", file);
      setResult(data);
    } catch (err) {
      setError(err.message || "Log analysis failed.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-4xl space-y-6">
      {/* Header */}
      <div>
        <h2 className="flex items-center gap-2 text-2xl font-bold">
          <ScrollText className="text-cyan-400" size={24} /> Log Analysis
        </h2>
        <p className="mt-1 text-sm text-slate-400">
          Upload system logs, PCAP captures, or text files to identify suspicious events.
        </p>
      </div>

      {/* Upload form */}
      <div className="rounded-xl border border-slate-800 bg-slate-950 p-6">
        <form onSubmit={handleSubmit} className="space-y-5">
          {/* Drop zone */}
          <div
            onClick={() => inputRef.current?.click()}
            onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
            onDragLeave={() => setDragging(false)}
            onDrop={handleDrop}
            className={`flex cursor-pointer flex-col items-center justify-center gap-3 rounded-xl border-2 border-dashed py-10 transition ${
              dragging
                ? "border-cyan-500 bg-cyan-500/5"
                : "border-slate-800 hover:border-slate-700 hover:bg-slate-900/50"
            }`}
          >
            <Upload size={28} className="text-slate-500" />
            <p className="text-sm text-slate-400">
              Drag &amp; drop a log file here, or{" "}
              <span className="text-cyan-400">browse</span>
            </p>
            <p className="text-xs text-slate-600">.log · .txt · .pcap · .pcapng · any format</p>
            <input
              ref={inputRef}
              type="file"
              accept=".log,.txt,.pcap,.pcapng,*"
              className="hidden"
              onChange={(e) => selectFile(e.target.files[0])}
            />
          </div>

          {/* Selected file */}
          {file && (
            <div className="flex items-center justify-between rounded-lg border border-slate-800 bg-slate-900/60 px-4 py-2.5 text-sm">
              <span className="text-slate-300 truncate">{file.name}</span>
              <div className="flex items-center gap-3 shrink-0">
                <span className="text-xs text-slate-500">
                  {(file.size / 1024).toFixed(1)} KB
                </span>
                <button
                  type="button"
                  onClick={() => { setFile(null); setResult(null); setError(null); }}
                  className="rounded p-0.5 text-slate-500 transition hover:text-red-400"
                >
                  <X size={14} />
                </button>
              </div>
            </div>
          )}

          <button
            type="submit"
            disabled={!file || loading}
            className="flex items-center gap-2 rounded-lg bg-cyan-600 px-5 py-2.5 text-sm font-medium text-white transition hover:bg-cyan-500 disabled:opacity-50"
          >
            {loading ? "Analyzing…" : "Analyze Log"}
          </button>
        </form>

        {error && (
          <div className="mt-4">
            <ErrorMessage message={error} onDismiss={() => setError(null)} />
          </div>
        )}
      </div>

      {/* Loading */}
      {loading && <LoadingState message="Parsing and analyzing log file…" />}

      {/* Results */}
      {result && (
        <ResultCard title="Log Analysis Report" badge={result.risk_level}>
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
