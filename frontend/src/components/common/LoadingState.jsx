import { Loader2 } from "lucide-react";

/**
 * LoadingState – centered spinner with optional message.
 * Props:
 *   message  (string, optional) – text shown below the spinner
 */
export default function LoadingState({ message = "Analyzing…" }) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 py-12 text-slate-400">
      <Loader2 size={30} className="animate-spin text-cyan-400" />
      {message && (
        <p className="text-sm">{message}</p>
      )}
    </div>
  );
}
