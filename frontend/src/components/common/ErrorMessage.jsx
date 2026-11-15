import { AlertCircle, X } from "lucide-react";

/**
 * ErrorMessage – red-tinted error box.
 * Props:
 *   message   (string)            – error text to display
 *   onDismiss (function, optional) – called when user clicks ✕
 */
export default function ErrorMessage({ message, onDismiss }) {
  return (
    <div className="flex items-start gap-3 rounded-lg border border-red-500/25 bg-red-500/10 px-4 py-3 text-sm text-red-400">
      <AlertCircle size={16} className="mt-0.5 shrink-0" />
      <span className="flex-1 leading-5">{message}</span>
      {onDismiss && (
        <button
          onClick={onDismiss}
          className="shrink-0 rounded p-0.5 transition hover:bg-red-500/20"
          aria-label="Dismiss error"
        >
          <X size={14} />
        </button>
      )}
    </div>
  );
}
