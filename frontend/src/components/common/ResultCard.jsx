/**
 * ResultCard – dark-themed card container.
 * Props:
 *   title      (string)           – card heading
 *   children                      – card body content
 *   badge      (string, optional) – risk_level / label shown as a colored pill
 *   badgeColor (string, optional) – Tailwind color class override (e.g. "text-red-400 bg-red-500/10 border-red-500/25")
 */

const BADGE_COLORS = {
  critical: "border-red-500/40 bg-red-500/15 text-red-400",
  high: "border-orange-500/40 bg-orange-500/15 text-orange-400",
  medium: "border-yellow-500/40 bg-yellow-500/15 text-yellow-400",
  low: "border-blue-400/40 bg-blue-400/15 text-blue-400",
  info: "border-slate-500/40 bg-slate-500/15 text-slate-400",
  unknown: "border-slate-600/40 bg-slate-600/15 text-slate-500",
};

export default function ResultCard({ title, children, badge, badgeColor }) {
  const resolvedBadgeColor =
    badgeColor ||
    BADGE_COLORS[(badge || "").toLowerCase()] ||
    BADGE_COLORS.unknown;

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-950 p-5">
      <div className="mb-4 flex items-center justify-between gap-3">
        <h3 className="text-sm font-semibold text-slate-200">{title}</h3>
        {badge && (
          <span
            className={`rounded-full border px-2.5 py-0.5 text-xs font-semibold uppercase tracking-wide ${resolvedBadgeColor}`}
          >
            {badge}
          </span>
        )}
      </div>
      <div>{children}</div>
    </div>
  );
}
