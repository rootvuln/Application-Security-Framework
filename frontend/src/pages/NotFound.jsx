
import { Link } from "react-router-dom";

export default function NotFound() {
  return (
    <div className="p-6">
      <h2 className="text-2xl font-bold">Page not found</h2>

      <p className="mt-2 text-slate-400">
        The page you are looking for does not exist.
      </p>

      <Link
        className="mt-4 inline-block text-cyan-400 hover:text-cyan-300"
        to="/"
      >
        Return to dashboard
      </Link>
    </div>
  );
}
