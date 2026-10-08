import { useState, type FormEvent } from "react";
import { useNavigate } from "react-router-dom";
import { Button } from "../components/Button";
import { useAuth } from "../auth/AuthContext";

export function Login() {
  const { login } = useAuth();
  const navigate = useNavigate();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      await login(username, password);
      navigate("/", { replace: true });
    } catch {
      setError("Incorrect username or password.");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="flex h-screen w-screen bg-lm-bg text-lm-text font-ui">
      <div className="hidden lg:flex flex-col justify-center flex-1 px-16 border-r border-lm-line">
        <div className="flex items-center gap-2 mb-10">
          <span className="text-xl">🐱</span>
          <span className="font-display font-semibold text-lg tracking-tight">clouds8</span>
        </div>
        <h1 className="font-display text-4xl font-semibold leading-tight max-w-md">
          See the path before someone else walks it.
        </h1>
        <p className="text-lm-dim mt-4 max-w-sm">
          Inventory every cloud asset, score it on one scale, and read the attack paths between them as a graph.
        </p>
      </div>
      <div className="flex flex-col justify-center flex-1 px-8 lg:px-16 max-w-md mx-auto w-full">
        <h2 className="text-2xl font-display font-semibold mb-1">Sign in</h2>
        <p className="text-lm-dim text-sm mb-6">Enter the admin credentials to continue.</p>
        <form onSubmit={handleSubmit} className="flex flex-col gap-4">
          <div>
            <label className="block text-xs uppercase tracking-wider text-lm-dim mb-1.5">Username</label>
            <input
              type="text"
              autoComplete="username"
              placeholder="admin"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="w-full rounded-md border border-lm-line bg-lm-panel-2 px-3 py-2 text-sm focus:outline-none focus:border-lm-accent"
            />
          </div>
          <div>
            <label className="block text-xs uppercase tracking-wider text-lm-dim mb-1.5">Password</label>
            <input
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full rounded-md border border-lm-line bg-lm-panel-2 px-3 py-2 text-sm focus:outline-none focus:border-lm-accent"
            />
          </div>
          {error && <div className="text-sm text-lm-critical">{error}</div>}
          <Button type="submit" variant="primary" disabled={submitting} className="justify-center mt-2">
            {submitting ? "Signing in…" : "Continue"}
          </Button>
        </form>
      </div>
    </div>
  );
}
