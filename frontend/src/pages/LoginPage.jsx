import { useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";

function LoginPage() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);

  const { login } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const redirectTo = location.state?.from?.pathname || "/scan";

  const handleSubmit = async (event) => {
    event.preventDefault();
    if (isSubmitting) return;

    setError("");
    setIsSubmitting(true);
    try {
      await login(email, password);
      navigate(redirectTo, { replace: true });
    } catch (err) {
      setError(err.message || "Login failed");
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <section className="flex min-h-screen items-center justify-center px-6 pt-[100px] pb-16">
      <div className="w-[400px] max-w-full rounded-[22px] border border-white/8 bg-[rgba(15,19,40,0.72)] p-9 backdrop-blur-[18px]">
        <h1 className="text-[26px] font-extrabold tracking-[-1px]">Log in</h1>
        <p className="mt-2 text-[14px] text-[#a7aec8]">
          Access your MaximReconForge engagements.
        </p>

        <form onSubmit={handleSubmit} className="mt-7 flex flex-col gap-4">
          <input
            type="email"
            required
            placeholder="Email"
            value={email}
            onChange={(event) => setEmail(event.target.value)}
            className="rounded-xl border border-white/10 bg-white/[0.06] px-4 py-3 text-[15px] text-white outline-none placeholder:text-white/40 focus:border-[#7c5cff]/50"
          />
          <input
            type="password"
            required
            placeholder="Password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            className="rounded-xl border border-white/10 bg-white/[0.06] px-4 py-3 text-[15px] text-white outline-none placeholder:text-white/40 focus:border-[#7c5cff]/50"
          />

          {error && <p className="text-[13px] text-[#ff6b6b]">{error}</p>}

          <button
            type="submit"
            disabled={isSubmitting}
            className="mt-2 rounded-full bg-white px-5 py-3 text-[14px] font-bold text-[#181468] transition hover:-translate-y-px hover:bg-[#f5f7ff] disabled:cursor-not-allowed disabled:opacity-60"
          >
            {isSubmitting ? "Logging in..." : "Log in"}
          </button>
        </form>

        <p className="mt-6 text-center text-[13px] text-[#a7aec8]">
          Private deployment — no new registrations possible.
        </p>
      </div>
    </section>
  );
}

export default LoginPage;
