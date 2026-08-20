import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { useAuth } from "../context/AuthContext";

function Navbar() {
  const [scrollOpacity, setScrollOpacity] = useState(0);
  const { user, isAuthenticated, logout } = useAuth();

  // No explicit navigate() here: ProtectedRoute already redirects to /login
  // the instant isAuthenticated flips false, so an extra navigate("/") would
  // race it and produce dueling replace() navigations.
  const handleLogout = () => {
    logout();
  };

  useEffect(() => {
    const handleScroll = () => {
      setScrollOpacity(Math.min(window.scrollY / 150, 1));
    };

    handleScroll();
    window.addEventListener("scroll", handleScroll);

    return () => window.removeEventListener("scroll", handleScroll);
  }, []);

  const navbarStyle = {
    background: `rgba(10, 12, 35, ${0.05 + scrollOpacity * 0.35})`,
    backdropFilter: `blur(${scrollOpacity * 22}px)`,
    WebkitBackdropFilter: `blur(${scrollOpacity * 22}px)`,
  };

  return (
    <nav
      style={navbarStyle}
      className="fixed top-0 left-0 z-[1000] flex h-[82px] w-full items-center justify-between border-b border-white/5 px-[70px] max-[1000px]:px-[36px] max-[900px]:h-[72px] max-[900px]:px-[24px]"
    >
      <div className="shrink-0 whitespace-nowrap text-[30px] leading-none font-extrabold tracking-[-1px] text-white select-none max-[900px]:text-[24px]">
        Maxim<span className="text-[#7c5cff]">ReconForge</span>
      </div>

      <div className="flex items-center gap-[34px] text-[15px] font-semibold max-[900px]:hidden">
        <a
          href="#product"
          className="whitespace-nowrap text-white/80 no-underline transition-colors hover:text-white"
        >
          Product
        </a>

        <a
          href="#pipeline"
          className="whitespace-nowrap text-white/80 no-underline transition-colors hover:text-white"
        >
          Pipeline
        </a>

        <a
          href="#docs"
          className="whitespace-nowrap text-white/80 no-underline transition-colors hover:text-white"
        >
          Docs
        </a>

        <a
          href="#pricing"
          className="whitespace-nowrap text-white/80 no-underline transition-colors hover:text-white"
        >
          Pricing
        </a>

        <a
          href="#scan"
          className="inline-flex h-[38px] shrink-0 items-center justify-center whitespace-nowrap rounded-full bg-white px-[18px] text-[14px] leading-none font-bold text-[#181468] no-underline transition hover:-translate-y-px hover:bg-[#f5f7ff]"
        >
          Start Scan
        </a>

        {isAuthenticated ? (
          <div className="flex items-center gap-3">
            <span className="whitespace-nowrap text-white/60">{user?.email}</span>
            <button
              type="button"
              onClick={handleLogout}
              className="whitespace-nowrap text-white/80 transition-colors hover:text-white"
            >
              Log out
            </button>
          </div>
        ) : (
          <div className="flex items-center gap-3">
            <Link
              to="/login"
              className="whitespace-nowrap text-white/80 no-underline transition-colors hover:text-white"
            >
              Log in
            </Link>
          </div>
        )}
      </div>
    </nav>
  );
}

export default Navbar;