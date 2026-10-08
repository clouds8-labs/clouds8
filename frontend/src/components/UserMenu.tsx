import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../auth/AuthContext";

export function UserMenu() {
  const [open, setOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);
  const { logout } = useAuth();
  const navigate = useNavigate();

  useEffect(() => {
    if (!open) return;
    const onClickOutside = (e: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", onClickOutside);
    return () => document.removeEventListener("mousedown", onClickOutside);
  }, [open]);

  const handleLogout = () => {
    logout();
    navigate("/login", { replace: true });
  };

  return (
    <div className="relative" ref={menuRef}>
      <button
        onClick={() => setOpen((v) => !v)}
        aria-label="User menu"
        className="flex items-center justify-center rounded-full p-2 text-lm-text hover:bg-lm-panel-2 transition-colors"
      >
        <span className="text-base opacity-80">👤</span>
      </button>

      {open && (
        <div className="absolute right-0 top-full mt-2 w-40 rounded-md border border-lm-line bg-lm-panel shadow-xl z-50 py-1">
          <button
            onClick={handleLogout}
            className="w-full text-left px-3 py-2 text-sm text-lm-text hover:bg-lm-panel-2 transition-colors"
          >
            Log out
          </button>
        </div>
      )}
    </div>
  );
}
