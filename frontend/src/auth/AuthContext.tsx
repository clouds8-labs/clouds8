import { createContext, useContext, useState, type ReactNode } from "react";
import { authApi } from "../api/client";
import { clearStoredAuth, getStoredAuth, setStoredAuth } from "./authStorage";

interface AuthContextValue {
  isAuthenticated: boolean;
  login: (username: string, password: string) => Promise<void>;
  logout: () => void;
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [isAuthenticated, setIsAuthenticated] = useState(() => getStoredAuth() !== null);

  const login = async (username: string, password: string) => {
    const result = await authApi.login(username, password);
    setStoredAuth({ token: result.token, expiresAt: result.expires_at });
    setIsAuthenticated(true);
  };

  const logout = () => {
    clearStoredAuth();
    setIsAuthenticated(false);
  };

  return (
    <AuthContext.Provider value={{ isAuthenticated, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}
