// Pure localStorage helpers for the admin session token - no React, no
// dependency on api/client.ts, so both that module and AuthContext.tsx can
// import this without a circular import between them.
const STORAGE_KEY = "clouds8_auth";

export interface StoredAuth {
  token: string;
  expiresAt: string;
}

export function getStoredAuth(): StoredAuth | null {
  const raw = localStorage.getItem(STORAGE_KEY);
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw) as StoredAuth;
    if (!parsed.token || !parsed.expiresAt) return null;
    if (new Date(parsed.expiresAt).getTime() <= Date.now()) return null;
    return parsed;
  } catch {
    return null;
  }
}

export function getStoredToken(): string | null {
  return getStoredAuth()?.token ?? null;
}

export function setStoredAuth(auth: StoredAuth): void {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(auth));
}

export function clearStoredAuth(): void {
  localStorage.removeItem(STORAGE_KEY);
}
