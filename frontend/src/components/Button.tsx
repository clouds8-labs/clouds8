import type { ButtonHTMLAttributes, ReactNode } from "react";

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: "primary" | "secondary" | "destructive";
  children: ReactNode;
}

const VARIANT_CLASS: Record<NonNullable<ButtonProps["variant"]>, string> = {
  primary: "bg-lm-accent text-lm-bg hover:brightness-110 disabled:bg-lm-line disabled:text-lm-dim",
  secondary: "bg-transparent border border-lm-line text-lm-text hover:border-lm-dim disabled:text-lm-dim",
  destructive: "bg-transparent border border-lm-critical text-lm-critical hover:bg-lm-critical/10 disabled:border-lm-line disabled:text-lm-dim",
};

export function Button({ variant = "secondary", className = "", disabled, children, ...rest }: ButtonProps) {
  return (
    <button
      disabled={disabled}
      className={`inline-flex items-center gap-2 rounded-md px-3.5 py-2 text-sm font-medium font-ui transition-colors disabled:cursor-not-allowed ${VARIANT_CLASS[variant]} ${className}`}
      {...rest}
    >
      {children}
    </button>
  );
}
