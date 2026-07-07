import type { ButtonHTMLAttributes, ReactNode } from "react";

type Variant = "primary" | "secondary" | "ghost" | "danger";
type Size = "sm" | "md";

const VARIANT: Record<Variant, string> = {
  primary: "bg-accent text-white hover:bg-accent-strong active:opacity-90 disabled:hover:bg-accent",
  secondary:
    "border border-edge bg-panel text-slate-600 hover:border-accent/50 hover:text-accent hover:bg-accent-soft/60",
  ghost: "text-muted hover:bg-ink hover:text-slate-700",
  danger: "border border-red-500/40 bg-red-500/10 text-red-700 hover:bg-red-500/20",
};

const SIZE: Record<Size, string> = {
  sm: "h-7 px-2.5 text-[11px] gap-1.5 rounded-md",
  md: "h-9 px-3.5 text-[13px] gap-2 rounded-lg",
};

type CommonProps = {
  variant?: Variant;
  size?: Size;
  icon?: ReactNode;
  children?: ReactNode;
  className?: string;
};

// Button is the one button vocabulary for the app - a filled primary, a bordered
// secondary, a quiet ghost, and a danger. Pass `href` to render an anchor (for
// downloads/links) with identical styling, so visual consistency never depends
// on remembering a class string.
export default function Button({
  variant = "secondary",
  size = "sm",
  icon,
  children,
  className = "",
  href,
  download,
  target,
  rel,
  title,
  ...rest
}: CommonProps &
  ButtonHTMLAttributes<HTMLButtonElement> & {
    href?: string;
    download?: string | boolean;
    target?: string;
    rel?: string;
  }) {
  const cls = `inline-flex items-center justify-center font-medium tracking-tight transition disabled:cursor-not-allowed disabled:opacity-50 ${SIZE[size]} ${VARIANT[variant]} ${className}`;
  if (href) {
    // The anchor branch carries title (tooltip) explicitly - it is NOT in ...rest,
    // which is only spread on the button, so a link Button keeps its tooltip.
    return (
      <a href={href} download={download} target={target} rel={rel} title={title} className={cls}>
        {icon}
        {children}
      </a>
    );
  }
  return (
    <button className={cls} title={title} {...rest}>
      {icon}
      {children}
    </button>
  );
}
