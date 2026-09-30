import { useEffect, useRef, useState } from "react";

// A tiny "ⓘ" affordance with a hover/focus tooltip. Used to explain domain jargon
// (KEV, EPSS, Monte Carlo, choke point…) in plain language without cluttering the
// UI - so a first-time user can self-serve the meaning of every number on screen.
//
// A tap opens it too. Hover and focus were the only triggers, and on an iPhone neither
// happens: there is no hover, and Safari does not focus a button it taps - so every
// explanation on the dashboard was out of reach from a phone. The tap toggles it; a tap
// anywhere else, or Escape, closes it.
//
// The bubble exists only while it shows. It used to be laid out all the time, merely
// transparent, and a transparent box still counts as overflow: an icon near the right of a
// scrolling panel gave the panel a sideways scroll on a phone. It is centred under the icon
// and then nudged back inside the viewport, or an icon near the edge pushed half the
// explanation off-screen.
interface Props {
  text: string;
  className?: string;
}

const WIDTH = 224; // w-56
const MARGIN = 16; // the page gutter on a phone

// The horizontal room the bubble may use: the viewport less the gutter, narrowed by every
// scrolling panel it sits in. Clamping to the viewport alone still overflowed the Accuracy
// panel, whose content box ends a few pixels short of the gutter, by 4px.
function room(el: HTMLElement): [number, number] {
  let lo = MARGIN;
  let hi = (document.documentElement.clientWidth || window.innerWidth) - MARGIN;
  for (let p = el.parentElement; p; p = p.parentElement) {
    const s = getComputedStyle(p);
    if (!/auto|scroll|hidden/.test(`${s.overflowX} ${s.overflowY}`)) continue;
    const r = p.getBoundingClientRect();
    lo = Math.max(lo, r.left + parseFloat(s.paddingLeft || "0"));
    hi = Math.min(hi, r.left + p.clientWidth - parseFloat(s.paddingRight || "0"));
  }
  return [lo, hi];
}

export default function InfoTip({ text, className }: Props) {
  const [open, setOpen] = useState(false); // tapped or clicked
  const [peek, setPeek] = useState(false); // hovered, or focused from the keyboard
  const [shift, setShift] = useState(0);
  const root = useRef<HTMLSpanElement>(null);
  const button = useRef<HTMLButtonElement>(null);

  const place = () => {
    const b = button.current;
    if (!b) return;
    const r = b.getBoundingClientRect();
    const left = r.left + r.width / 2 - WIDTH / 2;
    const [lo, hi] = room(b);
    // Too narrow for the bubble at all: pin it to the left edge rather than both.
    if (left < lo || hi - lo < WIDTH) setShift(lo - left);
    else if (left + WIDTH > hi) setShift(hi - (left + WIDTH));
    else setShift(0);
  };

  useEffect(() => {
    if (!open && !peek) return;
    const outside = (e: PointerEvent) => {
      if (!root.current?.contains(e.target as Node)) setOpen(false);
    };
    const escape = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        setOpen(false);
        setPeek(false);
      }
    };
    document.addEventListener("pointerdown", outside);
    document.addEventListener("keydown", escape);
    return () => {
      document.removeEventListener("pointerdown", outside);
      document.removeEventListener("keydown", escape);
    };
  }, [open, peek]);

  return (
    <span
      ref={root}
      className={`relative inline-flex align-middle ${className ?? ""}`}
      onPointerEnter={() => {
        place();
        setPeek(true);
      }}
      onPointerLeave={() => setPeek(false)}
    >
      <button
        ref={button}
        type="button"
        aria-label={text}
        aria-expanded={open}
        onFocus={() => {
          place();
          setPeek(true);
        }}
        onBlur={() => setPeek(false)}
        onClick={(e) => {
          // An InfoTip can sit inside a clickable row or a <summary>; the tap is for the tip.
          e.preventDefault();
          e.stopPropagation();
          place();
          setOpen((o) => !o);
        }}
        className="grid h-3.5 w-3.5 cursor-help place-items-center rounded-full border border-slate-300 text-[12px] font-bold leading-none text-slate-500 transition hover:border-accent hover:text-accent focus:outline-hidden"
      >
        i
      </button>
      {(open || peek) && (
        <span
          role="tooltip"
          style={{ transform: `translateX(calc(-50% + ${shift}px))` }}
          className="pointer-events-none absolute left-1/2 top-full z-30 mt-1.5 w-56 rounded-lg border border-edge bg-slate-900/95 px-3 py-2 text-[12px] font-normal normal-case leading-relaxed tracking-normal text-slate-100 shadow-lg"
        >
          {text}
        </span>
      )}
    </span>
  );
}
