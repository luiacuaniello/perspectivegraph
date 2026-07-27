import type { AIAnswer } from "../api/client";

// Names the model that wrote an answer, under the answer.
//
// Prose reads with the same authority whichever backend produced it, and the two
// supported backends are not interchangeable: the free path can be a small self-hosted
// model writing a risk briefing. Showing the model id lets the reader weigh the text;
// leaving it out would be the same false confidence the engine refuses to produce for a
// score it cannot back up.
//
// Deliberately factual and unstyled-by-verdict: no badge colour ranking the provider, no
// warning icon on the cheaper one. It states what answered and lets the reader judge.
export function ModelAttribution({ answer }: { answer: AIAnswer }) {
  if (!answer.model) return null;
  return (
    <p className="mt-2 text-[11px] text-slate-500">
      Written by <span className="font-medium text-slate-600">{answer.model}</span>
      {answer.provider && <span className="text-slate-400"> · {answer.provider}</span>} · grounded in your current
      attack paths, and an estimate rather than a measurement
    </p>
  );
}
