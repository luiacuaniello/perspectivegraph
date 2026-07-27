import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { ModelAttribution } from "./ModelAttribution";

// An AI answer reads with the same authority whichever backend wrote it, and the two
// supported backends are not interchangeable: the free path can be a small self-hosted
// model writing a risk briefing. These tests pin that the reader is always told which
// model they are reading, and that the text stays a fact rather than a verdict.

describe("ModelAttribution", () => {
  it("names the model that wrote the answer", () => {
    render(<ModelAttribution answer={{ answer: "…", provider: "anthropic", model: "claude-opus-5" }} />);
    expect(screen.getByText("claude-opus-5")).toBeInTheDocument();
  });

  it("names a small self-hosted model just as plainly - that is the case it exists for", () => {
    render(
      <ModelAttribution
        answer={{ answer: "…", provider: "huggingface", model: "meta-llama/Llama-3.1-8B-Instruct" }}
      />,
    );
    expect(screen.getByText("meta-llama/Llama-3.1-8B-Instruct")).toBeInTheDocument();
    expect(screen.getByText(/huggingface/)).toBeInTheDocument();
  });

  it("repeats that the answer is an estimate, not a measurement", () => {
    render(<ModelAttribution answer={{ answer: "…", provider: "anthropic", model: "claude-opus-5" }} />);
    expect(screen.getByText(/estimate rather than a measurement/)).toBeInTheDocument();
  });

  it("renders nothing when the backend named no model, rather than an empty label", () => {
    const { container } = render(<ModelAttribution answer={{ answer: "…", provider: "none", model: "" }} />);
    expect(container).toBeEmptyDOMElement();
  });
});
