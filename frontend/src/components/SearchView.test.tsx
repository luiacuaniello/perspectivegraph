import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import SearchView from "./SearchView";

describe("SearchView", () => {
  it("shows a clear disabled state (not a false 'no results') when search is off", () => {
    render(<SearchView enabled={false} />);
    expect(screen.getByText(/Full-text search is off/i)).toBeInTheDocument();
    // It must NOT render the query input in the disabled state.
    expect(screen.queryByPlaceholderText(/Search assets/i)).toBeNull();
  });

  it("renders the search box when enabled", () => {
    render(<SearchView enabled={true} />);
    expect(screen.getByPlaceholderText(/Search assets/i)).toBeInTheDocument();
  });
});
