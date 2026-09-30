// The documentation site, published at https://docs.a3thinker.it.
//
// Its pages are generated from the repository's Markdown by scripts/sync-docs.mjs - the
// docs/ folder and the README stay the single source, and this only lays them out with
// navigation and search. The links validator fails the build on a link or an anchor that
// points nowhere, which is how a renamed heading gets caught before it reaches a reader.
import { defineConfig, passthroughImageService } from "astro/config";
import starlight from "@astrojs/starlight";
import starlightLinksValidator from "starlight-links-validator";

export default defineConfig({
  site: "https://docs.a3thinker.it",
  // The only images are the repository's own PNG and SVG files; nothing needs resizing, and
  // leaving the image service out keeps sharp - a native dependency - off the build.
  image: { service: passthroughImageService() },
  integrations: [
    starlight({
      title: "PerspectiveGraph",
      description:
        "Open-source attack-path analysis: from internet exposure, through privilege that is too broad, to a sensitive asset - caught in the pull request that opens it.",
      logo: { src: "./src/assets/logo.svg" },
      // The dashboard's own icon, on its dark tile, so a docs tab and a dashboard tab look alike.
      favicon: "/favicon.svg",
      social: [{ icon: "github", label: "GitHub", href: "https://github.com/luiacuaniello/perspectivegraph" }],
      // What a shared link shows (LinkedIn, Slack, chat apps): the dashboard's social card. The
      // title and the per-page description Starlight writes itself.
      head: [
        { tag: "meta", attrs: { property: "og:image", content: "https://docs.a3thinker.it/social-card.png" } },
        { tag: "meta", attrs: { property: "og:image:width", content: "1280" } },
        { tag: "meta", attrs: { property: "og:image:height", content: "640" } },
        {
          tag: "meta",
          attrs: { property: "og:image:alt", content: "PerspectiveGraph: Your scanners find issues. This finds the way in." },
        },
        { tag: "meta", attrs: { name: "twitter:card", content: "summary_large_image" } },
        // Starlight lets a wide table scroll sideways on a narrow screen, and a keyboard user can
        // scroll only a region that takes focus (WCAG 2.1.1; axe found every wide table on a
        // phone). Only tables that actually scroll become a tab stop, rechecked on resize. A
        // script rather than a rehype plugin: Astro 7's Markdown processor no longer runs them
        // without another dependency, and this is one attribute.
        {
          tag: "script",
          content: `(() => {
  const mark = () => {
    for (const t of document.querySelectorAll(".sl-markdown-content table")) {
      if (t.scrollWidth > t.clientWidth) t.tabIndex = 0;
      else t.removeAttribute("tabindex");
    }
  };
  addEventListener("DOMContentLoaded", mark);
  addEventListener("resize", mark);
})();`,
        },
      ],
      customCss: ["./src/styles/custom.css"],
      // Local links are instructions ("open http://localhost:3000"), not broken pages.
      plugins: [starlightLinksValidator({ errorOnLocalLinks: false })],
      // Grouped by what a reader has come to do, in the order they usually need it: what this is,
      // using it, believing its numbers, running it, and the project around it.
      sidebar: [
        {
          label: "Start here",
          items: [
            { label: "Introduction", link: "/" },
            "overview",
            "manual/concepts",
            "manual/quick-start",
            { label: "Live demo", link: "https://demo.a3thinker.it", attrs: { target: "_blank", rel: "noopener" } },
            "evaluation",
          ],
        },
        {
          label: "Use it",
          items: ["manual/ci-gate", "manual/integrations", "manual/working-the-findings", "manual/ai-and-mcp", "manual/onboarding"],
        },
        {
          label: "Understand the numbers",
          items: ["manual/how-it-works", "manual/scoring", "manual/accuracy", "positioning"],
        },
        {
          label: "Run it",
          items: ["manual/kubernetes", "manual/security", "manual/running", "operations", "scale", "upgrading"],
        },
        {
          label: "Reference",
          items: [{ label: "The whole manual", slug: "manual" }, "api-stability", "threat-model", "security-policy"],
        },
        {
          label: "Project",
          items: ["roadmap", "support", "contributing", "adopters", "governance"],
        },
      ],
    }),
  ],
});
