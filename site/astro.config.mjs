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
      social: [{ icon: "github", label: "GitHub", href: "https://github.com/luiacuaniello/perspectivegraph" }],
      customCss: ["./src/styles/custom.css"],
      // Local links are instructions ("open http://localhost:3000"), not broken pages.
      plugins: [starlightLinksValidator({ errorOnLocalLinks: false })],
      sidebar: [
        {
          label: "Start here",
          items: [
            { label: "Overview", link: "/" },
            "manual/quick-start",
            "evaluation",
            "positioning",
          ],
        },
        {
          label: "Manual",
          items: [
            { label: "Contents", slug: "manual" },
            "manual/how-it-works",
            "manual/scoring",
            "manual/accuracy",
            "manual/ci-gate",
            "manual/integrations",
            "manual/working-the-findings",
            "manual/ai-and-mcp",
            "manual/onboarding",
          ],
        },
        {
          label: "Run it",
          items: [
            "manual/kubernetes",
            "manual/security",
            "manual/running",
            "operations",
            "scale",
            "upgrading",
          ],
        },
        {
          label: "Reference",
          items: ["api-stability", "threat-model", "security-policy", "contributing"],
        },
      ],
    }),
  ],
});
