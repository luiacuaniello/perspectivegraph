# Documentation site

The source of [docs.a3thinker.it](https://docs.a3thinker.it): an [Astro Starlight](https://starlight.astro.build)
site built from the repository's own Markdown.

There is almost nothing to write here. The pages are the README and the files in `docs/` - edit
those, as before, and the site follows on the next merge to `main`. `scripts/sync-docs.mjs`
copies them into `src/content/docs/` at build time, turning links between documents into
links between pages and links into the code into links to GitHub; that folder is generated
and ignored by git.

```bash
cd site
npm ci
npm run dev      # http://localhost:4321, rebuilt from the Markdown on start
npm run build    # what CI runs: fails on any link or anchor that points nowhere
```

The front page, `landing/index.mdx`, is the one page written here: it only points into the
others, so nothing on it can go stale on its own. `public/favicon.svg` is the dashboard's icon.

A new document needs one line in `PAGES` in `scripts/sync-docs.mjs` and one in the sidebar
in `astro.config.mjs`. `.github/workflows/docs.yml` builds the site on every pull request
that touches the documentation and publishes it to GitHub Pages from `main`.
