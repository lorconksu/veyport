# Documentation diagram assets

Documentation embeds PNG images rather than inline Mermaid blocks. Preserve the
illustrated blue-and-white format of `docs/screenshots/veyport-architecture.png`
when updating the overview. Update its contents rather than replacing it with a
code diagram. The README and architecture wiki share that image.

All flow and sequence diagrams use a shared style matching the overview: navy
and blue gradient cards, white text and component icons, rounded pale blue group
panels, strong navy arrows, white backgrounds, and centered descriptive titles.
The shared styling lives in `scripts/doc-diagram-style.mjs`; change it there and
regenerate every diagram to keep their appearance consistent. Their editable topology is stored in `.mmd`
files here. `manifest.json` maps those sources to their PNG images. Generated SVG
files live alongside the PNGs as editable vector exports.

From the repository root, after installing the frontend dependencies, regenerate
the reference diagrams with:

```bash
node scripts/render-doc-diagrams.mjs
# Include internal documentation when present locally:
node scripts/render-doc-diagrams.mjs docs/diagrams/manifest.json docs-internal/diagrams/manifest.json
```

The renderer uses the project's Mermaid and JSDOM packages, Python 3, system
`librsvg-2`, Cairo, and DejaVu Sans fonts. It works without a browser or network
connection. Text measurements are estimated, so visually check spacing, labels,
and arrows after changing a source. Keep URLs and commands intact when wrapping
labels. The illustrated overview is maintained separately and is not overwritten
by this command; `architecture.mmd` records its topology.

The GitHub wiki sync workflow copies the public PNGs from `docs/screenshots/` and
rewrites wiki-relative image paths. Keep public diagram assets there. Internal
source files and exports remain under the ignored `docs-internal/` tree and are
not published by the wiki workflow.
