# AISecure — design

White and deep green. A selected observation opens the actual evidence behind a synthetic finding; hypotheses and unknowns remain visible.

Three alternatives under candidates/ use the same copy and evidence. At 1440×1000: A places the 1192px-wide case below the copy at y594; B places a 760px case next to the copy at y151; C places a 1192px case above the copy, moving the CTA to y894. **B adopted**: product purpose, an actionable observation and the limitation stay together in the initial viewport. This is a layout comparison, not a conversion experiment.

Body 18px desktop, 17px mobile; primary controls at least 48px; content maximum 1240px. User-initiated playback; reduced motion preserves content.
References: https://developers.openai.com/showcase/watchmaker-landing-page and https://developers.openai.com/showcase/frame-studio . Only design principles were borrowed, not assets or brand expression.

## Local control workbench — skill follow-up 2026-09-19

This is a focused refinement of the existing light local workbench, not a new
marketing design. Preserve its navy controls and white surfaces. No new fonts,
images, framework, motion or visual-reference imitation.

Task order: edit input → inspect locally → read verdict/coverage → save report.
Observed before: result is below all input, save precedes result, and errors only
appear beneath advanced sections. Separate AI first-use review reproduced the
error distance. Adopt a desktop input/result split with the same DOM order on
mobile; keep the save action with the report and validation feedback with inspect.
A fully modal wizard was rejected: it would hide the relationship between source
and evidence. A full-width dashboard would add unrelated material to this task.

Signature: a plain evidence sheet with a verdict, explicit no-send state, then
coverage and rule explanations. Review uses amber, block uses dark red, neither
signals external safety. Color never replaces text. Empty result explains what
will appear; processing/error are distinct from completed inspection.

CSS tokens in control/web/app.css: text #172337, muted #4b596c, accent #20364f,
focus #17649b, surface #fff, border #dce2ea; spacing 8/12/16/24/32px,
body 16px/1.65, headings 20–32px, native control minimum 44px. Input/result split
only at >=960px, otherwise source order. System fonts; no assets or animation
budget (zero new network resources). Verify 360/390/768/1440 and CSS 200%; genuine
browser zoom and native IME require separate recorded execution.

## Public homepage — obsidian theme 2026-09-22

Dark rethemed at the user's request, referencing https://www.obsidianui.dev . Only
principles were taken: dark glass surfaces, a dotted-grid ground, spotlight cards,
a glowing scroll indicator, a magnetic tab rail and flow-scroll reveals. No code,
component, asset, font or brand expression was copied, and neither React, Next,
Tailwind nor Motion was introduced — the motifs are reimplemented in plain CSS and
DOM APIs, so the page still loads zero third-party resources.

`docs/obsidian.css` and `docs/obsidian.js` are a third theme layer over
`home.css` → `home-refine.css`. They change colour, texture, radius and motion
only. Layout, type scale, the crop offsets on the real workbench capture and the
`html[lang="ja"] .jp-phrase` line-breaking rules stay in `home-refine.css`, so the
recorded 320/390/768/1024/1440 checks remain comparable rather than re-baselined.

Tokens: paper #07080b, surface #0c0e13, raised #11141b, ink #eef1f6,
muted #98a1b2, line #1d212b, edge #272c38, accent #54e0b2 over #1d8f72,
block #ff7a7a, review #f5c26b; radius 16px for panels and 10px for controls.
The product captures are real light screenshots and are never recoloured or
filtered: they are framed and given a halo so they read as objects on the page.

Every script effect is decoration and degrades to the flat dark page: the reveal
state is only applied by JavaScript and only inside
`@media (prefers-reduced-motion: no-preference)`, the spotlight is bound to fine
pointers, and the tab rail hides itself if it cannot measure, leaving the selected
tab styled on its own. Verified locally with Chromium at five widths in both
languages under `reduce` and `no-preference`: no horizontal overflow, no JS
errors, no 4xx, no POST, sample tabs and keyboard `End` unchanged, Japanese
phrases still unwrapped, and nothing left invisible in view.
