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

## 公開サイト — 実動作動画を軸に再構成 2026-09-22

### 参照した実物（実際に開いて撮影、2026-09-22）

| 種別 | URL | 採用する原則 | 真似しない表現 |
|---|---|---|---|
| 第一線 | https://linear.app/ | 見出しは1文2行まで。上部に大きな余白。**実UIを大きく見せる** | 装飾のない黒背景そのままの模倣 |
| 第一線 | https://tailscale.com/ | 製品分類が近い。導線を用途別に分ける | 第一画面をCookieバナーと多段ナビで埋めること |
| 第一線 | https://www.voiceos.com/ | 機能名でなく成果（何が終わるか）で見出しを作る | 同社のモード名・コピー |
| 直接競合 | https://aona.ai/solutions/dlp-for-chatgpt/ | 合成例を明示し、保証しないと書く。送信前の瞬間を主役にする | 配色・レイアウト・文言。**「Book a demo」中心の導線** |
| 直接競合 | https://www.strac.io/blog/chatgpt-dlp-data-loss-prevention | 具体的な事故のパターンを言語化する | 記事を製品ページの代わりにすること |

**Aonaは既に「合成例」と明記し、保証しないと書いている。** したがって「正直であること」は
差別化にならない。残る差別化は2つだけで、サイトはこれを第一画面に置く。

1. **商談を経ずに3分で動く**（競合2社はいずれも Book a demo が主導線）
2. **自分の見逃し率0.30を数値で公開している**（5件調べて、公開している例は見つからなかった）

### 決めたこと

第一画面は「誰向けか／何ができるか／**実際の結果**／次の操作」を1画面に収める。
実際の結果は静止画ではなく**実アプリの画面収録**で見せる（`docs/site/VIDEO.md`）。
数値は実測4つだけを置く（0.19秒・外部送信0件・再現率0.30・MIT）。
主CTAは「3分で試す」1つ。GitHubと導入手順は副導線に下げる。

測定セクション `#proof` では、弱い数字（マイナンバー等0件）を良い数字と同じ大きさで出す。
赤で強調するのは検出できない範囲であって、検出できた件数ではない。

### 評価ループ（実ブラウザ・2言語×5幅×reduce/no-preference＝20通り）

- ラウンド1: 日本語の `.jp-phrase` が320pxで溢れた → 文節を短く分割。数値4つが1行に
  収まらず孤立 → 2×2グリッドへ。再実行で20/20合格。
- ラウンド2: **導入手順が動画と別のアプリを案内していた**（`.[workbench]` /
  `aisecure.workbench`）。動画は `aisecure.control`。`.[control]` に修正し、
  `python -m aisecure.control --help` が exit 0 で起動することを確認。
  併せて開始セクションの主CTAをGitHubからコマンド取得に変更（主CTAは1つ）。

未達・未実施: 人間の利用試験、実ユーザーの表示速度、Safari/Windowsでの目視、
X（API未接続のため配布未実施）。
