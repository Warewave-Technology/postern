# site

postern's own pages. Two self-contained HTML files, no build step and no
runtime dependencies — open them in a browser or copy the directory to
any static host.

- `index.html` — the landing page
- `docs/index.html` — the documentation

Both carry their CSS inline and load nothing from the network, so they
work from `file://` and behind an air gap. The docs page carries one
small inline script — it marks the section you are reading in the side
list — and the page works without it: if the script never runs, the
list is still twenty-four working links. They follow the reader's
light/dark preference.

⚠️ **Do not strip the `<head>` block.** It was missing until 2026-09-02
and the pages were measurably broken because of it — checked in a
browser, not guessed:

    document.compatMode   → "BackCompat"     (quirks mode)
    document.characterSet → "windows-1252"   (not UTF-8)

Ninety non-ASCII characters — em dashes, arrows, `§` — rendered as
`â€"`. A host that sends `charset=utf-8` in the header hides this; one
that does not shows it to every visitor. `viewport` is the same kind of
load-bearing line: without it a phone lays the page out at desktop
width.

⚠️ **Every claim on these pages was checked against the code**, not
against what we intended to build: the CLI flags come from `--help`, the
dependency counts from `go.mod` and `package.json`, and the refusals from
the tests that enforce them. When you change behaviour, change the pages
in the same commit — a documentation page that overstates a security
property is worse than no page, because someone will deploy on it.

`docs/index.html#limits` is deliberately blunt about what postern does
*not* do. Keep it that way.
