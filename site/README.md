# site

postern's own pages. Two self-contained HTML files, no build step and no
runtime dependencies — open them in a browser or copy the directory to
any static host.

- `index.html` — the landing page
- `docs/index.html` — the documentation

Both carry their CSS inline and load nothing from the network, so they
work from `file://` and behind an air gap. They follow the reader's
light/dark preference.

⚠️ **Every claim on these pages was checked against the code**, not
against what we intended to build: the CLI flags come from `--help`, the
dependency counts from `go.mod` and `package.json`, and the refusals from
the tests that enforce them. When you change behaviour, change the pages
in the same commit — a documentation page that overstates a security
property is worse than no page, because someone will deploy on it.

`docs/index.html#limits` is deliberately blunt about what postern does
*not* do. Keep it that way.
