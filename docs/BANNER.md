# Banner assets

The CLI banner and the README hero are generated from a single source logo with
[chafa](https://github.com/hpjansson/chafa) and [figlet](http://www.figlet.org/).

Source: [`logo.svg`](logo.svg) — a shield + radar/scope emblem.

## Regenerate

```sh
# 1. Rasterize the vector logo
rsvg-convert -w 480 -h 560 docs/logo.svg -o /tmp/logo.png

# 2. Terminal banner (256-colour ANSI blocks) used by the CLI
chafa --size 26x13 --symbols block --colors 256 /tmp/logo.png \
  > netsec_auditor/data/logo.ans

# 3. Plain-ASCII emblem for the README (no colour, renders on GitHub)
chafa --size 22x11 --symbols ascii -c none /tmp/logo.png

# 4. Wordmark
figlet -f small "NetSec Auditor" > netsec_auditor/data/wordmark.txt
```

`logo.ans` and `wordmark.txt` are packaged as data files and printed by
`netsec-auditor --version` (and on the bare `netsec-auditor` invocation).
