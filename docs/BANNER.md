# Banner assets

The banner is built from one source logo with
[chafa](https://github.com/hpjansson/chafa), [figlet](http://www.figlet.org/),
and [rsvg-convert](https://gitlab.gnome.org/GNOME/librsvg).

Sources: [`logo.svg`](logo.svg) (shield + radar emblem) and the figlet wordmark.

## CLI banner (`netsec-auditor --version`)

```sh
# colour shield (256-colour ANSI blocks) + compact wordmark, packaged as data files
chafa --size 26x13 --symbols block --colors 256 docs/logo.png > netsec_auditor/data/logo.ans
figlet -f small "NetSec Auditor" > netsec_auditor/data/wordmark.txt
```

## README hero (renders crisply on GitHub, both themes)

GitHub's `<pre>` uses a loose line-height that pulls figlet ASCII apart, so the
README embeds **images** instead of live ASCII:

```sh
# crisp shield
rsvg-convert -w 400 -h 467 docs/logo.svg -o docs/logo.png

# slant wordmark rendered as an image with tight (terminal-like) line-height,
# so the letters stay connected — see the generator that writes docs/wordmark.svg,
# then rasterize it:
rsvg-convert -w 2040 docs/wordmark.svg -o docs/wordmark.png
```

`docs/logo.png` and `docs/wordmark.png` are embedded in `README.md`; `logo.ans`
and `wordmark.txt` are packaged and printed by the CLI banner.
