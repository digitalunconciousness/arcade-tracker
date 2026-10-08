# Fonts

Served from this directory, never from a CDN, so the app works offline and leaks no
requests. Every file came from the same pinned `google/fonts` commit GATBOX uses
(`23e54b51ddffbc7713c583748e3bd86f62b1fa4a`), and the source files' sha256 sums match
GATBOX's bootstrap.

| File | Font | Licence | What was done to it |
|------|------|---------|---------------------|
| `chakra-petch-600-latin.woff2` | Chakra Petch SemiBold (display) | SIL OFL 1.1, `OFL-ChakraPetch.txt` | Subset to Latin + punctuation, arrows and the euro sign, then converted to WOFF2 with fontTools `pyftsubset` (78.6 KB TTF to 9.6 KB). Chakra Petch declares **no Reserved Font Name**, so a modified version may keep the name. |
| `ShareTechMono-Regular.ttf` | Share Tech Mono (body) | SIL OFL 1.1, `OFL-ShareTechMono.txt` | **Nothing.** Byte-identical to upstream (sha256 `9ceab1f8…a6732677`). The font reserves the name "Share", and the OFL forbids a *Modified Version* from using a Reserved Font Name. Whether a WOFF2 conversion or a subset counts as modification is a question for the OFL FAQ, which could not be checked when this was vendored (2026-10-08). Shipping the original file needs no interpretation, and at 43 KB it costs little. |

Both OFL texts must stay beside the fonts: the licence requires that it travels with them.

To rebuild the Chakra Petch subset:

    pyftsubset ChakraPetch-SemiBold.ttf --flavor=woff2 --layout-features='*' \
      --unicodes="U+0000-00FF,U+0131,U+0152-0153,U+02BB-02BC,U+02C6,U+02DA,U+02DC,U+0304,U+0308,U+0329,U+2000-206F,U+20AC,U+2122,U+2190-2199,U+2212,U+2215,U+FEFF,U+FFFD" \
      --output-file=chakra-petch-600-latin.woff2

The old files `orbitron-v35-latin.woff2`, `share-tech-mono-v16-latin.woff2` and `OFL.txt` belong
to the pre-redesign stylesheet (`static/css/cyberpunk.css`) and are deleted with it at the end of
the migration.
