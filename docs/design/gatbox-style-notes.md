# GATBOX style notes (reference for the tracker redesign)

Read from the public GATBOX repo: `CLAUDE.md` ("Design tokens (any UI)" and hard rule 10), `BRINGUP.md`
(M5 notes), `web/dash/{index.html,dash.css,dash.js,chart.js}` (the 7" kiosk dashboard) and
`backend/gatboxweb/phone.py` (the phone view's inline CSS). This page is a summary, not a copy. Where the
house palette in the redesign brief and the GATBOX CSS disagree, the GATBOX CSS wins. They agree: every
house colour and both fonts appear verbatim in `dash.css`.

## 1. Colour tokens

Both GATBOX stylesheets declare the same custom properties on `:root`:

| Token     | Value     | Role in GATBOX                                                        |
|-----------|-----------|-----------------------------------------------------------------------|
| `--bg`    | `#150a28` | page background (bottom of the gradient), inset stat boxes, inputs    |
| `--bg2`   | `#1f0f3d` | top of the body gradient, sheets/dialogs, toast                        |
| `--panel` | `#1f1240` | cards, buttons, tiles                                                 |
| `--line`  | `#3d1e6b` | every 1px border and divider, scrollbar thumb                         |
| `--mag`   | `#ff2e9f` | primary: brand mark, active nav/tab, selected row/tile, primary button |
| `--cyan`  | `#7dfaff` | secondary: links, chips, info banners, focus outline (phone view)     |
| `--ok`    | `#5ef2b0` | OK / live / in-window (lime)                                          |
| `--bad`   | `#ff4d6d` | trip / danger / fault, destructive hold buttons                        |
| `--warn`  | `#ffb74d` | warning (amber)                                                       |
| `--fg`    | `#ece3ff` | body text                                                             |
| `--mut`   | `#9080b0` | secondary text, labels, disabled                                       |

Body background is `linear-gradient(180deg, var(--bg2), var(--bg))` fixed. Tinted surfaces are
the status colour at low alpha with a full-strength border, for example
`.banner.warn { background: rgba(255,183,77,.14); color: var(--warn); border-color: var(--warn) }`.
The same pattern is used for info (cyan at .08), bad (red at .16) and dim (mut at .08).

### Measured contrast (WCAG 2.x)

| Text token | on `--bg` | on `--bg2` | on `--panel` |
|------------|-----------|------------|--------------|
| `--fg`     | 15.4      | 14.2       | 14.0         |
| `--cyan`   | 15.4      | 14.2       | 13.9         |
| `--ok`     | 13.4      | 12.4       | 12.2         |
| `--warn`   | 11.0      | 10.2       | 10.0         |
| `--bad`    | 5.9       | 5.5        | 5.4          |
| `--mag`    | 5.6       | 5.2        | 5.0          |
| `--mut`    | 5.3       | 4.9        | 4.8          |
| `--line`   | 1.4       | 1.3        | 1.3          |

- Every text token passes AA (4.5:1) on every surface. `--mut` on `--panel` is the closest at 4.8.
- `--fg` text on a filled `--mag` button is **2.8:1, a fail**. The GATBOX phone view gets this right by
  putting `--bg` text on magenta (5.6:1). The tracker must do the same for filled primary buttons.
- `--line` is 1.4:1. That's fine for decorative dividers but **fails the 3:1 non-text rule** when it's the only
  edge of an input or button. The tracker needs a stronger border token for form controls.

## 2. Typography

- **Display:** Chakra Petch SemiBold (600) only. Used for buttons, headings, the brand, big numbers
  (`.big`, `.verdict`, `.stat b`, `#m-value`) and banners. Headings use `letter-spacing: .03–.06em`.
  Section labels (`h3`) are 14px uppercase in `--mut` with .06em tracking.
- **Body:** Share Tech Mono Regular, 15px/1.35 on the dash and 15px/1.45 on the phone view. Small print
  (`small`, `.badge`, `.tag`, table headers) is 11–13px mono, and table headers are uppercase in `--mut`.
- Fallback stacks: `"Chakra Petch", system-ui, sans-serif` and `"Share Tech Mono", ui-monospace, monospace`.
- Fonts are **served by the device, never a CDN** (hard rule 10). The bootstrap fetches the TTFs plus their
  `OFL.txt` from a pinned `google/fonts` commit and checks each one's sha256. `font-display: swap` is set.
- Scale in use: 11 / 12 / 13 / 14 / 15 / 17–19 (buttons, h2) / 22–24 (verdict, brand) / 28–32 (big) /
  64–96 (hero reading).

## 3. Spacing, shape and layout

- Gaps step 6 → 8 → 10 → 12 → 14px. Card padding is `10px 12px` (dash) or `12px 14px` (phone).
- Radius: 8px on cards, buttons, banners and chart boxes, 6px on inset stat boxes, 4px on badges and tags,
  999px on chips, 10px on sheets.
- Borders are always 1px. Elevation comes from a lighter surface plus a border, never a drop shadow.
- Touch: `--tap: 56px` minimum on the kiosk, with 64px nav buttons, 48–54px small controls and 40px "mini"
  buttons. The phone view is less strict: its buttons are about 36px tall.
- The kiosk layout is a 52px header row, a 112px vertical nav rail and a non-scrolling main area. At or below
  760px it stacks: sticky header, then a horizontally scrolling sticky nav row, then scrolling main.
- Lists use `.grid` (`auto-fill, minmax(250px,1fr)`) and `.stat` (`minmax(140px,1fr)`), with a list/detail
  `.split` that stacks on phones.

## 4. Effects: glow and scanlines

- **Scanlines:** a fixed `body::before` overlay,
  `repeating-linear-gradient(0deg, rgba(0,0,0,.18) 0 1px, transparent 1px 3px)`, with
  `pointer-events: none` (.22 alpha on the phone view).
- **Glow is rationed** ("glow only on badges / active states / headline edges"). It appears on:
  - the brand (`text-shadow` in magenta at .55)
  - the active nav button and selected tile or segment (magenta inset glow at .35)
  - live dots and `.badge.glow` (`box-shadow: 0 0 8px currentColor`)
  - the hero reading (cyan at .25)
  - the armed hold button (red)
  - the toast (cyan at .25)

  Body text, cards and ordinary buttons never glow.
- **Motion:** the live dot pulses (.4s), the keypad cursor blinks and the hold bar fills with a linear width
  transition. Nothing else moves.

## 5. Components

| Component | GATBOX implementation | Notes for the tracker |
|-----------|----------------------|-----------------------|
| **Header** | brand `GATBOX<b>//</b>` (magenta slashes), unit id, then right-aligned status: log dot, net, clock, source badge | Tracker header: brand, then user/role and status right-aligned |
| **Nav / tabs** | big stacked buttons, `.on` = magenta border, text and inset glow; `.dim` = 40% when the feature is unavailable; `<small>` subtitle under the label | Use the same `.on` treatment for the current page in the nav and for in-page tabs |
| **Buttons** | panel fill, line border, Chakra 600 17px, 8px radius. `:active` turns the border magenta, `:disabled` is 38% opacity. Variants: `.primary` (magenta border), `.act` (two-line with a `<small>` hint), `.mini`, `.hold` (press-and-hold with a red fill bar for destructive actions) | Add a filled primary (magenta with `--bg` text), and use `.hold` or a confirm step for deletes |
| **Link-button** | `a.btnlink`: same look as a button, magenta border | For GET actions such as "Open PDF" |
| **Chips** | pill with a cyan border, cyan text and a cyan .07 wash; `button.chip` is the magenta tappable version | Machine status, location, filters |
| **Badges / tags** | 1px `currentColor` border, 4px radius, 12px mono; colour comes from a status class (`.ok .bad .warn .mut`) | **The status chip.** Colour encodes status only |
| **Status dot** | 10px circle, `--mut` when off; `.on` is lime with a glow | "Live/online" indicator (skeeball Pi reachability) |
| **Banners** | full-width strip, 44px min, Chakra 19px headline plus mono `<small>` detail, optional right-aligned button. Classes `warn`/`bad`/`info`/`dim` | Flash messages and page-level warnings |
| **Cards** | `--panel` with a `--line` border, 8px radius | Everything groups into cards |
| **Stat tiles (readouts)** | `.stat > div`: `--bg` inset box with a small uppercase `<i>` label, a big Chakra `<b>` value and a mono `<span>` sub-line | Dashboard KPIs, machine page counters |
| **Tiles (pickers)** | `.tile`: 96px min, left-aligned, bold title plus mono detail; `.on` is magenta | Machine picker, quick actions |
| **Rows** | `.row`: full-width button styled as a list row; `.on` is magenta | Mobile list rows (orders, machines) |
| **Key/value** | `.kv` two-column `dl`, `dt` in `--mut` | Machine details |
| **Tables** | `table.t`: no borders, uppercase muted 11px headers, 3px/10px cell padding | Desktop tables. Phones need a stacked-row fallback |
| **Toast** | fixed bottom-centre, `--bg2` with a cyan border and glow; `.warn`/`.bad` recolour the border; 4s (6s for errors) | Result of fetch actions |
| **Sheet / dialog** | full-screen dim (`rgba(10,4,22,.86)`) with a centred `.pane` | Confirm dialogs (use `<dialog>`) |
| **Full-screen alarm** | dark red takeover, huge red title, ACK button | Not needed in the tracker |
| **Chart** | own canvas chart: 2px series line, recessive hairline grid, text in text colours (never the series colour), status-coloured event dots with a 2px surface-colour ring, lime wash for the in-spec band | Restyle Chart.js to the same rules |

## 6. Empty, loading and error states

GATBOX's rule, from the top of `dash.js`: **"No simulated data anywhere: an empty panel says why."**

- **Empty:** a `card mut` with one plain sentence that names the next action. For example, "No machine set.
  PICK MACHINE, or scan its QR code." and "No sessions yet." Chart empty states are centred muted text inside
  the chart box: "Waiting for readings…" and "Logging ended. The last session stays on the chart until the
  next one starts."
- **Loading:** inline muted text with an ellipsis ("Loading <name>…", "checking the name…"). There are no
  spinners and no skeletons. Header values start as `…`, and an empty reading shows `—`.
- **Error:** every API failure goes to `fail(e)`, which shows a red toast for 6s with the server's `error`
  string or `HTTP <status>`. Persistent conditions become banners (`warn`/`bad`) that state the cause and the
  fix, for example "LOGGER STOPPED / Nothing is being recorded. START LOGGING starts a new file." Partial
  failures render what worked plus a "Couldn't read" tile listing what didn't.
- **Disconnected:** the header dot and badge change (`S.connected = false`), and the live connection
  reconnects by itself.
- **Disabled feature:** the nav item is dimmed with a reason in its subtitle, for example "T48 not plugged in".
- **Destructive:** press-and-hold with a visible fill and a relabel ("KEEP HOLDING…"), or a confirm sheet
  whose button names the action ("STOP").
- **Copy style:** short and imperative, uppercase for commands and banner headlines, sentence case for
  explanations. Say what happened and what to do next.

## 7. Engineering conventions that carry over

- Plain HTML/CSS/JS: no framework, no build step, no CDN. Fonts and libraries are vendored and work offline.
- No browser storage for state (hard rule 10). The tracker currently keeps a light/dark choice in
  `localStorage`, which is a per-viewer convenience rather than state. Whether to keep the light theme at all
  is an open question for the owner.
- Hard rules are numbered, terse and carry the reason. Backward compatibility of URLs is a hard rule.
- `BRINGUP.md` is a checklist with dated `[x]` items, an exit test per milestone, and "resume from the first
  unchecked box".
- Commits use `TZ=UTC`, and nothing personal goes in the public repo.

## 8. Gaps in GATBOX that the tracker must close

GATBOX is a single-user kiosk, so a few accessibility basics are missing there. The tracker brief requires
them:

1. **No focus styles.** The dash has no `:focus-visible` rule, and the phone view only has `outline: 1px` on
   inputs. The tracker adds a 2px cyan `:focus-visible` ring with offset on every interactive element.
2. **No `prefers-reduced-motion`.** The pulse, blink and scanlines always run. The tracker turns off
   animation, transitions and the scanline overlay under `reduce`.
3. **Border contrast.** Add a control-border token of at least 3:1 against `--panel` for inputs, buttons and
   focusable rows, and keep `--line` for dividers.
4. **Filled magenta** needs dark text (see §1).
5. **Touch targets:** 44px minimum everywhere on the tracker. That's less than the kiosk's 56px, but the phone
   view's 36px buttons are too small.
6. **Status is never colour alone.** Badges always carry a text label (OK / DUE / DOWN), because colour
   blindness and barcade lighting both erase hue.

## 9. Adapting it to the tracker (layout, not look)

- The GATBOX dash is a fixed 1024x600 kiosk with a side rail and no scrolling. **Don't copy that layout.**
- **Phone (390px)** is primary, because a QR scan lands on `/g/<barcode>`. Use a single column with a sticky
  compact header, a bottom-reachable primary action, and lists as `.row` blocks instead of tables.
- **Desktop (1280px):** a top nav bar with the `.on` treatment, content capped around 1200px, and tables and
  `.grid` tiles.
- **Under barcade lighting:** keep body text at 15–16px minimum on phones, use high-contrast `--fg` for
  values, and save the colour accents for status. Scanline alpha must not reduce text contrast below AA; check
  it in screenshots.
