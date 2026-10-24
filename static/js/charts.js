/* Chart.js (3.9.1, static/js/chart.min.js) on the design system.
 *
 * Load after chart.min.js. Colours and the font come from the CSS tokens
 * (static/css/tokens.css), so a chart can't drift from the page around it. Data reaches a
 * page's script as a JSON island, <script type="application/json" id="…">, never as
 * template-built JavaScript; ArcadeCharts.read(id) parses one.
 */
(function () {
  "use strict";
  if (!window.Chart) return;

  var css = getComputedStyle(document.documentElement);
  function token(name) { return css.getPropertyValue(name).trim(); }

  var theme = {
    text: token("--text"),
    dim: token("--text-dim"),
    surface: token("--surface-raised"),
    border: token("--border-control"),
    grid: "rgba(163, 148, 196, 0.14)",
    accent: token("--accent"),
    ok: token("--ok"),
    warn: token("--warn"),
    fault: token("--fault"),
    info: token("--info"),
    muted: token("--muted")
  };

  // "#5ef2b0" and 0.1 -> "rgba(94, 242, 176, 0.1)", for fills under a line.
  function alpha(hex, a) {
    var h = hex.replace("#", "");
    if (h.length === 3) h = h.replace(/./g, "$&$&");
    var n = parseInt(h, 16);
    return "rgba(" + (n >> 16) + ", " + ((n >> 8) & 255) + ", " + (n & 255) + ", " + a + ")";
  }

  var d = Chart.defaults;
  d.color = theme.dim;
  d.borderColor = theme.grid;
  d.font.family = token("--font-body");
  d.font.size = 13;
  d.maintainAspectRatio = false;
  d.plugins.legend.labels.boxWidth = 12;
  d.plugins.legend.labels.color = theme.text;
  d.plugins.tooltip.backgroundColor = theme.surface;
  d.plugins.tooltip.borderColor = theme.border;
  d.plugins.tooltip.borderWidth = 1;
  d.plugins.tooltip.titleColor = theme.text;
  d.plugins.tooltip.bodyColor = theme.text;
  d.plugins.tooltip.footerColor = theme.dim;
  if (window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
    d.animation = false;
  }

  window.ArcadeCharts = {
    theme: theme,
    alpha: alpha,
    read: function (id) {
      var el = document.getElementById(id);
      return el ? JSON.parse(el.textContent) : null;
    }
  };
})();
