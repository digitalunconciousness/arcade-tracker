/* The rail-history charts. Load after chart.min.js and charts.js.
 *
 *   #history-data  one machine: powered mean per session, against the window of the day;
 *   #trace-data    one session: every reading, against that session's window.
 *
 * What the data means is set in app/routes/rails.py; this file only draws it.
 */
(function () {
  "use strict";
  if (!window.ArcadeCharts) return;
  var t = ArcadeCharts.theme;
  var alpha = ArcadeCharts.alpha;

  function history(d) {
    if (!d.points.length) return;
    var labels = d.points.map(function (p) {
      return p.t ? new Date(p.t * 1000).toLocaleDateString() : "";
    });
    // window_lo/window_hi are per point and stepped, because they can change between
    // sessions: one flat band would claim they never did.
    new Chart(document.getElementById("history"), {
      type: "line",
      data: {
        labels: labels,
        datasets: [
          { label: "Powered mean (" + d.unit + ")",
            data: d.points.map(function (p) { return p.mean; }),
            borderColor: t.info, backgroundColor: alpha(t.info, 0.1),
            pointBackgroundColor: d.points.map(function (p) { return p.colour; }),
            pointBorderColor: d.points.map(function (p) { return p.colour; }),
            pointRadius: 5, borderWidth: 2, tension: 0, spanGaps: false, order: 1 },
          { label: "Window high", data: d.points.map(function (p) { return p.hi; }),
            borderColor: t.ok, borderWidth: 1, stepped: true, pointRadius: 0,
            fill: "+1", backgroundColor: alpha(t.ok, 0.08), order: 3 },
          { label: "Window low", data: d.points.map(function (p) { return p.lo; }),
            borderColor: t.ok, borderWidth: 1, stepped: true, pointRadius: 0, order: 3 },
          { label: "Over-voltage limit", data: d.points.map(function (p) { return p.alarm; }),
            borderColor: t.fault, borderWidth: 1, borderDash: [5, 4], stepped: true,
            pointRadius: 0, order: 2 }
        ]
      },
      options: {
        plugins: {
          tooltip: { callbacks: { afterBody: function (items) {
            var p = d.points[items[0].dataIndex];
            var out = [];
            if (p.verdict) out.push("verdict: " + p.verdict);
            if (p.source) out.push("window from " + p.source);
            if (p.min != null && p.max != null) out.push("min " + p.min + "  max " + p.max);
            return out;
          } } }
        },
        scales: {
          x: { ticks: { maxRotation: 0, autoSkip: true } },
          y: { title: { display: true, text: d.unit } }
        }
      }
    });
  }

  function trace(d) {
    if (!d.points.length) return;
    var colour = function (p) {
      if (p.alarm === "alarm") return t.fault;
      if (p.alarm === "spike") return t.warn;
      return t.info;
    };
    var sets = [{
      label: "Reading (" + d.unit + ")",
      // y is null for an over-range reading and stays null: spanGaps false breaks the line
      // there. A zero would draw a dropout to 0 V that the meter never reported.
      data: d.points.map(function (p) { return { x: p.x, y: p.y }; }),
      borderColor: t.info, borderWidth: 1.5, pointRadius: 0, tension: 0,
      spanGaps: false, order: 1
    }];
    // Within one session the window really is constant, so a flat band is correct here --
    // unlike the per-machine history, where it can step.
    var span = function (v, c, dash) {
      return { label: null, data: d.points.map(function (p) { return { x: p.x, y: v }; }),
               borderColor: c, borderWidth: 1, borderDash: dash || [], pointRadius: 0,
               tension: 0, order: 3 };
    };
    if (d.lo !== null && d.lo !== undefined) {
      var hi = span(d.hi, t.ok); hi.fill = "+1";
      hi.backgroundColor = alpha(t.ok, 0.08); hi.label = "Window";
      sets.push(hi, span(d.lo, t.ok));
    }
    if (d.alarm !== null && d.alarm !== undefined) {
      var a = span(d.alarm, t.fault, [5, 4]); a.label = "Over-voltage limit"; sets.push(a);
    }
    // Mark the readings GATBOX flagged, so a one-sample spike is visible on a line of
    // thousands of points where a 0-radius line would hide it.
    var flagged = d.points.filter(function (p) { return p.alarm === "spike" || p.alarm === "alarm"; });
    if (flagged.length) {
      sets.push({ label: "Flagged", type: "scatter",
                  data: flagged.map(function (p) { return { x: p.x, y: p.y }; }),
                  pointBackgroundColor: flagged.map(colour),
                  pointBorderColor: flagged.map(colour), pointRadius: 4, order: 0 });
    }
    new Chart(document.getElementById("trace"), {
      type: "line",
      data: { datasets: sets },
      options: {
        parsing: false,
        plugins: {
          legend: { labels: { filter: function (i) { return !!i.text; } } },
          tooltip: { mode: "nearest", intersect: false }
        },
        scales: {
          x: { type: "linear",
               title: { display: true, text: "seconds from the start of the session" } },
          y: { title: { display: true, text: d.unit } }
        }
      }
    });
  }

  var h = ArcadeCharts.read("history-data");
  if (h) history(h);
  var s = ArcadeCharts.read("trace-data");
  if (s) trace(s);
})();
