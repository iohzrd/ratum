function num(n) { return n == null ? "-" : Number(n).toLocaleString(); }
function esc(s) { return String(s == null ? "" : s).replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }
function ths(t) { return t == null ? "-" : Number(t).toFixed(3) + " TH/s"; }
function card(label, value) {
  return `<div class="card"><div class="label">${label}</div><div class="value">${value}</div></div>`;
}
function unreachable() {
  document.getElementById("updated").innerHTML = '<span class="stale">unreachable</span>';
}
function updated(when) {
  document.getElementById("updated").textContent = "updated " + (when || new Date()).toLocaleTimeString();
}
// Fetch `url` as JSON every 5 s and pass it to `render`; the header shows when the page
// last succeeded or that the server is unreachable.
function poll(url, render) {
  async function tick() {
    let s;
    try {
      const r = await fetch(url(), {cache: "no-store"});
      s = await r.json();
    } catch (e) {
      unreachable();
      return;
    }
    render(s);
  }
  tick();
  setInterval(tick, 5000);
}

// An approximate hashes-per-second figure with a unit chosen to keep 1 to 3 integer digits.
function hashrate(hs) {
  if (hs == null) return "-";
  const units = ["H/s", "kH/s", "MH/s", "GH/s", "TH/s", "PH/s", "EH/s"];
  let i = 0;
  while (hs >= 1000 && i < units.length - 1) { hs /= 1000; i += 1; }
  return hs.toLocaleString(undefined, {maximumFractionDigits: hs < 10 ? 2 : 1}) + " " + units[i];
}

// A rough duration: seconds below 90 s, minutes below 90 min, hours below 48 h, then days.
function duration(secs) {
  if (secs == null || !isFinite(secs) || secs <= 0) return "-";
  if (secs < 90) return Math.round(secs) + " s";
  if (secs < 5400) return Math.round(secs / 60) + " min";
  if (secs < 172800) return (secs / 3600).toFixed(1) + " h";
  return (secs / 86400).toFixed(1) + " d";
}

function tile(label, big, sub) {
  return `<div class="tile"><div class="label">${label}</div><div class="big">${big}</div>`
    + (sub ? `<div class="sub">${sub}</div>` : "") + `</div>`;
}
function chip(label, value) { return `<span class="chip">${label} <b>${value}</b></span>`; }

// Set a `.meter`'s fill and the text beside it. `fraction` is clamped to 0..1.
function meter(fillId, valsId, fraction, text) {
  const f = isFinite(fraction) ? Math.min(Math.max(fraction, 0), 1) : 0;
  document.getElementById(fillId).style.width = (f * 100) + "%";
  document.getElementById(valsId).textContent = text;
}

// --- Hashrate history chart ---------------------------------------------------------------
// `root` is a `.chart` element holding an <svg>, a `.empty` note and a `.chart-tip`.
// `samples` are [unix, hashes per second] pairs taken every `interval` seconds; a longer gap
// between two breaks the line, so a pause in sampling (a restart) shows as a gap. Returns a
// note on what was drawn for the caller's heading.
function drawChart(root, samples, interval) {
  root._data = [samples, interval];
  root._pts = [];
  const svg = root.querySelector("svg");
  const empty = root.querySelector(".empty");
  const pts = samples;
  if (pts.length < 2) {
    svg.innerHTML = "";
    empty.style.display = "flex";
    return "";
  }
  empty.style.display = "none";

  const w = root.clientWidth, h = root.clientHeight;
  const padT = 14, padB = 16, padL = 2, padR = 2;
  const t0 = pts[0][0], t1 = pts[pts.length - 1][0];
  const span = Math.max(t1 - t0, 1);
  const max = Math.max(...pts.map(p => p[1]), 1e-9) * 1.05;
  const x = t => padL + (t - t0) / span * (w - padL - padR);
  const y = v => padT + (1 - v / max) * (h - padT - padB);

  const baseline = y(0);
  let line = "", area = "";
  let seg = [];
  const flush = () => {
    if (seg.length < 2) { seg = []; return; }
    const d = seg.map((p, i) => (i ? "L" : "M") + p[0].toFixed(1) + " " + p[1].toFixed(1)).join(" ");
    line += d + " ";
    area += d + ` L${seg[seg.length - 1][0].toFixed(1)} ${baseline.toFixed(1)}`
      + ` L${seg[0][0].toFixed(1)} ${baseline.toFixed(1)} Z `;
    seg = [];
  };
  for (let i = 0; i < pts.length; i++) {
    if (i > 0 && pts[i][0] - pts[i - 1][0] > interval * 2.5) flush();
    const px = x(pts[i][0]), py = y(pts[i][1]);
    seg.push([px, py]);
    root._pts.push([px, py, pts[i][0], pts[i][1]]);
  }
  flush();

  // Recessive horizontal grid at 1/2 and full scale, labeled with the hashrate they mark.
  const grid = [max / 2, max].map(v =>
    `<line x1="0" y1="${y(v).toFixed(1)}" x2="${w}" y2="${y(v).toFixed(1)}"
       stroke="var(--line)" stroke-width="1"/>
     <text x="4" y="${(y(v) - 3).toFixed(1)}" fill="var(--muted)" font-size="10">${hashrate(v)}</text>`
  ).join("");

  const last = root._pts[root._pts.length - 1];
  svg.innerHTML = grid
    + `<path d="${area}" fill="var(--accent)" opacity=".12"/>`
    + `<path d="${line}" fill="none" stroke="var(--accent)" stroke-width="2"
        stroke-linejoin="round" stroke-linecap="round"/>`
    + `<circle cx="${last[0].toFixed(1)}" cy="${last[1].toFixed(1)}" r="3" fill="var(--accent)"/>`
    + `<text x="${padL}" y="${h - 3}" fill="var(--muted)" font-size="10">${
        new Date(t0 * 1000).toLocaleTimeString()}</text>`
    + `<text x="${w - padR}" y="${h - 3}" text-anchor="end" fill="var(--muted)" font-size="10">${
        new Date(t1 * 1000).toLocaleTimeString()}</text>`
    + `<line class="crosshair" y1="${padT}" y2="${h - padB}" stroke="var(--muted)"
        stroke-width="1" stroke-dasharray="3 3" visibility="hidden"/>`;
  return `${pts.length} samples over ${duration(span)}`;
}

// Hover on a chart: the crosshair snaps to the nearest sample and the tip shows its time
// and rate. Attached to every `.chart` on the page; a resize redraws them.
(function () {
  for (const root of document.querySelectorAll(".chart")) {
    const tip = root.querySelector(".chart-tip");
    root.addEventListener("mousemove", e => {
      const cross = root.querySelector(".crosshair");
      const pts = root._pts || [];
      if (!pts.length || !cross) return;
      const mx = e.clientX - root.getBoundingClientRect().left;
      let best = pts[0];
      for (const p of pts) if (Math.abs(p[0] - mx) < Math.abs(best[0] - mx)) best = p;
      cross.setAttribute("x1", best[0]); cross.setAttribute("x2", best[0]);
      cross.setAttribute("visibility", "visible");
      tip.style.display = "block";
      tip.style.left = Math.min(Math.max(best[0], 60), root.clientWidth - 60) + "px";
      tip.style.top = (best[1] - 8) + "px";
      tip.textContent = `${new Date(best[2] * 1000).toLocaleTimeString()} · ~${hashrate(best[3])}`;
    });
    root.addEventListener("mouseleave", () => {
      const cross = root.querySelector(".crosshair");
      if (cross) cross.setAttribute("visibility", "hidden");
      tip.style.display = "none";
    });
  }
  addEventListener("resize", () => {
    for (const root of document.querySelectorAll(".chart")) {
      if (root._data) drawChart(root, root._data[0], root._data[1]);
    }
  });
})();
