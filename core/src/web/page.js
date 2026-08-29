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
