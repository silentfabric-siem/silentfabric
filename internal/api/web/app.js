"use strict";

// All log content is attacker-controlled: build DOM nodes and set
// textContent, never innerHTML.
function el(tag, attrs, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k === "class") node.className = v;
    else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v);
  }
  for (const c of children) {
    if (c == null) continue;
    node.append(c instanceof Node ? c : String(c));
  }
  return node;
}

const $ = (id) => document.getElementById(id);
const fmtTime = (t) => new Date(t).toLocaleString(undefined, {
  month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false,
});

async function getJSON(url) {
  const res = await fetch(url, { headers: { Accept: "application/json" } });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.error || res.statusText);
  return body;
}

// ---- tabs ----
for (const tab of document.querySelectorAll(".tab")) {
  tab.addEventListener("click", () => showView(tab.dataset.view));
}
function showView(name) {
  for (const t of document.querySelectorAll(".tab")) t.classList.toggle("active", t.dataset.view === name);
  for (const v of document.querySelectorAll(".view")) v.hidden = v.id !== "view-" + name;
  if (name === "alerts") loadAlerts();
  history.replaceState(null, "", name === "alerts" ? "#alerts" : location.pathname + location.search);
}

// ---- search ----
function quoteValue(v) {
  return /^[^\s"]+$/.test(v) ? v : '"' + v.replace(/\\/g, "\\\\").replace(/"/g, '\\"') + '"';
}
function addFilter(field, value) {
  const term = field + ":" + quoteValue(value);
  const q = $("q");
  if (!q.value.includes(term)) q.value = (q.value.trim() + " " + term).trim();
  runSearch();
}

async function runSearch() {
  const q = $("q").value, range = $("range").value;
  const params = new URLSearchParams({ q, range });
  history.replaceState(null, "", "?" + params);
  const status = $("search-status");
  status.className = "status";
  status.textContent = "Searching…";
  const started = performance.now();
  try {
    const res = await getJSON("api/v1/search?" + params);
    const ms = Math.round(performance.now() - started);
    const shown = (res.events || []).length;
    status.textContent = `${res.total.toLocaleString()} events` +
      (shown < res.total ? `, showing newest ${shown}` : "") + ` · ${ms} ms`;
    renderHistogram(res);
    renderFacets(res.facets || {});
    renderEvents(res.events || []);
  } catch (err) {
    status.className = "status error";
    status.textContent = "Search failed: " + err.message;
  }
}

// Bars sit on a fixed time axis covering the whole range, so gaps in the
// data show as gaps rather than stretching the bars that exist.
function renderHistogram(res) {
  const box = $("histogram");
  box.replaceChildren();
  const buckets = res.histogram || [];
  if (!buckets.length) return;
  const ns = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(ns, "svg");
  const w = 1000, h = 72;
  svg.setAttribute("viewBox", `0 0 ${w} ${h}`);
  svg.setAttribute("preserveAspectRatio", "none");
  const stepMs = res.step_seconds * 1000;
  const start = Math.floor(Date.parse(res.from) / stepMs) * stepMs;
  const slots = Math.max(1, Math.ceil((Date.parse(res.to) - start) / stepMs));
  const bw = w / slots, gap = bw > 4 ? 1 : 0;
  const max = Math.max(...buckets.map((b) => b.count));
  for (const b of buckets) {
    const slot = Math.round((Date.parse(b.time) - start) / stepMs);
    if (slot < 0 || slot >= slots) continue;
    const bh = Math.max(1, (b.count / max) * (h - 2));
    const r = document.createElementNS(ns, "rect");
    r.setAttribute("x", slot * bw);
    r.setAttribute("y", h - bh);
    r.setAttribute("width", Math.max(0.5, bw - gap));
    r.setAttribute("height", bh);
    const title = document.createElementNS(ns, "title");
    title.textContent = `${fmtTime(b.time)}: ${b.count.toLocaleString()} events`;
    r.append(title);
    svg.append(r);
  }
  box.append(svg);
}

const facetLabels = { host: "Host", "event.dataset": "Dataset", "event.action": "Action", "event.outcome": "Outcome" };

function renderFacets(facets) {
  const box = $("facets");
  box.replaceChildren();
  for (const [field, label] of Object.entries(facetLabels)) {
    const values = facets[field];
    if (!values || !values.length) continue;
    box.append(el("h3", null, label));
    for (const v of values) {
      box.append(el("button", { class: "facet", type: "button", title: `Filter ${field}:${v.value}`, onclick: () => addFilter(field, v.value) },
        el("span", null, v.value), el("span", null, v.count.toLocaleString())));
    }
  }
}

function renderEvents(events) {
  const box = $("results");
  box.replaceChildren();
  if (!events.length) {
    box.append(el("div", { class: "empty" }, "No events match this search."));
    return;
  }
  box.append(el("div", { class: "row head" }, el("span", null, "Time"), el("span", null, "Host"), el("span", null, "Dataset"), el("span", null, "Message")));
  for (const ev of events) {
    const msg = ev.message || ev.raw;
    const row = el("div", { class: "row", tabindex: "0", role: "button" },
      el("span", { class: "time" }, fmtTime(ev.time)),
      el("span", null, ev.host),
      el("span", null, (ev.fields && ev.fields["event.dataset"]) || ev.source),
      el("span", { class: "mono" }, msg));
    let detail = null;
    const toggle = () => {
      if (detail) { detail.remove(); detail = null; return; }
      detail = eventDetail(ev);
      row.after(detail);
    };
    row.addEventListener("click", toggle);
    row.addEventListener("keydown", (e) => { if (e.key === "Enter") toggle(); });
    box.append(row);
  }
}

function eventDetail(ev) {
  const fields = Object.assign({ host: ev.host, source: ev.source }, ev.fields || {});
  const tbody = el("tbody");
  for (const k of Object.keys(fields).sort()) {
    const v = fields[k];
    if (v === "") continue;
    tbody.append(el("tr", null, el("td", { class: "mono" }, k),
      el("td", { class: "mono" }, el("a", { title: "Add as filter", onclick: () => addFilter(k, v) }, v))));
  }
  return el("div", { class: "detail" }, el("table", null, tbody), el("pre", { class: "mono" }, ev.raw));
}

$("search-form").addEventListener("submit", (e) => { e.preventDefault(); runSearch(); });
$("range").addEventListener("change", runSearch);

// ---- alerts ----
async function loadAlerts() {
  const params = new URLSearchParams({ range: $("alerts-range").value, level: $("alerts-level").value });
  const status = $("alerts-status");
  status.className = "status";
  status.textContent = "Loading…";
  try {
    const res = await getJSON("api/v1/alerts?" + params);
    status.textContent = `${res.alerts.length} alerts`;
    renderAlerts(res.alerts);
  } catch (err) {
    status.className = "status error";
    status.textContent = "Could not load alerts: " + err.message;
  }
}

function renderAlerts(alerts) {
  const box = $("alerts");
  box.replaceChildren();
  box.classList.add("alerts-grid");
  if (!alerts.length) {
    box.append(el("div", { class: "empty" }, "No alerts in this time range."));
    return;
  }
  box.append(el("div", { class: "row head" }, el("span", null, "Time"), el("span", null, "Level"), el("span", null, "Rule"), el("span", null, "Host")));
  for (const a of alerts) {
    const row = el("div", { class: "row", tabindex: "0", role: "button" },
      el("span", { class: "time" }, fmtTime(a.time)),
      el("span", { class: "level level-" + a.level }, a.level),
      el("span", null, a.rule_title),
      el("span", null, a.host));
    let detail = null;
    const toggle = () => {
      if (detail) { detail.remove(); detail = null; return; }
      const meta = el("tbody", null,
        el("tr", null, el("td", null, "Rule ID"), el("td", { class: "mono" }, a.rule_id)),
        el("tr", null, el("td", null, "Tags"), el("td", { class: "mono" }, (a.tags || []).join(", "))));
      detail = el("div", { class: "detail" }, el("table", null, meta), el("pre", { class: "mono" }, a.event_raw));
      row.after(detail);
    };
    row.addEventListener("click", toggle);
    row.addEventListener("keydown", (e) => { if (e.key === "Enter") toggle(); });
    box.append(row);
  }
}

$("alerts-form").addEventListener("submit", (e) => { e.preventDefault(); loadAlerts(); });
$("alerts-range").addEventListener("change", loadAlerts);
$("alerts-level").addEventListener("change", loadAlerts);

// ---- start ----
const initial = new URLSearchParams(location.search);
if (initial.has("q")) $("q").value = initial.get("q");
if (initial.has("range")) $("range").value = initial.get("range");
if (location.hash === "#alerts") showView("alerts");
runSearch();
