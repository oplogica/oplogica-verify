/* OVA Evidence Integrity Demo — vanilla JS, no framework, no build.
   Talks to the existing API: GET /health and POST /verify. When served from
   the same FastAPI origin (uvicorn api.server:app) these are same-origin
   relative paths and need no CORS. */

"use strict";

const $ = (id) => document.getElementById(id);

// ---- API base. Same-origin by default (served by FastAPI static mount). ----
const API_BASE = "";

// ---- Health check ----
async function checkHealth() {
  const el = $("health");
  const txt = $("health-text");
  try {
    const r = await fetch(`${API_BASE}/health`, { method: "GET" });
    if (!r.ok) throw new Error(`status ${r.status}`);
    const body = await r.json();
    el.classList.remove("down");
    el.classList.add("ok");
    txt.textContent = `API connected · ${body.checks_known} checks known`;
  } catch (e) {
    el.classList.remove("ok");
    el.classList.add("down");
    txt.textContent =
      "API not reachable. Start it with: uvicorn api.server:app --port 8000";
  }
}

// ---- Load demo clean inputs from ../exports/ (best effort) ----
async function loadCleanInputs() {
  const files = {
    bundle: "../exports/clean_bundle.json",
    registry: "../exports/registry.json",
    trust_root: "../exports/trust_root.json",
    input_data: "../exports/input_data.json",
  };
  let loadedAny = false;
  for (const [field, path] of Object.entries(files)) {
    try {
      const r = await fetch(path);
      if (!r.ok) continue;
      const obj = await r.json();
      $(field).value = JSON.stringify(obj, null, 2);
      loadedAny = true;
    } catch (e) {
      /* leave field as-is */
    }
  }
  if (!loadedAny) {
    showError(
      "Could not load demo inputs from ../exports/. Run the pipeline first " +
        "(python3 ova_demo/run_demo.py --out ./exports), or paste JSON manually."
    );
  }
}

// ---- Apply the T4 mutation to whatever bundle is in the textarea ----
function applyT4() {
  const raw = $("bundle").value.trim();
  if (!raw) {
    showError("Load or paste a bundle first, then apply the T4 tamper.");
    return;
  }
  let bundle;
  try {
    bundle = JSON.parse(raw);
  } catch (e) {
    showError("Bundle is not valid JSON; cannot apply T4 tamper.");
    return;
  }
  try {
    bundle.operational_layer.por.conclusions[0].derived_from = [
      "p1",
      "p2",
      "r1",
      "p_GHOST",
    ];
  } catch (e) {
    showError(
      "Bundle does not have the expected reasoning structure " +
        "(operational_layer.por.conclusions[0]); cannot apply T4 tamper."
    );
    return;
  }
  $("bundle").value = JSON.stringify(bundle, null, 2);
  showNote(
    "Applied T4 tamper: added a non-existent reference 'p_GHOST' to the first " +
      "reasoning conclusion. Now click Verify."
  );
}

// ---- Parse a textarea as JSON, or null if blank ----
function parseField(id, required) {
  const raw = $(id).value.trim();
  if (!raw) {
    if (required) throw new Error(`${id} is required`);
    return null;
  }
  try {
    return JSON.parse(raw);
  } catch (e) {
    throw new Error(`${id} is not valid JSON`);
  }
}

// ---- Verify ----
async function verify() {
  let payload;
  try {
    const bundle = parseField("bundle", true);
    const registry = parseField("registry", true);
    const trust_root = parseField("trust_root", true);
    const input_data = parseField("input_data", false);
    payload = { bundle, registry, trust_root };
    if (input_data !== null) payload.input_data = input_data;
  } catch (e) {
    showError(e.message);
    return;
  }

  try {
    const r = await fetch(`${API_BASE}/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const body = await r.json();
    renderResult(body);
  } catch (e) {
    showError(
      "Request failed. Is the API running? " +
        "uvicorn api.server:app --port 8000"
    );
  }
}

// ---- Render helpers ----
function showError(msg) {
  const box = $("result");
  box.hidden = false;
  box.innerHTML = `<div class="banner" style="border-color:var(--fail);background:#FAE7E2;">
    <strong>Cannot verify.</strong> ${escapeHtml(msg)}</div>`;
}

function showNote(msg) {
  const box = $("result");
  box.hidden = false;
  box.innerHTML = `<div class="banner scope">${escapeHtml(msg)}</div>`;
}

function renderResult(body) {
  const box = $("result");
  box.hidden = false;

  if (body.status === "ERROR") {
    box.innerHTML = `<div class="banner" style="border-color:var(--skip);background:var(--warn-bg);">
      <strong>Could not process.</strong> ${escapeHtml(body.error || "Unknown error.")}</div>`;
    return;
  }

  const c = body.counts || {};
  const mb = body.meaning_block || {};

  const passList = (body.passed || [])
    .map((n) => `<li class="pass"><span class="name">${escapeHtml(n)}</span></li>`)
    .join("");
  const failList = (body.failed || [])
    .map(
      (f) =>
        `<li class="fail"><span class="name">${escapeHtml(f.check)}</span>
         <div class="reason">${escapeHtml(f.reason || "")}</div></li>`
    )
    .join("");
  const skipList = (body.not_run || [])
    .map(
      (n) =>
        `<li class="skip"><span class="name">${escapeHtml(n.check)}</span>
         <div class="reason">${escapeHtml(n.reason || "")}</div></li>`
    )
    .join("");

  box.innerHTML = `
    <hr class="soft" />
    <div>
      <span class="status-pill status-${escapeHtml(body.status)}">${escapeHtml(body.status)}</span>
    </div>
    <div class="counts">
      <div class="c-pass"><span class="n">${c.passed ?? "?"}</span><span class="label-sm">passed</span></div>
      <div class="c-fail"><span class="n">${c.failed ?? "?"}</span><span class="label-sm">failed</span></div>
      <div class="c-skip"><span class="n">${c.not_run ?? "?"}</span><span class="label-sm">not run</span></div>
      <div><span class="n" style="color:var(--muted)">${c.checks_total ?? "?"}</span><span class="label-sm">of total</span></div>
    </div>

    ${failList ? `<h3>Failed</h3><ul class="check-list">${failList}</ul>` : ""}
    ${skipList ? `<h3>Not run</h3><ul class="check-list">${skipList}</ul>` : ""}
    ${passList ? `<h3>Passed</h3><ul class="check-list">${passList}</ul>` : ""}

    <div class="meaning">
      <div class="headline">${escapeHtml(mb.headline || "")}</div>
      <div class="m">Meaning: ${escapeHtml(mb.meaning || "")}</div>
      <div class="nm">Not meaning: <strong>${escapeHtml(mb.not_meaning || "")}</strong></div>
    </div>

    ${body.scope_warning ? `<p class="footnote">${escapeHtml(body.scope_warning)}</p>` : ""}
  `;
}

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

// ---- Wire up ----
window.addEventListener("DOMContentLoaded", () => {
  checkHealth();
  $("btn-load-clean").addEventListener("click", loadCleanInputs);
  $("btn-apply-t4").addEventListener("click", applyT4);
  $("btn-verify").addEventListener("click", verify);
});
