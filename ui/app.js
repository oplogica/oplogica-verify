
/* OVA Evidence Integrity Demo — vanilla JS, no framework, no build.
   Talks to the existing API: GET /health and POST /verify. When served from
   the same FastAPI origin (uvicorn api.server:app) these are same-origin
   relative paths and need no CORS.

   Demo inputs are loaded from the API's /exports static mount using no-store
   requests. Important: demo JSON is loaded and submitted as raw text so the
   browser does not normalize numeric lexemes such as 1.0 -> 1, which would
   change the registry hash.

   Before POSTing, verify() runs one safe pre-flight check: the bundle's
   embedded registry hash must be present in trust_root.allowed_registry_hashes.

   The server remains the authoritative verifier for the registry signature,
   registry hash, vote signatures, Merkle root, and all integrity checks. */

"use strict";

const $ = (id) => document.getElementById(id);

// ---- API base. Same-origin by default (served by FastAPI static mount). ----
const API_BASE = "";

// Demo artifact locations on the API's /exports mount (absolute, same-origin).
const EXPORT_FILES = {
  bundle: "/exports/clean_bundle.json",
  registry: "/exports/registry.json",
  trust_root: "/exports/trust_root.json",
  input_data: "/exports/input_data.json",
};

// ---- Health check ----
async function checkHealth() {
  const el = $("health");
  const txt = $("health-text");

  try {
    const r = await fetch(`${API_BASE}/health`, {
      method: "GET",
      cache: "no-store",
    });

    if (!r.ok) throw new Error(`status ${r.status}`);

    const body = await r.json();

    el.classList.remove("down");
    el.classList.add("ok");
    txt.textContent = `API connected · ${body.checks_known} checks known`;
  } catch (e) {
    el.classList.remove("ok");
    el.classList.add("down");
    txt.textContent =
      "API not reachable. Start it with: python -m uvicorn api.server:app --host 127.0.0.1 --port 8000";
  }
}

// ---- Load demo clean inputs from /exports (all-or-nothing, no-store) ----
async function loadCleanInputs() {
  // Clear old field values first so a partial load can never leave a stale mix.
  for (const field of Object.keys(EXPORT_FILES)) {
    $(field).value = "";
  }

  $("result").hidden = true;
  $("result").innerHTML = "";

  const loaded = {};
  const missing = [];

  for (const [field, path] of Object.entries(EXPORT_FILES)) {
    try {
      const r = await fetch(path, { cache: "no-store" });

      if (!r.ok) {
        missing.push(path);
        continue;
      }

      // Keep the original JSON text exactly as served.
      // Do not use r.json() here because JavaScript normalizes numbers
      // such as 1.0 -> 1, which changes the registry hash.
      const raw = await r.text();

      // Validate JSON, but store and display the original raw text.
      JSON.parse(raw);

      loaded[field] = raw;
    } catch (e) {
      missing.push(path);
    }
  }

  if (
    missing.length > 0 ||
    Object.keys(loaded).length !== Object.keys(EXPORT_FILES).length
  ) {
    showError(
      "Could not load all demo inputs from /exports/. Run the pipeline first " +
        "(python3 ova_demo/run_demo.py --out ./exports), then reload the page. " +
        "Missing: " +
        (missing.join(", ") || "(unknown)")
    );
    return;
  }

  for (const [field, raw] of Object.entries(loaded)) {
    $(field).value = raw;
  }

  showNote(
    "Loaded clean demo inputs from /exports/. You can now click Verify. " +
      "Do not click Apply T4 unless you want to test the tampered reasoning case."
  );
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

  // T4 intentionally mutates only the bundle. Registry and trust_root remain
  // raw and untouched, so their canonical hash relationship is preserved.
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
  const rawBundle = $("bundle").value.trim();
  const rawRegistry = $("registry").value.trim();
  const rawTrustRoot = $("trust_root").value.trim();
  const rawInputData = $("input_data").value.trim();

  let bundle, registry, trust_root, input_data;

  try {
    if (!rawBundle) throw new Error("bundle is required");
    if (!rawRegistry) throw new Error("registry is required");
    if (!rawTrustRoot) throw new Error("trust_root is required");

    bundle = JSON.parse(rawBundle);
    registry = JSON.parse(rawRegistry);
    trust_root = JSON.parse(rawTrustRoot);
    input_data = rawInputData ? JSON.parse(rawInputData) : null;
  } catch (e) {
    showError(e.message);
    return;
  }

  const allowed =
    (trust_root && Array.isArray(trust_root.allowed_registry_hashes)
      ? trust_root.allowed_registry_hashes
      : []) || [];

  // Safe pre-flight: the bundle's embedded registry hash must be allowed by
  // the supplied trust root. The server remains authoritative for recomputing
  // the registry hash and verifying the registry signature.
  const embedded =
    bundle &&
    bundle.constitutional_layer &&
    bundle.constitutional_layer.pon &&
    bundle.constitutional_layer.pon.governance_registry_hash;

  if (embedded && allowed.length && !allowed.includes(embedded)) {
    showError(
      "Inputs are from different demo generations. The bundle's embedded " +
        "registry hash is not in trust_root.allowed_registry_hashes.\n" +
        "  bundle registry hash: " +
        embedded +
        "\n  allowed: " +
        allowed.join(", ") +
        "\nRe-run `python3 ova_demo/run_demo.py --out ./exports`, then click " +
        "'Load demo clean inputs' again before Verify."
    );
    return;
  }

  // Important: build the POST body from raw textarea JSON text.
  // Do NOT JSON.stringify(parsed objects), because JavaScript normalizes
  // numeric lexemes such as 1.0 -> 1, which changes the registry hash.
  let requestBody =
    "{" +
    '"bundle":' +
    rawBundle +
    "," +
    '"registry":' +
    rawRegistry +
    "," +
    '"trust_root":' +
    rawTrustRoot;

  if (rawInputData) {
    requestBody += "," + '"input_data":' + rawInputData;
  }

  requestBody += "}";

  try {
    const r = await fetch(`${API_BASE}/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: requestBody,
    });

    const body = await r.json();
    renderResult(body);
  } catch (e) {
    showError(
      "Request failed. Is the API running? " +
        "python -m uvicorn api.server:app --host 127.0.0.1 --port 8000"
    );
  }
}

// ---- Render helpers ----
function showError(msg) {
  const box = $("result");
  box.hidden = false;
  box.innerHTML = `<div class="banner" style="border-color:var(--fail);background:#FAE7E2;white-space:pre-wrap;">
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
      <strong>Could not process.</strong> ${escapeHtml(
        body.error || "Unknown error."
      )}</div>`;
    return;
  }

  const c = body.counts || {};
  const mb = body.meaning_block || {};

  const passList = (body.passed || [])
    .map(
      (name) =>
        `<li class="pass"><span class="name">${escapeHtml(name)}</span></li>`
    )
    .join("");

  const failList = (body.failed || [])
    .map(
      (entry) =>
        `<li class="fail"><span class="name">${escapeHtml(entry.check)}</span>
         <div class="reason">${escapeHtml(entry.reason || "")}</div></li>`
    )
    .join("");

  const skipList = (body.not_run || [])
    .map(
      (entry) =>
        `<li class="skip"><span class="name">${escapeHtml(entry.check)}</span>
         <div class="reason">${escapeHtml(entry.reason || "")}</div></li>`
    )
    .join("");

  box.innerHTML = `
    <hr class="soft" />
    <div>
      <span class="status-pill status-${escapeHtml(body.status)}">${escapeHtml(
    body.status
  )}</span>
    </div>
    <div class="counts">
      <div class="c-pass"><span class="n">${
        c.passed ?? "?"
      }</span><span class="label-sm">passed</span></div>
      <div class="c-fail"><span class="n">${
        c.failed ?? "?"
      }</span><span class="label-sm">failed</span></div>
      <div class="c-skip"><span class="n">${
        c.not_run ?? "?"
      }</span><span class="label-sm">not run</span></div>
      <div><span class="n" style="color:var(--muted)">${
        c.checks_total ?? "?"
      }</span><span class="label-sm">of total</span></div>
    </div>

    ${failList ? `<h3>Failed</h3><ul class="check-list">${failList}</ul>` : ""}
    ${skipList ? `<h3>Not run</h3><ul class="check-list">${skipList}</ul>` : ""}
    ${passList ? `<h3>Passed</h3><ul class="check-list">${passList}</ul>` : ""}

    <div class="meaning">
      <div class="headline">${escapeHtml(mb.headline || "")}</div>
      <div class="m">Meaning: ${escapeHtml(mb.meaning || "")}</div>
      <div class="nm">Not meaning: <strong>${escapeHtml(
        mb.not_meaning || ""
      )}</strong></div>
    </div>

    ${
      body.scope_warning
        ? `<p class="footnote">${escapeHtml(body.scope_warning)}</p>`
        : ""
    }
  `;
}

function escapeHtml(value) {
  return String(value)
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