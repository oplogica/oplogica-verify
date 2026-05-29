/* OVA Evidence Integrity Demo — vanilla JS, no framework, no build.
   Talks to the existing API: GET /health and POST /verify. When served from
   the same FastAPI origin (uvicorn api.server:app) these are same-origin
   relative paths and need no CORS.

   Demo inputs are loaded from the API's /exports static mount (no-store), so a
   single consistent generation is always fetched. Before POSTing, verify()
   runs one pre-flight check to catch a cross-generation mix early:
     1. the bundle's embedded registry hash must be in
        trust_root.allowed_registry_hashes (a direct string comparison).
   The server still performs the authoritative check; the pre-flight only turns a
   confusing server INVALID into a precise client message. */

"use strict";

const $ = (id) => document.getElementById(id);

// ---- API base. Same-origin, prefix-aware. ----
// When served under a reverse-proxy prefix (e.g. /ova-demo/ui/), the API lives
// at the same prefix (/ova-demo/health, /ova-demo/verify). Derive it from the
// page path so /health and /verify resolve in both root and prefixed setups.
const API_BASE = window.location.pathname.replace(/\/ui\/?$/, "");

// Demo artifact locations on the API's /exports mount.
// The UI may be served at the domain root ("/ui/") or under a reverse-proxy
// prefix ("/ova-demo/ui/"). Derive the app prefix from the current page path so
// the exports resolve correctly in both cases:
//   /ui/           -> /exports/...
//   /ova-demo/ui/  -> /ova-demo/exports/...
const APP_PREFIX = window.location.pathname.replace(/\/ui\/?$/, "");
const EXPORT_BASE = `${APP_PREFIX}/exports`;
const EXPORT_FILES = {
  bundle: `${EXPORT_BASE}/clean_bundle.json`,
  registry: `${EXPORT_BASE}/registry.json`,
  trust_root: `${EXPORT_BASE}/trust_root.json`,
  input_data: `${EXPORT_BASE}/input_data.json`,
};

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
      loaded[field] = await r.json();
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

  for (const [field, obj] of Object.entries(loaded)) {
    $(field).value = JSON.stringify(obj, null, 2);
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

// ----------------------------------------------------------------------
// Note: the browser previously recomputed a canonical registry hash to mirror
// the engine. That logic was removed because reproducing the engine's exact
// canonical-JSON form across runtimes is unreliable and produced false
// negatives. The server is the authoritative verifier; the UI only checks the
// bundle's embedded registry hash (a direct string comparison) as a courtesy
// pre-flight.
// ----------------------------------------------------------------------

// ---- Verify ----
async function verify() {
  let bundle, registry, trust_root, input_data;
  try {
    bundle = parseField("bundle", true);
    registry = parseField("registry", true);
    trust_root = parseField("trust_root", true);
    input_data = parseField("input_data", false);
  } catch (e) {
    showError(e.message);
    return;
  }

  const allowed =
    (trust_root && Array.isArray(trust_root.allowed_registry_hashes)
      ? trust_root.allowed_registry_hashes
      : []) || [];

  // Pre-flight #1: the bundle's embedded registry hash must be allowed.
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

  // Note: a previous pre-flight recomputed a canonical registry hash in the
  // browser and compared it to trust_root.allowed_registry_hashes. That check
  // is intentionally removed: reproducing the engine's exact canonical-JSON
  // form (key ordering, numeric lexemes, ASCII escaping) in the browser is not
  // reliable across runtimes, and a mismatch there produced a false negative
  // even when the server verified the same inputs as VALID. Pre-flight #1
  // (the bundle's embedded registry hash, a direct string comparison) still
  // guards the cross-generation case, and the server remains the authoritative
  // verifier of every check, signature, and hash.

  // Build the POST payload from the parsed visible textareas only.
  const payload = { bundle, registry, trust_root };
  if (input_data !== null) payload.input_data = input_data;

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

    ${renderV02(body)}

    ${body.scope_warning ? `<p class="footnote">${escapeHtml(body.scope_warning)}</p>` : ""}
  `;
}

// ---- v0.2 display (additive, read-only over the API response) ----
// Renders the verification-discipline posture, the L3 failure taxonomy, and the
// negative-claims firewall status. Pure display of fields already present in the
// API response; no interpretation, no new claims. Uses only safe wording.
function renderV02(body) {
  const hasV02 =
    body.verification_discipline || body.l3_taxonomy || body.firewall;
  if (!hasV02) return "";

  const vd = body.verification_discipline || {};
  const tax = body.l3_taxonomy || {};
  const fw = body.firewall || {};

  // A. Status card — fixed labels (not derived from free text).
  const statusCard = `
    <div class="v02-card">
      <div class="v02-row"><span class="v02-dot ok"></span>Oplogica v0.2 active</div>
      <div class="v02-row"><span class="v02-dot ok"></span>Negative Claims Firewall: active</div>
      <div class="v02-row"><span class="v02-dot ok"></span>Verification Discipline: deterministic / no LLM</div>
      <div class="v02-row"><span class="v02-dot ok"></span>L3 Failure Taxonomy: active</div>
    </div>`;

  // B. Verification discipline — show the boolean posture in safe wording.
  const disciplineItems = [
    ["deterministic", "Deterministic recompute", true],
    ["uses_llm_interpretation", "No LLM interpretation", false],
    ["free_text_claim_extraction", "No free-text claim extraction", false],
    ["checks_recomputed_from_bundle", "Checks recomputed from the bundle", true],
    ["verifies_decision_correctness", "Does not prove decision correctness", false],
    ["certifies_compliance", "Does not certify compliance", false],
    ["establishes_fairness", "Does not establish fairness", false],
    ["detects_silent_omission", "Silent omissions not detectable from the bundle alone", false],
    ["is_a_standard", "Not a standard", false],
  ];
  const disciplineRows = disciplineItems
    .map(([key, label, wantTrue]) => {
      const present = Object.prototype.hasOwnProperty.call(vd, key);
      const ok = present ? vd[key] === wantTrue : true;
      const mark = ok ? "✓" : "•";
      return `<li class="v02-li"><span class="v02-mark">${mark}</span>${escapeHtml(label)}</li>`;
    })
    .join("");

  // C. L3 taxonomy — clean vs. classified failures.
  const classes = (tax.l3_failure_classification || []);
  let taxBlock;
  if (classes.length === 0) {
    taxBlock = `<p class="v02-clean">No L3 failure classifications.</p>`;
  } else {
    const rows = classes
      .map((e) => {
        const cls = escapeHtml(e.failure_class || "");
        const chk = escapeHtml(e.check || "");
        const means = escapeHtml(e.means || "");
        const dnp = escapeHtml(e.does_not_prove || "");
        return `<li class="v02-fail">
          <div><span class="tag fail-tag">${cls}</span> <span class="mono v02-chk">${chk}</span></div>
          ${means ? `<div class="v02-means">Means: ${means}</div>` : ""}
          ${dnp ? `<div class="v02-dnp">Does not prove: ${dnp}</div>` : ""}
        </li>`;
      })
      .join("");
    taxBlock = `<ul class="v02-taxlist">${rows}</ul>`;
  }
  const boundary = tax.scope_boundary_note || {};
  const boundaryNote = boundary.means
    ? `<p class="footnote">${escapeHtml(boundary.means)}</p>`
    : "";

  // D. Firewall status.
  const findings = (fw.findings || []);
  let fwBlock;
  if (findings.length === 0) {
    fwBlock = `<p class="v02-clean">Firewall applied: true · Findings: 0</p>`;
  } else {
    const items = findings
      .map(
        (f) =>
          `<li class="v02-warn">Overclaim warning: ${escapeHtml(
            f.term || ""
          )} <span class="mono">(${escapeHtml(f.path || "")})</span></li>`
      )
      .join("");
    fwBlock = `<p class="v02-clean">Firewall applied: true · Findings: ${findings.length}</p>
      <ul class="v02-warnlist">${items}</ul>`;
  }

  return `
    <hr class="soft" />
    <div class="v02-section">
      <h3>Oplogica v0.2</h3>
      ${statusCard}
      <h3 class="v02-h">Verification discipline</h3>
      <ul class="v02-disc">${disciplineRows}</ul>
      <h3 class="v02-h">L3 coherence failure taxonomy</h3>
      ${taxBlock}
      ${boundaryNote}
      <h3 class="v02-h">Negative claims firewall</h3>
      ${fwBlock}
    </div>`;
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
