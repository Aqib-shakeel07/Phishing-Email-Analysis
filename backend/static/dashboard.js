const API = "";

const $ = (id) => document.getElementById(id);

let allItems = [];
let currentResultId = null;

document.addEventListener("DOMContentLoaded", () => {
  bindEvents();
  loadAll();
});

/* ---------------- Events ---------------- */

function bindEvents() {
  const refreshBtn = $("refreshBtn");
  const searchInput = $("searchInput");
  const verdictFilter = $("verdictFilter");

  if (refreshBtn) refreshBtn.addEventListener("click", loadAll);
  if (searchInput) searchInput.addEventListener("input", applyFilters);
  if (verdictFilter) verdictFilter.addEventListener("change", applyFilters);

  const navAll = $("navAll");
  const navSafe = $("navSafe");
  const navSuspicious = $("navSuspicious");
  const navPhishing = $("navPhishing");
  if (navAll) navAll.onclick = (e) => { e.preventDefault(); if (verdictFilter) verdictFilter.value = ""; applyFilters(); };
  if (navSafe) navSafe.onclick = (e) => { e.preventDefault(); if (verdictFilter) verdictFilter.value = "Safe"; applyFilters(); };
  if (navSuspicious) navSuspicious.onclick = (e) => { e.preventDefault(); if (verdictFilter) verdictFilter.value = "Suspicious"; applyFilters(); };
  if (navPhishing) navPhishing.onclick = (e) => { e.preventDefault(); if (verdictFilter) verdictFilter.value = "Phishing"; applyFilters(); };

  const exportBtn = $("exportBtn");
  if (exportBtn) exportBtn.onclick = exportJson;

  const newScanBtn = $("newScanBtn");
  const openScanModal = $("openScanModal");
  const promoScanBtn = $("promoScanBtn");
  const closeScanModal = $("closeScanModal");
  const cancelScanBtn = $("cancelScanBtn");
  const runScanBtn = $("runScanBtn");
  const modalFileInput = $("modalFileInput");
  const fileDrop = document.querySelector(".file-drop");

  if (newScanBtn) newScanBtn.onclick = openModal;
  if (openScanModal) openScanModal.onclick = (e) => { e.preventDefault(); openModal(); };
  if (promoScanBtn) promoScanBtn.onclick = (e) => { e.preventDefault(); openModal(); };
  if (closeScanModal) closeScanModal.onclick = closeModal;
  if (cancelScanBtn) cancelScanBtn.onclick = closeModal;
  if (runScanBtn) runScanBtn.onclick = runScan;

  if (modalFileInput) {
    modalFileInput.addEventListener("change", () => {
      const name = modalFileInput.files[0]?.name;
      $("modalFileName").textContent = name ? `📎 ${name}` : "📎 Click to choose a file or drag it here";
    });
  }

  if (fileDrop) {
    ["dragenter", "dragover"].forEach((ev) =>
      fileDrop.addEventListener(ev, (e) => { e.preventDefault(); fileDrop.classList.add("dragover"); })
    );
    ["dragleave", "drop"].forEach((ev) =>
      fileDrop.addEventListener(ev, (e) => { e.preventDefault(); fileDrop.classList.remove("dragover"); })
    );
    fileDrop.addEventListener("drop", (e) => {
      const f = e.dataTransfer.files[0];
      if (f && modalFileInput) {
        modalFileInput.files = e.dataTransfer.files;
        $("modalFileName").textContent = `📎 ${f.name}`;
      }
    });
  }

  const closeResultModal = $("closeResultModal");
  const resultCloseBtn = $("resultCloseBtn");
  const resultJsonBtn = $("resultJsonBtn");
  const resultPdfBtn = $("resultPdfBtn");
  const resultModal = $("resultModal");
  const scanModal = $("scanModal");

  if (closeResultModal) closeResultModal.onclick = closeResult;
  if (resultCloseBtn) resultCloseBtn.onclick = closeResult;
  if (resultJsonBtn) resultJsonBtn.onclick = () => currentResultId && window.open(`/api/analyses/${currentResultId}/report?format=json`, "_blank");
  if (resultPdfBtn) resultPdfBtn.onclick = () => currentResultId && window.open(`/api/analyses/${currentResultId}/report?format=pdf`, "_blank");

  if (resultModal) resultModal.addEventListener("click", (e) => { if (e.target === resultModal) closeResult(); });
  if (scanModal) scanModal.addEventListener("click", (e) => { if (e.target === scanModal) closeModal(); });

  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") { closeModal(); closeResult(); }
  });
}

/* ---------------- Scan modal ---------------- */

function openModal() {
  const overlay = $("scanModal");
  if (!overlay) return;
  overlay.classList.remove("hidden");
  setStatus("", "hidden");
  const fi = $("modalFileInput");
  const raw = $("modalRawInput");
  if (fi) fi.value = "";
  if (raw) raw.value = "";
  const nameEl = $("modalFileName");
  if (nameEl) nameEl.textContent = "📎 Click to choose a file or drag it here";
}

function closeModal() {
  const overlay = $("scanModal");
  if (overlay) overlay.classList.add("hidden");
}

function setStatus(msg, type = "") {
  const el = $("modalStatus");
  if (!el) return;
  if (!msg) { el.className = "modal-status hidden"; el.textContent = ""; return; }
  el.className = `modal-status ${type}`;
  el.textContent = msg;
  el.classList.remove("hidden");
}

async function runScan() {
  const runScanBtn = $("runScanBtn");
  const file = $("modalFileInput")?.files[0];
  const raw = $("modalRawInput")?.value.trim();

  if (!file && !raw) {
    setStatus("Please upload a file or paste raw email source.", "error");
    return;
  }

  runScanBtn.disabled = true;
  setStatus("Analyzing email...", "");

  try {
    let res;
    if (file) {
      const fd = new FormData();
      fd.append("file", file);
      res = await fetch(`${API}/api/analyze`, { method: "POST", body: fd });
    } else {
      res = await fetch(`${API}/api/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ raw }),
      });
    }

    const data = await res.json();
    if (!res.ok || !data.success) throw new Error(data.error || "Analysis failed");

    const a = data.analysis;
    setStatus(`✓ Done — Verdict: ${a.verdict} (${a.final_score}/100)`, "success");

    await loadAll();

    setTimeout(() => {
      closeModal();
      showResult(a);
    }, 400);
  } catch (err) {
    setStatus("Error: " + err.message, "error");
  } finally {
    runScanBtn.disabled = false;
  }
}

/* ---------------- Result modal ---------------- */

async function openResultById(id) {
  try {
    const res = await fetch(`${API}/api/analyses/${id}`);
    if (!res.ok) throw new Error("Failed to load analysis");
    const a = await res.json();
    showResult(a);
  } catch (err) { alert("Error: " + err.message); }
}

function closeResult() {
  const overlay = $("resultModal");
  if (overlay) overlay.classList.add("hidden");
}

function showResult(a) {
  currentResultId = a.id;
  const body = $("resultBody");
  if (!body) return;

  body.innerHTML = `
    ${renderBanner(a)}
    ${renderAuth(a)}
    ${renderHeaderCard(a)}
    ${renderTriggered(a)}
    ${renderUrlsCard(a)}
    ${renderEncodedParts(a)}
    ${renderIpsCard(a)}
    ${renderAttachmentsCard(a)}
    ${renderRawHeaders(a)}
  `;

  const overlay = $("resultModal");
  if (overlay) overlay.classList.remove("hidden");
}

function renderBanner(a) {
  const cls = (a.verdict || "Unknown").toLowerCase();
  return `
    <div class="result-banner ${cls}">
      <div>
        <div class="result-verdict ${cls}">Verdict: ${escapeHtml(a.verdict || "Unknown")}</div>
        <div class="result-sub">${escapeHtml(a.explanation || "")}</div>
      </div>
      <div class="result-score">${a.final_score ?? 0}/100</div>
    </div>`;
}

function renderAuth(a) {
  const rows = [
    ["SPF",   authCell(a.spf_present,   a.spf_pass)],
    ["DKIM",  authCell(a.dkim_present,  a.dkim_pass)],
    ["DMARC", authCell(a.dmarc_present, a.dmarc_pass)],
  ];
  let html = rows.map(([k, v]) => `<tr><td>${escapeHtml(k)}</td><td>${v}</td></tr>`).join("");
  if (!a.spf_present && !a.dkim_present && !a.dmarc_present) {
    html += `<tr><td colspan="2" class="muted" style="color:#f59e0b;">⚠ No SPF / DKIM / DMARC headers found.</td></tr>`;
  }
  return `<div class="result-card"><h4>Authentication Status</h4><table class="result-kv">${html}</table></div>`;
}

function authCell(present, pass) {
  if (!present) return `<span class="badge suspicious">NOT PRESENT</span>`;
  if (pass === true) return `<span class="badge safe">PASS</span>`;
  if (pass === false) return `<span class="badge phishing">FAIL</span>`;
  return `<span class="badge suspicious">PRESENT (unknown)</span>`;
}

function renderHeaderCard(a) {
  const toList = (a.to || []).map(formatAddress).join(", ") || "—";
  const ccList = (a.cc || []).map(formatAddress).join(", ") || "—";
  const rows = [
    ["From (name)",   a.sender_name || "—"],
    ["From (email)",  a.sender || "—"],
    ["Sender Domain", a.sender_domain || "—"],
    ["To",            toList],
    ["Cc",            ccList],
    ["Reply-To",      a.reply_to || "—"],
    ["Reply-To Domain", a.reply_to_domain || "—"],
    ["Return-Path",   a.return_path || "—"],
    ["Return-Path Domain", a.return_path_domain || "—"],
    ["Subject",       a.subject || "—"],
    ["Date",          a.date || "—"],
    ["Message-ID",    a.message_id || "—"],
    ["Received Hops", (a.received_chain || []).length],
  ];
  let html = rows.map(([k, v]) => `<tr><td>${escapeHtml(k)}</td><td>${escapeHtml(String(v))}</td></tr>`).join("");
  if (a.received_chain && a.received_chain.length) {
    const hops = a.received_chain.map((h, i) => `[${i + 1}] ${escapeHtml(h)}`).join("\n");
    html += `<tr><td>Received Chain</td><td><pre class="raw-pre small-pre">${hops}</pre></td></tr>`;
  }
  return `<div class="result-card"><h4>Message Header</h4><table class="result-kv">${html}</table></div>`;
}

function formatAddress(entry) {
  if (!entry) return "";
  if (typeof entry === "string") return entry;
  const name = entry[0] || "";
  const email = entry[1] || "";
  return name ? `${name} <${email}>` : email;
}

function renderTriggered(a) {
  const flags = a.triggered_features || [];
  if (!flags.length) return `<div class="result-card"><h4>Triggered Features</h4><p class="muted">No suspicious features detected.</p></div>`;
  const items = flags.map((f) => `<li><span class="module-tag">${escapeHtml(f.module)}</span>${escapeHtml(f.detail)}</li>`).join("");
  return `<div class="result-card"><h4>Triggered Features</h4><ul class="flag-list">${items}</ul></div>`;
}

function renderUrlsCard(a) {
  const urls = a.urls_found || [];
  if (!urls.length) return `<div class="result-card"><h4>URLs Found</h4><p class="muted">No URLs extracted.</p></div>`;

  const groups = {};
  urls.forEach((u) => { const d = u.domain || "(unknown)"; if (!groups[d]) groups[d] = []; groups[d].push(u); });
  const order = Object.keys(groups).sort((x, y) => getGroupScore(groups[y]) - getGroupScore(groups[x]));

  let html = "";
  order.forEach((domain) => {
    const items = groups[domain];
    const maxScore = getGroupScore(items);
    const cls = maxScore >= 60 ? "phishing" : maxScore >= 30 ? "suspicious" : "safe";
    html += `<div class="url-group"><div class="url-group-header">
      <span class="url-group-domain">${escapeHtml(domain)}</span>
      <span class="badge ${cls}">${items.length} URL${items.length > 1 ? "s" : ""} · max ${maxScore}</span>
    </div>`;
    items.forEach((u) => {
      const full = u.url || "";
      const preview = shortenUrl(full);
      const uniqueFlags = [...new Set(u.flags || [])].map((f) => cleanFlag(f, full)).filter(Boolean);
      const flagText = uniqueFlags.length ? " · ⚠ " + uniqueFlags.map(escapeHtml).join(" · ") : "";
      html += `<div class="url-item">
        <div class="url">${escapeHtml(preview)}</div>
        <details class="url-details"><summary>show full URL</summary><pre class="raw-pre small-pre">${escapeHtml(full)}</pre></details>
        <div class="meta">Score: ${u.score}${flagText}</div>
      </div>`;
    });
    html += `</div>`;
  });
  return `<div class="result-card"><h4>URLs Found</h4>${html}</div>`;
}

/**
 * MIME-decoded parts (base64 / quoted-printable payloads) — already
 * decoded server-side, one entry per MIME part that had a transfer
 * encoding applied.
 */
function renderEncodedParts(a) {
  const parts = a.encoded_parts || [];
  if (!parts.length) {
    return `<div class="result-card"><h4>Encoded / Obfuscated Parts</h4><p class="muted">No encoded MIME parts detected.</p></div>`;
  }
  const items = parts.map((p, idx) => {
    const kind = p.is_binary ? (p.magic || "binary") : "text";
    const kindClass = p.is_binary ? "hex" : "base64";
    const header = `
      <div class="encoded-item-head">
        <span class="encoded-type ${kindClass}">${escapeHtml(kind)}</span>
        <span class="encoded-source">
          part #${p.part_index} · ${escapeHtml(p.content_type)} ·
          ${escapeHtml(p.transfer_encoding)}
          ${p.charset ? `· ${escapeHtml(p.charset)}` : ""}
          · ${p.decoded_bytes_len} bytes
        </span>
      </div>`;
    const filenameRow = p.filename
      ? `<div class="meta" style="margin-bottom:6px">📎 ${escapeHtml(p.filename)}${p.content_disposition ? ` · ${escapeHtml(p.content_disposition)}` : ""}</div>`
      : "";

    const preview = p.decoded_text.length > 4000
      ? p.decoded_text.slice(0, 4000) + "…"
      : p.decoded_text;

    return `
      <div class="encoded-item">
        ${header}
        ${filenameRow}
        <div class="encoded-value" id="enc-val-${idx}">${escapeHtml(preview)}</div>
        <div class="encoded-actions">
          <button class="encoded-btn" data-download="${idx}">Download</button>
          <button class="encoded-btn" data-copy="${idx}">Copy</button>
          ${!p.is_binary ? `<button class="encoded-btn" data-toggle-decoded="${idx}">Show raw</button>` : ""}
        </div>
        ${!p.is_binary ? `<div class="encoded-decoded hidden" id="enc-dec-${idx}"></div>` : ""}
      </div>
    `;
  }).join("");
  return `<div class="result-card"><h4>Encoded / Obfuscated Parts</h4>${items}</div>`;
}

function bindEncodedPartActions(parts) {
  document.querySelectorAll("[data-copy]").forEach((btn) => {
    btn.onclick = async () => {
      const idx = Number(btn.dataset.copy);
      const p = parts[idx];
      if (!p) return;
      try {
        await navigator.clipboard.writeText(p.decoded_text);
        btn.textContent = "Copied ✓";
        btn.classList.add("copied");
        setTimeout(() => { btn.textContent = "Copy"; btn.classList.remove("copied"); }, 1200);
      } catch { btn.textContent = "Failed"; }
    };
  });

  document.querySelectorAll("[data-download]").forEach((btn) => {
    btn.onclick = () => {
      const idx = Number(btn.dataset.download);
      const p = parts[idx];
      if (!p) return;
      const name = p.filename || `part-${p.part_index}.txt`;
      let blob;
      if (p.is_binary) {
        // decoded_text holds base64 of the payload — decode to bytes
        const bin = atob(p.decoded_text);
        const bytes = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
        blob = new Blob([bytes], { type: p.content_type || "application/octet-stream" });
      } else {
        blob = new Blob([p.decoded_text], { type: p.content_type || "text/plain" });
      }
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url; a.download = name;
      a.click();
      URL.revokeObjectURL(url);
    };
  });

  document.querySelectorAll("[data-toggle-decoded]").forEach((btn) => {
    btn.onclick = () => {
      const idx = btn.dataset.toggleDecoded;
      const p = parts[idx];
      if (!p) return;
      const target = document.getElementById(`enc-dec-${idx}`);
      if (!target) return;
      if (!target.classList.contains("hidden")) {
        target.classList.add("hidden");
        btn.textContent = "Show raw";
        return;
      }
      // Show the header block from the raw email (what was there before decode)
      const rawHeader = `Content-Type: ${p.content_type}\nContent-Transfer-Encoding: ${p.transfer_encoding}${p.charset ? `\nContent-Charset: ${p.charset}` : ""}`;
      target.textContent = rawHeader;
      target.classList.remove("hidden");
      btn.textContent = "Hide raw";
    };
  });
}

function renderIpsCard(a) {
  const ips = a.ips_found || [];
  if (!ips.length) return `<div class="result-card"><h4>IP Addresses Found</h4><p class="muted">No IP addresses found.</p></div>`;
  const items = ips.map((i) => {
    const tags = [];
    if (i.private) tags.push("private");
    if (i.loopback) tags.push("loopback");
    if (i.link_local) tags.push("link-local");
    if (i.multicast) tags.push("multicast");
    if (i.public) tags.push("public");
    const cls = i.public ? "phishing" : "safe";
    return `<div class="url-item">
      <div class="url">${escapeHtml(i.ip)}</div>
      <div class="meta"><span class="badge ${cls}">${i.public ? "PUBLIC" : "PRIVATE"}</span>${tags.map((t) => `<span class="module-tag">${t}</span>`).join(" ")}</div>
    </div>`;
  }).join("");
  return `<div class="result-card"><h4>IP Addresses Found</h4>${items}</div>`;
}

function renderAttachmentsCard(a) {
  const atts = a.attachments || [];
  if (!atts.length) return `<div class="result-card"><h4>Attachments</h4><p class="muted">No attachments.</p></div>`;
  const items = atts.map((at) => `
    <div class="url-item">
      <div class="url">${escapeHtml(at.filename || "")}</div>
      <div class="meta">${escapeHtml(at.content_type || "")} · ${at.size} bytes · Score: ${at.score}</div>
      ${(at.flags && at.flags.length) ? `<div class="meta">⚠ ${at.flags.map(escapeHtml).join(" · ")}</div>` : ""}
    </div>
  `).join("");
  return `<div class="result-card"><h4>Attachments</h4>${items}</div>`;
}

function renderRawHeaders(a) {
  if (!a.raw_headers) return `<div class="result-card"><h4>Raw Headers</h4><p class="muted">(none)</p></div>`;
  return `<div class="result-card"><h4>Raw Headers</h4>
    <details><summary style="cursor:pointer;color:var(--accent)">Show / hide raw email headers</summary>
      <pre class="raw-pre">${escapeHtml(a.raw_headers)}</pre>
    </details>
  </div>`;
}

const URL_PREVIEW_LEN = 90;
function shortenUrl(url) {
  if (!url) return "";
  if (url.length <= URL_PREVIEW_LEN) return url;
  return url.slice(0, 55) + "…" + url.slice(-25) + `  [${url.length} chars]`;
}
function cleanFlag(flagText, fullUrl) {
  if (!flagText) return "";
  let t = flagText;
  if (fullUrl) t = t.split(fullUrl).join("");
  t = t.replace(/https?:\/\/\S+/g, "");
  t = t.replace(/(Unusually long URL|Extremely long URL)\s*:?\s*/gi, "");
  t = t.replace(/\s*·\s*·/g, " · ");
  t = t.replace(/^\s*·\s*|\s*·\s*$/g, "");
  t = t.replace(/\s{2,}/g, " ").trim();
  return t;
}
function getGroupScore(items) { return Math.max(...items.map((i) => i.score || 0)); }

/* ---------------- Data loads ---------------- */

async function loadAll() {
  await Promise.all([loadStats(), loadHistory(), loadEncodedText()]);
}

async function loadStats() {
  try {
    const res = await fetch(`${API}/api/stats`);
    const data = await res.json();
    const total = data.total ?? 0;
    const safe = data.safe ?? 0;
    const sus = data.suspicious ?? 0;
    const phish = data.phishing ?? 0;
    setText("statTotal", total);
    setText("statSafe", safe);
    setText("statSuspicious", sus);
    setText("statPhishing", phish);
    renderCharts({ total, safe, sus, phish });
  } catch (err) { console.error("stats failed", err); }
}

/**
 * Load analyses and render the Encoded card from encoded_parts.
 * We also stash the parts on window so the copy/download buttons
 * can access them.
 */
async function loadEncodedText() {
  try {
    const res = await fetch(`${API}/api/analyses?limit=500`);
    const data = await res.json();
    const items = data.items || [];

    // Flatten encoded_parts from every analysis
    const allParts = [];
    items.forEach((a) => {
      (a.encoded_parts || []).forEach((p) => {
        allParts.push({ ...p, _analysis_id: a.id });
      });
    });

    // Dedupe by decoded_text (same blob across scans)
    const seen = new Map();
    allParts.forEach((p) => {
      const key = p.decoded_text;
      if (!seen.has(key)) seen.set(key, p);
    });
    const unique = Array.from(seen.values());

    // Sort: text first, then binary; larger first within group
    unique.sort((x, y) => {
      if (x.is_binary !== y.is_binary) return x.is_binary ? 1 : -1;
      return y.decoded_bytes_len - x.decoded_bytes_len;
    });

    const container = $("encodedContainer");
    const countEl = $("encodedCount");
    if (!container) return;

    if (countEl) countEl.textContent = `${unique.length} item${unique.length === 1 ? "" : "s"}`;

    if (!unique.length) {
      container.innerHTML = `<p class="muted">No encoded MIME parts detected yet.</p>`;
      return;
    }

    container.innerHTML = unique.map((p, idx) => {
      const kind = p.is_binary ? (p.magic || "binary") : "text";
      const kindClass = p.is_binary ? "hex" : "base64";
      const filenameRow = p.filename
        ? `<div class="meta" style="margin-bottom:6px">📎 ${escapeHtml(p.filename)}${p.content_disposition ? ` · ${escapeHtml(p.content_disposition)}` : ""}</div>`
        : "";
      const preview = p.decoded_text.length > 4000
        ? p.decoded_text.slice(0, 4000) + "…"
        : p.decoded_text;
      return `
        <div class="encoded-item">
          <div class="encoded-item-head">
            <span class="encoded-type ${kindClass}">${escapeHtml(kind)}</span>
            <span class="encoded-source">
              #${p._analysis_id} · part #${p.part_index} ·
              ${escapeHtml(p.content_type)} · ${escapeHtml(p.transfer_encoding)}
              ${p.charset ? `· ${escapeHtml(p.charset)}` : ""} ·
              ${p.decoded_bytes_len} bytes
            </span>
          </div>
          ${filenameRow}
          <div class="encoded-value" id="enc-val-${idx}">${escapeHtml(preview)}</div>
          <div class="encoded-actions">
            <button class="encoded-btn" data-download="${idx}">Download</button>
            <button class="encoded-btn" data-copy="${idx}">Copy</button>
          </div>
        </div>
      `;
    }).join("");

    // Wire actions
    container.querySelectorAll("[data-copy]").forEach((btn) => {
      btn.onclick = async () => {
        const p = unique[Number(btn.dataset.copy)];
        if (!p) return;
        try {
          await navigator.clipboard.writeText(p.decoded_text);
          btn.textContent = "Copied ✓";
          btn.classList.add("copied");
          setTimeout(() => { btn.textContent = "Copy"; btn.classList.remove("copied"); }, 1200);
        } catch { btn.textContent = "Failed"; }
      };
    });

    container.querySelectorAll("[data-download]").forEach((btn) => {
      btn.onclick = () => {
        const p = unique[Number(btn.dataset.download)];
        if (!p) return;
        const name = p.filename || `part-${p.part_index}.${p.is_binary ? "bin" : "txt"}`;
        let blob;
        if (p.is_binary) {
          const bin = atob(p.decoded_text);
          const bytes = new Uint8Array(bin.length);
          for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
          blob = new Blob([bytes], { type: p.content_type || "application/octet-stream" });
        } else {
          blob = new Blob([p.decoded_text], { type: p.content_type || "text/plain" });
        }
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url; a.download = name;
        a.click();
        URL.revokeObjectURL(url);
      };
    });
  } catch (err) {
    console.error("encoded parts load failed", err);
  }
}

function setText(id, value) { const el = $(id); if (el) el.textContent = value; }

function renderCharts({ total, safe, sus, phish }) {
  const max = Math.max(safe, sus, phish, 1);
  setBar("barSafe", "barSafeVal", safe, max);
  setBar("barSuspicious", "barSuspiciousVal", sus, max);
  setBar("barPhishing", "barPhishingVal", phish, max);
  const threats = sus + phish;
  const rate = total > 0 ? Math.round((threats / total) * 100) : 0;
  const donutValue = $("donutValue");
  if (donutValue) donutValue.textContent = `${rate}%`;
  const donutFg = $("donutFg");
  if (donutFg) {
    const circ = 2 * Math.PI * 50;
    donutFg.style.strokeDasharray = circ;
    donutFg.style.strokeDashoffset = circ - (rate / 100) * circ;
  }
}

function setBar(barId, valId, value, max) {
  const bar = $(barId); const val = $(valId);
  if (bar) bar.style.width = `${(value / max) * 100}%`;
  if (val) val.textContent = value;
}

async function loadHistory() {
  const tbody = $("historyBody");
  if (!tbody) return;
  tbody.innerHTML = `<tr><td colspan="7" class="muted">Loading...</td></tr>`;
  try {
    const res = await fetch(`${API}/api/analyses?limit=200`);
    const data = await res.json();
    allItems = data.items || [];
    applyFilters();
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="7" class="muted">Failed to load.</td></tr>`;
  }
}

function applyFilters() {
  const searchInput = $("searchInput");
  const verdictFilter = $("verdictFilter");
  const q = searchInput ? searchInput.value.trim().toLowerCase() : "";
  const verdict = verdictFilter ? verdictFilter.value : "";
  const filtered = allItems.filter((it) => {
    if (verdict && it.verdict !== verdict) return false;
    if (!q) return true;
    const hay = `${it.sender || ""} ${it.subject || ""} ${it.sender_domain || ""}`.toLowerCase();
    return hay.includes(q);
  });
  renderTable(filtered);
}

function renderTable(items) {
  const tbody = $("historyBody");
  if (!tbody) return;
  if (!items.length) {
    tbody.innerHTML = `<tr><td colspan="7" class="muted">No analyses found.</td></tr>`;
    return;
  }
  tbody.innerHTML = items.map((it) => {
    const cls = (it.verdict || "Unknown").toLowerCase();
    const date = it.created_at ? new Date(it.created_at).toLocaleString() : "-";
    return `<tr>
      <td>#${it.id}</td>
      <td>${escapeHtml(date)}</td>
      <td>${escapeHtml(it.sender || "-")}</td>
      <td class="subject-cell" title="${escapeHtml(it.subject || "")}">${escapeHtml(it.subject || "(no subject)")}</td>
      <td>${it.final_score ?? 0}</td>
      <td><span class="badge ${cls}">${escapeHtml(it.verdict || "Unknown")}</span></td>
      <td>
        <button class="icon-btn-row" data-action="view" data-id="${it.id}">View</button>
        <button class="icon-btn-row" data-action="json" data-id="${it.id}">JSON</button>
        <button class="icon-btn-row" data-action="pdf" data-id="${it.id}">PDF</button>
        <button class="icon-btn-row" data-action="delete" data-id="${it.id}">🗑</button>
      </td>
    </tr>`;
  }).join("");

  tbody.querySelectorAll(".icon-btn-row").forEach((btn) => btn.addEventListener("click", onRowAction));
}

async function onRowAction(e) {
  const action = e.currentTarget.dataset.action;
  const id = e.currentTarget.dataset.id;
  if (action === "view") openResultById(id);
  else if (action === "json") window.open(`/api/analyses/${id}/report?format=json`, "_blank");
  else if (action === "pdf") window.open(`/api/analyses/${id}/report?format=pdf`, "_blank");
  else if (action === "delete") {
    if (!confirm(`Delete analysis #${id}?`)) return;
    await fetch(`${API}/api/analyses/${id}`, { method: "DELETE" });
    loadAll();
  }
}

/* ---------------- Utils ---------------- */

function exportJson() {
  const blob = new Blob([JSON.stringify(allItems, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = `analyses_${Date.now()}.json`;
  a.click(); URL.revokeObjectURL(url);
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;")
    .replace(/>/g, "&gt;").replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}