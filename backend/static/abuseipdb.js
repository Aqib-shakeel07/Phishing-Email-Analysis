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
    ${renderEncodedCard(a)}
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

function renderEncodedCard(a) {
  const urls = a.urls_found || [];
  const encoded = urls.filter((u) =>
    (u.flags || []).some((f) => /encoded|obfuscated|base64|%[0-9a-f]{2}/i.test(f)) ||
    (u.url && /%[0-9a-fA-F]{2}/.test(u.url))
  );
  if (!encoded.length) return `<div class="result-card"><h4>Encoded / Obfuscated URLs</h4><p class="muted">None detected.</p></div>`;
  const items = encoded.map((u) => {
    const flags = [...new Set(u.flags || [])].map((f) => cleanFlag(f, u.url || "")).filter(Boolean);
    return `<div class="url-item">
      <div class="url">${escapeHtml(shortenUrl(u.url || ""))}</div>
      <details class="url-details"><summary>show full URL</summary><pre class="raw-pre small-pre">${escapeHtml(u.url || "")}</pre></details>
      <div class="meta"><span class="encoded-badge">${flags.length} signal(s)</span>${flags.map(escapeHtml).join(" · ")}</div>
    </div>`;
  }).join("");
  return `<div class="result-card"><h4>Encoded / Obfuscated URLs</h4>${items}</div>`;
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

/* ============================================================
   ENCODED / OBFUSCATED TEXT CARD
   ============================================================ */

const B64_RE = /(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?/g;
const URLENC_RE = /(?:%[0-9A-Fa-f]{2}){4,}/g;
const HEX_RE = /(?:\\x[0-9A-Fa-f]{2}){4,}/g;

function extractEncodedFromAnalysis(a) {
  const found = [];
  const push = (value, type, source) => {
    if (!value) return;
    found.push({ value: value.trim(), type, source });
  };

  /* ---- Helper: strip HTML tags but keep all textual content ---- */
  function stripHtml(html) {
    if (!html) return "";
    return html
      .replace(/<style[\s\S]*?<\/style>/gi, " ")
      .replace(/<script[\s\S]*?<\/script>/gi, " ")
      .replace(/<[^>]+>/g, " ")
      .replace(/&nbsp;/g, " ")
      .replace(/&amp;/g, "&")
      .replace(/&lt;/g, "<")
      .replace(/&gt;/g, ">")
      .replace(/&quot;/g, "\"")
      .replace(/&#39;/g, "'");
  }

  /* ---- Helper: scan a text blob for base64/url/hex ---- */
  function scanBlob(text, source) {
    if (!text) return;

    // Join line continuations (base64 wrapped over multiple lines)
    const joined = text.replace(/[\r\n]+[ \t]+/g, "");

    // Base64 candidates
    const b64Matches = joined.match(B64_RE);
    if (b64Matches) {
      const merged = mergeAdjacentBase64(b64Matches, joined);
      merged
        .filter((m) => m.length >= 40)
        .forEach((m) => push(m, "base64", source));
    }

    // URL-encoded
    const urlMatches = joined.match(URLENC_RE);
    if (urlMatches) {
      // merge adjacent URL-encoded chunks into one
      const merged = mergeAdjacent(urlMatches, joined);
      merged
        .filter((m) => m.length >= 20)
        .forEach((m) => push(m, "url", source));
    }

    // Hex escapes
    const hexMatches = joined.match(HEX_RE);
    if (hexMatches) {
      const merged = mergeAdjacent(hexMatches, joined);
      merged.filter((m) => m.length >= 20).forEach((m) => push(m, "hex", source));
    }
  }

  /* 1. Headers */
  scanBlob(a.raw_headers || "", `#${a.id} · Headers`);

  /* 2. Subject */
  scanBlob(a.subject || "", `#${a.id} · Subject`);

  /* 3. HTML body (strip tags, keep text) */
  const htmlText = stripHtml(a.body_html || "");
  scanBlob(htmlText, `#${a.id} · HTML body`);

  /* 4. Plain-text body */
  scanBlob(a.body_text || "", `#${a.id} · Text body`);

  /* 5. URLs — pull whole path when it looks like one big base64 */
  (a.urls_found || []).forEach((u) => {
    const url = u.url || "";
    try {
      const uo = new URL(url.startsWith("http") ? url : "http://" + url);
      const path = uo.pathname.replace(/^\/+/, "");
      if (path && path.length >= 40) {
        const cleaned = path.replace(/[-_]/g, "");
        if (/^[A-Za-z0-9+/=]+$/.test(cleaned)) {
          push(cleaned, "base64", `#${a.id} · URL path`);
        } else {
          const chunks = cleaned.match(B64_RE);
          if (chunks) {
            const longest = chunks.sort((x, y) => y.length - x.length)[0];
            if (longest && longest.length >= 40) push(longest, "base64", `#${a.id} · URL path`);
          }
        }
      }
      const q = uo.search.replace(/^\?/, "");
      scanBlob(q, `#${a.id} · URL query`);
    } catch {
      scanBlob(url, `#${a.id} · URL`);
    }
  });

  /* 6. Attachments (filenames) */
  (a.attachments || []).forEach((at) => {
    scanBlob(at.filename || "", `#${a.id} · Attachment name`);
  });

  return found;
}

function mergeAdjacent(matches, original) {
  const withPos = matches
    .map((m) => ({ str: m, pos: original.indexOf(m) }))
    .filter((x) => x.pos >= 0)
    .sort((a, b) => a.pos - b.pos);

  const merged = [];
  let current = null;
  for (const { str, pos } of withPos) {
    if (current && pos <= current.end + 4) {
      current.str += str;
      current.end = pos + str.length;
    } else {
      if (current) merged.push(current.str);
      current = { str, pos, end: pos + str.length };
    }
  }
  if (current) merged.push(current.str);
  return merged;
}

const mergeAdjacentBase64 = mergeAdjacent;

function tryBase64Decode(s) {
  try {
    const clean = s.replace(/\s+/g, "");
    const padded = clean + "=".repeat((4 - (clean.length % 4)) % 4);
    const decoded = atob(padded);
    const printable = decoded.split("").filter((c) => {
      const n = c.charCodeAt(0);
      return (n >= 32 && n < 127) || n === 9 || n === 10 || n === 13;
    }).length;
    if (printable / decoded.length < 0.6) return null;
    return decoded;
  } catch { return null; }
}

function tryUrlDecode(s) {
  try { return decodeURIComponent(s); }
  catch { return null; }
}

function renderEncodedText(items) {
  const container = $("encodedContainer");
  const countEl = $("encodedCount");
  if (!container) return;

  let all = [];
  items.forEach((a) => { all = all.concat(extractEncodedFromAnalysis(a)); });

  const seen = new Set();
  const unique = [];
  all.forEach((e) => {
    const key = e.type + "::" + e.value;
    if (seen.has(key)) return;
    seen.add(key);
    unique.push(e);
  });

  const order = { base64: 0, url: 1, hex: 2, other: 3 };
  unique.sort((x, y) => {
    const t = order[x.type] - order[y.type];
    if (t !== 0) return t;
    return y.value.length - x.value.length;
  });

  if (countEl) countEl.textContent = `${unique.length} item${unique.length === 1 ? "" : "s"}`;

  if (!unique.length) {
    container.innerHTML = `<p class="muted">No encoded text detected yet.</p>`;
    return;
  }

  container.innerHTML = unique.map((e, idx) => {
    const preview = e.value;
    return `
      <div class="encoded-item">
        <div class="encoded-item-head">
          <span class="encoded-type ${e.type}">${e.type}</span>
          <span class="encoded-source">${escapeHtml(e.source)} · ${e.value.length} chars</span>
        </div>
        <div class="encoded-value" id="enc-val-${idx}">${escapeHtml(preview)}</div>
        <div class="encoded-actions">
          <button class="encoded-btn" data-copy="${idx}">Copy</button>
          <button class="encoded-btn" data-decode="${idx}" data-type="${e.type}">Decode</button>
        </div>
        <div class="encoded-decoded hidden" id="enc-dec-${idx}"></div>
      </div>
    `;
  }).join("");

  container.querySelectorAll("[data-copy]").forEach((btn) => {
    btn.onclick = async () => {
      const idx = btn.dataset.copy;
      const item = unique[idx];
      if (!item) return;
      try {
        await navigator.clipboard.writeText(item.value);
        btn.textContent = "Copied ✓";
        btn.classList.add("copied");
        setTimeout(() => { btn.textContent = "Copy"; btn.classList.remove("copied"); }, 1200);
      } catch { btn.textContent = "Failed"; }
    };
  });

  container.querySelectorAll("[data-decode]").forEach((btn) => {
    btn.onclick = () => {
      const idx = btn.dataset.decode;
      const item = unique[idx];
      if (!item) return;
      const target = document.getElementById(`enc-dec-${idx}`);
      if (!target) return;

      if (!target.classList.contains("hidden")) {
        target.classList.add("hidden");
        btn.textContent = "Decode";
        return;
      }

      let decoded = null;
      if (item.type === "base64") decoded = tryBase64Decode(item.value);
      else if (item.type === "url") decoded = tryUrlDecode(item.value);

      if (!decoded) decoded = tryBase64Decode(item.value);
      if (!decoded) decoded = tryUrlDecode(item.value);
      if (!decoded) decoded = "(could not decode)";

      target.textContent = decoded;
      target.classList.remove("hidden");
      btn.textContent = "Hide decoded";
    };
  });
}

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

async function loadEncodedText() {
  try {
    // Pull last 500 analyses WITH body_text + body_html
    const res = await fetch(`${API}/api/analyses?limit=500`);
    const data = await res.json();
    renderEncodedText(data.items || []);
  } catch (err) {
    console.error("encoded text load failed", err);
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