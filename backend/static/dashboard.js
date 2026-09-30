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

  // Sidebar filters
  const navAll = $("navAll");
  const navSafe = $("navSafe");
  const navSuspicious = $("navSuspicious");
  const navPhishing = $("navPhishing");
  if (navAll) navAll.onclick = (e) => { e.preventDefault(); if (verdictFilter) verdictFilter.value = ""; applyFilters(); };
  if (navSafe) navSafe.onclick = (e) => { e.preventDefault(); if (verdictFilter) verdictFilter.value = "Safe"; applyFilters(); };
  if (navSuspicious) navSuspicious.onclick = (e) => { e.preventDefault(); if (verdictFilter) verdictFilter.value = "Suspicious"; applyFilters(); };
  if (navPhishing) navPhishing.onclick = (e) => { e.preventDefault(); if (verdictFilter) verdictFilter.value = "Phishing"; applyFilters(); };

  // Export
  const exportBtn = $("exportBtn");
  if (exportBtn) exportBtn.onclick = exportJson;

  // Scan modal
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

  // Result modal
  const closeResultModal = $("closeResultModal");
  const resultCloseBtn = $("resultCloseBtn");
  const resultJsonBtn = $("resultJsonBtn");
  const resultPdfBtn = $("resultPdfBtn");
  const resultEnrichBtn = $("resultEnrichBtn");
  const resultModal = $("resultModal");
  const scanModal = $("scanModal");

  if (closeResultModal) closeResultModal.onclick = closeResult;
  if (resultCloseBtn) resultCloseBtn.onclick = closeResult;
  if (resultJsonBtn) resultJsonBtn.onclick = () => currentResultId && window.open(`/api/analyses/${currentResultId}/report?format=json`, "_blank");
  if (resultPdfBtn) resultPdfBtn.onclick = () => currentResultId && window.open(`/api/analyses/${currentResultId}/report?format=pdf`, "_blank");
  if (resultEnrichBtn) resultEnrichBtn.onclick = runEnrichment;

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
  } catch (err) {
    alert("Error: " + err.message);
  }
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
    ${renderAuthSummary(a)}
    ${renderHops(a)}
    ${renderHeaderCard(a)}
    ${renderFullHeaders(a)}
    ${renderTriggered(a)}
    ${renderUrlsCard(a)}
    ${renderEncodedCard(a)}
    ${renderIpsCard(a)}
    ${renderAttachmentsCard(a)}
    ${renderRawHeaders(a)}
    <div id="enrichmentZone"></div>
  `;

  const overlay = $("resultModal");
  if (overlay) overlay.classList.remove("hidden");
}

/* ---- Enrich with VT + AbuseIPDB ---- */
async function runEnrichment() {
  if (!currentResultId) return;
  const zone = $("enrichmentZone");
  if (!zone) return;

  zone.innerHTML = `<div class="result-card"><h4>🌐 Enrichment</h4><p class="muted">Querying VirusTotal & AbuseIPDB…</p></div>`;

  try {
    const res = await fetch(`${API}/api/enrich/${currentResultId}`);
    const data = await res.json();
    if (!res.ok || data.error) {
      zone.innerHTML = `<div class="result-card"><h4>Enrichment</h4><p class="muted">❌ ${escapeHtml(data.error || "failed")}</p></div>`;
      return;
    }
    renderEnrichment(zone, data);
  } catch (err) {
    zone.innerHTML = `<div class="result-card"><h4>Enrichment</h4><p class="muted">❌ ${escapeHtml(err.message)}</p></div>`;
  }
}

function renderEnrichment(zone, data) {
  const vt = data.virustotal || {};
  const abuse = data.abuseipdb || {};
  const keys = data.keys || {};

  let html = `<div class="result-card"><h4>🌐 Threat Intelligence Enrichment</h4>`;

  if (!keys.virustotal && !keys.abuseipdb) {
    html += `<p class="muted">⚠ No API keys configured. Add <code>VIRUSTOTAL_API_KEY</code> and <code>ABUSEIPDB_API_KEY</code> to <code>.env</code>, then restart.</p></div>`;
    zone.innerHTML = html;
    return;
  }

  // VT URLs
  if (vt.urls && vt.urls.length) {
    html += `<h4 style="margin-top:12px">🦠 VirusTotal · URLs</h4>`;
    html += vt.urls.map((u) => {
      const pos = u.positives ?? 0;
      const tot = u.total_engines ?? 0;
      const cls = pos === 0 ? "safe" : pos / Math.max(tot, 1) < 0.05 ? "suspicious" : "malicious";
      const label = u.error ? escapeHtml(u.error) : `${pos}/${tot} flags`;
      return `<div class="url-item">
        <div class="url">${escapeHtml(shortenUrl(u.url || ""))}</div>
        <div class="meta">
          <span class="badge ${cls}">${label}</span>
          <a class="ti-link" target="_blank"
             href="https://www.virustotal.com/gui/url/${encodeURIComponent(btoa(u.url || "").replace(/=+$/, ""))}">Open in VirusTotal ↗</a>
        </div>
      </div>`;
    }).join("");
  }

  // VT IPs
  if (vt.ips && vt.ips.length) {
    html += `<h4 style="margin-top:12px">🦠 VirusTotal · IPs</h4>`;
    html += vt.ips.map((r) => {
      const pos = r.positives ?? 0;
      const tot = r.total_engines ?? 0;
      const cls = pos === 0 ? "safe" : pos / Math.max(tot, 1) < 0.05 ? "suspicious" : "malicious";
      const label = r.error ? escapeHtml(r.error) : `${pos}/${tot} flags`;
      return `<div class="url-item">
        <div class="url">${escapeHtml(r.ip || "")}</div>
        <div class="meta">
          <span class="badge ${cls}">${label}</span>
          ${r.country ? `<span class="module-tag">${escapeHtml(r.country)}</span>` : ""}
          ${r.as_owner ? `<span class="module-tag">${escapeHtml(r.as_owner)}</span>` : ""}
          <a class="ti-link" target="_blank"
             href="https://www.virustotal.com/gui/ip-address/${encodeURIComponent(r.ip || "")}">Open in VirusTotal ↗</a>
        </div>
      </div>`;
    }).join("");
  }

  // AbuseIPDB IPs
  if (abuse.ips && abuse.ips.length) {
    html += `<h4 style="margin-top:12px">🚨 AbuseIPDB · IPs</h4>`;
    html += abuse.ips.map((r) => {
      const score = r.abuse_confidence_score ?? 0;
      const cls = score === 0 ? "safe" : score < 25 ? "suspicious" : "malicious";
      const label = r.error ? escapeHtml(r.error) : `${score}% abuse confidence`;
      return `<div class="url-item">
        <div class="url">${escapeHtml(r.ip || "")}</div>
        <div class="meta">
          <span class="badge ${cls}">${label}</span>
          ${r.country_code ? `<span class="module-tag">${escapeHtml(r.country_code)}</span>` : ""}
          ${r.isp ? `<span class="module-tag">${escapeHtml(r.isp)}</span>` : ""}
          ${r.total_reports !== undefined ? `<span class="module-tag">${r.total_reports} reports</span>` : ""}
          <a class="ti-link" target="_blank"
             href="https://www.abuseipdb.com/check/${encodeURIComponent(r.ip || "")}">Open in AbuseIPDB ↗</a>
        </div>
      </div>`;
    }).join("");
  }

  if ((!vt.urls || !vt.urls.length) &&
      (!vt.ips || !vt.ips.length) &&
      (!abuse.ips || !abuse.ips.length)) {
    html += `<p class="muted">No IPs or URLs in this analysis to enrich.</p>`;
  }

  html += `</div>`;
  zone.innerHTML = html;
}

/* ---- banner ---- */
function renderBanner(a) {
  const cls = (a.verdict || "Unknown").toLowerCase();
  return `
    <div class="result-banner ${cls}">
      <div>
        <div class="result-verdict ${cls}">Verdict: ${escapeHtml(a.verdict || "Unknown")}</div>
        <div class="result-sub">${escapeHtml(a.explanation || "")}</div>
      </div>
      <div class="result-score">${a.final_score ?? 0}/100</div>
    </div>
  `;
}

/* ---- auth summary ---- */
function renderAuthSummary(a) {
  const s = a.auth_summary || {};
  const rows = [
    ["SPF Published",            yesNo(s.spf_published)],
    ["SPF Authenticated",        passFailUnknown(a.spf_present, a.spf_pass)],
    ["SPF Aligned",              passFailUnknown(a.spf_present, s.spf_aligned)],
    ["DKIM Published",           yesNo(s.dkim_published)],
    ["DKIM Authenticated",       passFailUnknown(a.dkim_present, a.dkim_pass)],
    ["DKIM Aligned",             passFailUnknown(a.dkim_present, s.dkim_aligned)],
    ["DMARC Published",          yesNo(s.dmarc_published)],
    ["DMARC Compliant",          passFailUnknown(a.dmarc_present, s.dmarc_compliant)],
  ];
  const html = rows.map(([k, v]) => `<tr><td>${escapeHtml(k)}</td><td>${v}</td></tr>`).join("");
  return `<div class="result-card"><h4>Authentication Summary</h4><table class="auth-table">${html}</table></div>`;
}

function yesNo(v) {
  if (v === true) return `<span class="badge safe">YES</span>`;
  if (v === false) return `<span class="badge suspicious">NO</span>`;
  return `<span class="badge suspicious">UNKNOWN</span>`;
}

function passFailUnknown(present, pass) {
  if (!present) return `<span class="badge suspicious">NOT PRESENT</span>`;
  if (pass === true) return `<span class="badge safe">PASS</span>`;
  if (pass === false) return `<span class="badge phishing">FAIL</span>`;
  return `<span class="badge suspicious">UNKNOWN</span>`;
}

/* ---- hops ---- */
function renderHops(a) {
  const hops = a.hops || [];
  if (!hops.length) {
    return `<div class="result-card"><h4>Relay Information</h4><p class="muted">No Received headers parsed.</p></div>`;
  }

  const totalDelay = hops.reduce((sum, h) => sum + (h.delay_seconds || 0), 0);

  const rows = hops.map((h) => {
    const delay = h.delay_seconds == null ? "—" : `${h.delay_seconds}s`;
    const from = h.from_host
      ? `${escapeHtml(h.from_host)}${h.from_ip ? " " + escapeHtml(h.from_ip) : ""}`
      : "—";
    const by = h.by_host
      ? `${escapeHtml(h.by_host)}${h.by_ip ? " " + escapeHtml(h.by_ip) : ""}`
      : "—";
    const with_ = h.with ? escapeHtml(h.with) : "—";
    const time = h.time ? escapeHtml(h.time) : "—";
    return `<tr>
      <td class="nowrap">${h.hop}</td>
      <td class="nowrap">${delay}</td>
      <td class="mono">${from}</td>
      <td class="mono">${by}</td>
      <td class="mono">${with_}</td>
      <td class="nowrap">${time}</td>
    </tr>`;
  }).join("");

  return `<div class="result-card">
    <h4>Relay Information</h4>
    <p class="muted" style="margin-bottom:8px">Total received delay: <strong>${totalDelay}s</strong> · ${hops.length} hop(s)</p>
    <div class="mx-table-wrap">
      <table class="mx-table">
        <thead>
          <tr>
            <th>Hop</th>
            <th>Delay</th>
            <th>From</th>
            <th>By</th>
            <th>With</th>
            <th>Time (UTC)</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    </div>
  </div>`;
}

/* ---- header info ---- */
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
  ];
  const html = rows.map(([k, v]) => `<tr><td>${escapeHtml(k)}</td><td>${escapeHtml(String(v))}</td></tr>`).join("");
  return `<div class="result-card"><h4>Message Header</h4><table class="result-kv">${html}</table></div>`;
}

function formatAddress(entry) {
  if (!entry) return "";
  if (typeof entry === "string") return entry;
  const name = entry[0] || "";
  const email = entry[1] || "";
  return name ? `${name} <${email}>` : email;
}

/* ---- full headers ---- */
function renderFullHeaders(a) {
  const list = a.full_headers || [];
  if (!list.length) {
    return `<div class="result-card"><h4>Headers Found</h4><p class="muted">No headers.</p></div>`;
  }
  const rows = list.map((h) => `
    <div class="header-row">
      <div class="h-name">${escapeHtml(h.name || "")}</div>
      <div class="h-value">${escapeHtml(h.value || "")}</div>
    </div>
  `).join("");
  return `<div class="result-card">
    <h4>Headers Found (${list.length})</h4>
    <div class="header-list">${rows}</div>
  </div>`;
}

/* ---- triggered ---- */
function renderTriggered(a) {
  const flags = a.triggered_features || [];
  if (!flags.length) {
    return `<div class="result-card"><h4>Triggered Features</h4><p class="muted">No suspicious features detected.</p></div>`;
  }
  const items = flags.map((f) =>
    `<li><span class="module-tag">${escapeHtml(f.module)}</span>${escapeHtml(f.detail)}</li>`
  ).join("");
  return `<div class="result-card"><h4>Triggered Features</h4><ul class="flag-list">${items}</ul></div>`;
}

/* ---- URLs ---- */
function renderUrlsCard(a) {
  const urls = a.urls_found || [];
  if (!urls.length) {
    return `<div class="result-card"><h4>URLs Found</h4><p class="muted">No URLs extracted.</p></div>`;
  }

  const groups = {};
  urls.forEach((u) => {
    const d = u.domain || "(unknown)";
    if (!groups[d]) groups[d] = [];
    groups[d].push(u);
  });

  const order = Object.keys(groups).sort(
    (x, y) => getGroupScore(groups[y]) - getGroupScore(groups[x])
  );

  let html = "";
  order.forEach((domain) => {
    const items = groups[domain];
    const maxScore = getGroupScore(items);
    const cls = maxScore >= 60 ? "phishing" : maxScore >= 30 ? "suspicious" : "safe";
    html += `<div class="url-group">
      <div class="url-group-header">
        <span class="url-group-domain">${escapeHtml(domain)}</span>
        <span class="badge ${cls}">${items.length} URL${items.length > 1 ? "s" : ""} · max ${maxScore}</span>
      </div>`;

    items.forEach((u) => {
      const full = u.url || "";
      const preview = shortenUrl(full);
      const uniqueFlags = [...new Set(u.flags || [])]
        .map((f) => cleanFlag(f, full))
        .filter(Boolean);
      const flagText = uniqueFlags.length
        ? " · ⚠ " + uniqueFlags.map(escapeHtml).join(" · ")
        : "";
      const vtUrl = "https://www.virustotal.com/gui/url/" + b64url(full);
      const vtDomain = u.domain ? "https://www.virustotal.com/gui/domain/" + encodeURIComponent(u.domain) : null;
      html += `<div class="url-item">
        <div class="url">${escapeHtml(preview)}</div>
        <details class="url-details">
          <summary>show full URL</summary>
          <pre class="raw-pre small-pre">${escapeHtml(full)}</pre>
        </details>
        <div class="meta">
          Score: ${u.score}${flagText}
          <div class="ti-links">
            <a class="ti-link" target="_blank" href="${vtUrl}">🦠 VirusTotal (URL)</a>
            ${vtDomain ? `<a class="ti-link" target="_blank" href="${vtDomain}">🦠 VirusTotal (domain)</a>` : ""}
          </div>
        </div>
      </div>`;
    });

    html += `</div>`;
  });

  return `<div class="result-card"><h4>URLs Found</h4>${html}</div>`;
}

/* ---- Encoded card ---- */
function renderEncodedCard(a) {
  const urls = a.urls_found || [];
  const encoded = urls.filter((u) =>
    (u.flags || []).some((f) =>
      /encoded|obfuscated|base64|%[0-9a-f]{2}/i.test(f)
    ) || (u.url && /%[0-9a-fA-F]{2}/.test(u.url))
  );

  if (!encoded.length) {
    return `<div class="result-card"><h4>Encoded / Obfuscated URLs</h4><p class="muted">None detected.</p></div>`;
  }

  const items = encoded.map((u) => {
    const flags = [...new Set(u.flags || [])].map((f) => cleanFlag(f, u.url || "")).filter(Boolean);
    return `<div class="url-item">
      <div class="url">${escapeHtml(shortenUrl(u.url || ""))}</div>
      <details class="url-details">
        <summary>show full URL</summary>
        <pre class="raw-pre small-pre">${escapeHtml(u.url || "")}</pre>
      </details>
      <div class="meta">
        <span class="encoded-badge">${flags.length} signal(s)</span>
        ${flags.map(escapeHtml).join(" · ")}
      </div>
    </div>`;
  }).join("");

  return `<div class="result-card"><h4>Encoded / Obfuscated URLs</h4>${items}</div>`;
}

/* ---- IPs ---- */
function renderIpsCard(a) {
  const ips = a.ips_found || [];
  if (!ips.length) {
    return `<div class="result-card"><h4>IP Addresses Found</h4><p class="muted">No IP addresses found.</p></div>`;
  }
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
      <div class="meta">
        <span class="badge ${cls}">${i.public ? "PUBLIC" : "PRIVATE"}</span>
        ${tags.map((t) => `<span class="module-tag">${t}</span>`).join(" ")}
      </div>
      ${i.public ? `
        <div class="ti-links">
          <a class="ti-link" target="_blank" href="https://www.virustotal.com/gui/ip-address/${encodeURIComponent(i.ip)}">🦠 VirusTotal</a>
          <a class="ti-link" target="_blank" href="https://www.abuseipdb.com/check/${encodeURIComponent(i.ip)}">🚨 AbuseIPDB</a>
        </div>` : ""}
    </div>`;
  }).join("");
  return `<div class="result-card"><h4>IP Addresses Found</h4>${items}</div>`;
}

/* ---- attachments ---- */
function renderAttachmentsCard(a) {
  const atts = a.attachments || [];
  if (!atts.length) {
    return `<div class="result-card"><h4>Attachments</h4><p class="muted">No attachments.</p></div>`;
  }
  const items = atts.map((at) => `
    <div class="url-item">
      <div class="url">${escapeHtml(at.filename || "")}</div>
      <div class="meta">${escapeHtml(at.content_type || "")} · ${at.size} bytes · Score: ${at.score}</div>
      ${(at.flags && at.flags.length) ? `<div class="meta">⚠ ${at.flags.map(escapeHtml).join(" · ")}</div>` : ""}
      ${at.sha256 ? `<div class="ti-links"><a class="ti-link" target="_blank" href="https://www.virustotal.com/gui/file/${encodeURIComponent(at.sha256)}">🦠 VirusTotal (hash)</a></div>` : ""}
    </div>
  `).join("");
  return `<div class="result-card"><h4>Attachments</h4>${items}</div>`;
}

/* ---- raw headers ---- */
function renderRawHeaders(a) {
  if (!a.raw_headers) {
    return `<div class="result-card"><h4>Raw Headers</h4><p class="muted">(none)</p></div>`;
  }
  return `<div class="result-card">
    <h4>Raw Headers</h4>
    <details>
      <summary style="cursor:pointer;color:var(--accent)">Show / hide raw email headers</summary>
      <pre class="raw-pre">${escapeHtml(a.raw_headers)}</pre>
    </details>
  </div>`;
}

/* ---- helpers ---- */
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
function getGroupScore(items) {
  return Math.max(...items.map((i) => i.score || 0));
}
function b64url(str) {
  try {
    return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  } catch (e) {
    return encodeURIComponent(str);
  }
}

/* ---------------- Data loads ---------------- */

async function loadAll() {
  await Promise.all([loadStats(), loadHistory()]);
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

  tbody.querySelectorAll(".icon-btn-row").forEach((btn) => {
    btn.addEventListener("click", onRowAction);
  });
}

async function onRowAction(e) {
  const action = e.currentTarget.dataset.action;
  const id = e.currentTarget.dataset.id;
  if (action === "view") {
    openResultById(id);
  } else if (action === "json") {
    window.open(`/api/analyses/${id}/report?format=json`, "_blank");
  } else if (action === "pdf") {
    window.open(`/api/analyses/${id}/report?format=pdf`, "_blank");
  } else if (action === "delete") {
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