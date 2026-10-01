const API = "";

const $ = (id) => document.getElementById(id);

let allItems = [];
let currentResultId = null;

document.addEventListener("DOMContentLoaded", () => {
  bindEvents();
  initBackground();
  initSpotlight();
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

  if (resultModal) {
    resultModal.addEventListener("click", (e) => {
      const btn = e.target.closest("[data-copy]");
      if (!btn) return;
      const idx = btn.getAttribute("data-copy");
      const pre = document.getElementById(`decoded-full-${idx}`);
      if (!pre) return;
      const text = pre.textContent || "";
      navigator.clipboard.writeText(text).then(() => {
        const old = btn.textContent;
        btn.textContent = "✓ Copied";
        setTimeout(() => (btn.textContent = old), 1200);
      });
    });
  }

  document.querySelectorAll(".btn").forEach(attachRipple);
}

/* ---------------- Background canvas ---------------- */

let fxCanvas, fxCtx, fxParticles = [], fxW = 0, fxH = 0;

function initBackground() {
  fxCanvas = $("fx");
  if (!fxCanvas) return;
  fxCtx = fxCanvas.getContext("2d");
  resizeFx();
  window.addEventListener("resize", () => { resizeFx(); initFxParticles(); });
  initFxParticles();
  drawFx();
}

function resizeFx() {
  fxW = fxCanvas.width = window.innerWidth;
  fxH = fxCanvas.height = window.innerHeight;
}

function initFxParticles() {
  const count = Math.min(60, Math.floor(fxW * fxH / 26000));
  fxParticles = [];
  for (let i = 0; i < count; i++) {
    fxParticles.push({
      x: Math.random() * fxW,
      y: Math.random() * fxH,
      vx: (Math.random() - 0.5) * 0.25,
      vy: (Math.random() - 0.5) * 0.25,
      r: 0.8 + Math.random() * 1.2,
    });
  }
}

function drawFx() {
  if (!fxCtx) return;
  fxCtx.clearRect(0, 0, fxW, fxH);
  for (let i = 0; i < fxParticles.length; i++) {
    const p = fxParticles[i];
    p.x += p.vx; p.y += p.vy;
    if (p.x < 0 || p.x > fxW) p.vx *= -1;
    if (p.y < 0 || p.y > fxH) p.vy *= -1;

    fxCtx.beginPath();
    fxCtx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
    fxCtx.fillStyle = "rgba(140, 180, 255, 0.5)";
    fxCtx.fill();

    for (let j = i + 1; j < fxParticles.length; j++) {
      const q = fxParticles[j];
      const dx = p.x - q.x;
      const dy = p.y - q.y;
      const d = Math.sqrt(dx * dx + dy * dy);
      if (d < 140) {
        fxCtx.beginPath();
        fxCtx.moveTo(p.x, p.y);
        fxCtx.lineTo(q.x, q.y);
        fxCtx.strokeStyle = `rgba(140, 180, 255, ${0.12 * (1 - d / 140)})`;
        fxCtx.lineWidth = 0.5;
        fxCtx.stroke();
      }
    }
  }
  requestAnimationFrame(drawFx);
}

function initSpotlight() {
  const spotlight = $("spotlight");
  if (!spotlight) return;
  document.addEventListener("mousemove", (e) => {
    spotlight.style.left = e.clientX + "px";
    spotlight.style.top = e.clientY + "px";
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
    ${renderEncodedContentCard(a)}
    ${renderIpsCard(a)}
    ${renderAttachmentsCard(a)}
    ${renderRawHeaders(a)}
    <div id="enrichmentZone"></div>
  `;

  const overlay = $("resultModal");
  if (overlay) overlay.classList.remove("hidden");
}

/* ---------------- Enrichment ---------------- */

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

  if (vt.urls && vt.urls.length) {
    html += `<h4 style="margin-top:12px">🦠 VirusTotal · URLs</h4>`;
    html += vt.urls.map((u) => {
      const pos = u.positives ?? 0;
      const tot = u.total_engines ?? 0;
      const cls = pos === 0 ? "safe" : pos / Math.max(tot, 1) < 0.05 ? "suspicious" : "phishing";
      const label = u.error ? escapeHtml(u.error) : `${pos}/${tot} flags`;
      return `<div class="url-item">
        <div class="url">${escapeHtml(shortenUrl(u.url || ""))}</div>
        <div class="meta">
          <span class="badge ${cls}">${label}</span>
          <a class="ti-link" target="_blank"
             href="https://www.virustotal.com/gui/url/${b64url(u.url || "")}">Open in VirusTotal ↗</a>
        </div>
      </div>`;
    }).join("");
  }

  if (vt.ips && vt.ips.length) {
    html += `<h4 style="margin-top:12px">🦠 VirusTotal · IPs</h4>`;
    html += vt.ips.map((r) => {
      const pos = r.positives ?? 0;
      const tot = r.total_engines ?? 0;
      const cls = pos === 0 ? "safe" : pos / Math.max(tot, 1) < 0.05 ? "suspicious" : "phishing";
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

  if (abuse.ips && abuse.ips.length) {
    html += `<h4 style="margin-top:12px">🚨 AbuseIPDB · IPs</h4>`;
    html += abuse.ips.map((r) => {
      const score = r.abuse_confidence_score ?? 0;
      const cls = score === 0 ? "safe" : score < 25 ? "suspicious" : "phishing";
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

/* ---------------- Result renderers ---------------- */

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
          <tr><th>Hop</th><th>Delay</th><th>From</th><th>By</th><th>With</th><th>Time (UTC)</th></tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    </div>
  </div>`;
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

function renderEncodedContentCard(a) {
  const items = a.encoded_found || [];
  const dump = a.encoded_full_dump || {};

  if (!items.length && !dump.raw_eml) {
    return `<div class="result-card"><h4>Encoded Content</h4><p class="muted">No encoded blobs detected.</p></div>`;
  }

  let html = "";
  const summary = a.encoded_summary || {};
  const summaryLine = Object.entries(summary)
    .filter(([_, v]) => v > 0)
    .map(([k, v]) => `${k.replace(/_/g, " ")}=${v}`)
    .join(" · ");

  html += `<div class="enc-header-row">
    <h4>Encoded Content (${items.length})</h4>
    <div class="enc-badges">
      ${summary.mime_parts ? `<span class="badge suspicious">${summary.mime_parts} MIME</span>` : ""}
      ${summary.base64 ? `<span class="badge suspicious">${summary.base64} base64</span>` : ""}
      ${summary.quoted_printable ? `<span class="badge suspicious">${summary.quoted_printable} QP</span>` : ""}
      ${summary.url_encoded ? `<span class="badge suspicious">${summary.url_encoded} URL-enc</span>` : ""}
      ${summary.hex ? `<span class="badge suspicious">${summary.hex} hex</span>` : ""}
      ${summary.rfc2047_headers ? `<span class="badge suspicious">${summary.rfc2047_headers} RFC2047</span>` : ""}
      ${summary.html_entities ? `<span class="badge suspicious">${summary.html_entities} HTML-ent</span>` : ""}
    </div>
  </div>`;
  if (summaryLine) html += `<p class="muted" style="margin-bottom:10px">${escapeHtml(summaryLine)}</p>`;

  if (dump.raw_eml) {
    html += `<div class="dump-section">
      <div class="dump-head">
        <strong>📄 Full Raw .eml Dump</strong>
        <span class="muted">${dump.raw_eml_size ?? 0} bytes${dump.raw_eml_truncated ? " (truncated)" : ""}</span>
      </div>
      <details class="dump-details" id="rawEmlDump">
        <summary>Show complete raw .eml file</summary>
        <div class="dump-actions">
          <button class="copy-btn" data-copy="raweml">📋 Copy entire .eml</button>
        </div>
        <pre class="raw-pre" id="decoded-full-raweml">${escapeHtml(dump.raw_eml)}</pre>
      </details>
    </div>`;
  }

  if (items.length) {
    const groups = {};
    items.forEach((it) => {
      const t = it.type || "unknown";
      if (!groups[t]) groups[t] = [];
      groups[t].push(it);
    });

    const order = ["mime-part", "rfc2047-header", "base64", "quoted-printable", "url-encoded", "hex-escape", "hex-0x", "html-entities"];
    const present = Object.keys(groups).sort((a, b) => {
      const ia = order.indexOf(a), ib = order.indexOf(b);
      return (ia === -1 ? 99 : ia) - (ib === -1 ? 99 : ib);
    });

    let globalIndex = 0;

    present.forEach((type) => {
      const list = groups[type];
      html += `<div class="enc-group">
        <div class="enc-group-head">
          <span class="enc-type">${escapeHtml(typeLabel(type))}</span>
          <span class="badge suspicious">${list.length} item${list.length > 1 ? "s" : ""}</span>
        </div>`;

      list.forEach((it) => {
        const idx = globalIndex++;
        html += `<div class="url-item enc-item">
          <div class="enc-meta">
            <span class="module-tag">${escapeHtml(it.encoding || type)}</span>
            <span class="muted">source: ${escapeHtml(it.source || "—")}</span>
            ${it.size_raw ? `<span class="muted">· ${it.size_raw} raw</span>` : ""}
            ${it.size_decoded ? `<span class="muted">· ${it.size_decoded} decoded</span>` : ""}
            ${it.binary ? `<span class="badge suspicious">binary</span>` : ""}
          </div>

          <details class="url-details">
            <summary>Raw (encoded)</summary>
            <div class="dump-actions">
              <button class="copy-btn" data-copy="${idx}">📋 Copy raw</button>
            </div>
            <pre class="raw-pre small-pre" id="decoded-full-${idx}">${escapeHtml(it.raw || "")}</pre>
          </details>

          <div class="enc-decoded-head">
            <span class="muted">Decoded preview:</span>
          </div>
          <pre class="raw-pre small-pre">${escapeHtml(it.decoded_preview || it.decoded_full || "")}</pre>

          ${(it.decoded_full && it.decoded_full.length > (it.decoded_preview || "").length) ? `
            <details class="url-details">
              <summary>Show full decoded content</summary>
              <div class="dump-actions">
                <button class="copy-btn" data-copy="decoded-${idx}">📋 Copy decoded</button>
              </div>
              <pre class="raw-pre small-pre" id="decoded-full-decoded-${idx}">${escapeHtml(it.decoded_full)}</pre>
            </details>
          ` : ""}
        </div>`;
      });

      html += `</div>`;
    });
  }

  return `<div class="result-card">${html}</div>`;
}

function typeLabel(t) {
  return {
    "base64": "Base64",
    "mime-part": "MIME Part",
    "rfc2047-header": "RFC 2047 Header",
    "quoted-printable": "Quoted-Printable",
    "url-encoded": "URL-encoded",
    "hex-escape": "Hex (\\xNN)",
    "hex-0x": "Hex (0xNN)",
    "html-entities": "HTML Entities",
  }[t] || t;
}

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
      ${(at.embedded_urls && at.embedded_urls.length)
        ? `<div class="meta">🔗 Embedded URL: <span class="mono">${at.embedded_urls.map(escapeHtml).join(" · ")}</span></div>`
        : ""}
      ${at.sha256 ? `<div class="ti-links"><a class="ti-link" target="_blank" href="https://www.virustotal.com/gui/file/${encodeURIComponent(at.sha256)}">🦠 VirusTotal (hash)</a></div>` : ""}
    </div>
  `).join("");
  return `<div class="result-card"><h4>Attachments</h4>${items}</div>`;
}

function renderRawHeaders(a) {
  if (!a.raw_headers) {
    return `<div class="result-card"><h4>Raw Headers</h4><p class="muted">(none)</p></div>`;
  }
  return `<div class="result-card">
    <h4>Raw Headers</h4>
    <details>
      <summary style="cursor:pointer;color:var(--accent-2)">Show / hide raw email headers</summary>
      <pre class="raw-pre">${escapeHtml(a.raw_headers)}</pre>
    </details>
  </div>`;
}

/* ==================================================
   Latest Scan Summary
   ================================================== */

function renderLatestSummary(latest) {
  const panel = $("summaryBody");
  const tag = $("summaryTag");
  if (!panel) return;

  if (!latest) {
    panel.innerHTML = `<p class="muted">Run a scan to see the summary of your latest analyzed email.</p>`;
    if (tag) tag.textContent = "Idle";
    return;
  }

  if (tag) tag.textContent = "Latest";

  const cls = (latest.verdict || "Unknown").toLowerCase();
  const score = latest.final_score ?? 0;
  const scoreLabel = cls === "safe" ? "Low risk" : cls === "suspicious" ? "Needs review" : "High risk";

  // Gather top indicators from triggered features + attachment flags
  const flags = latest.triggered_features || [];
  const topFlags = flags.slice(0, 6);

  // Build "what to verify" checklist based on the signals we found
  const checklist = buildChecklist(latest);

  const flagsHtml = topFlags.length
    ? `<ul class="summary-flags">
        ${topFlags.map((f) => {
          const sev = (f.module === "header" || f.module === "attachment" || f.module === "url") ? "" : "info";
          return `<li class="${sev}">
            <span class="flag-module">${escapeHtml(f.module || "")}</span>
            <span class="flag-text">${escapeHtml(f.detail || "")}</span>
          </li>`;
        }).join("")}
      </ul>`
    : `<p class="muted">No suspicious signals triggered.</p>`;

  const checkHtml = checklist.length
    ? `<ul class="summary-checklist">
        ${checklist.map((c) => `<li class="${c.done ? "done" : ""}">${escapeHtml(c.text)}</li>`).join("")}
      </ul>`
    : `<p class="muted">No manual checks required.</p>`;

  panel.innerHTML = `
    <div class="summary-header">
      <div class="summary-left">
        <span class="summary-verdict-badge ${cls}">${escapeHtml(latest.verdict || "Unknown")}</span>
        <div class="summary-info">
          <div class="summary-subject">${escapeHtml(latest.subject || "(no subject)")}</div>
          <div class="summary-sender">${escapeHtml(latest.sender || "unknown sender")}</div>
        </div>
      </div>
      <div class="summary-score-box">
        <div class="summary-score-value ${cls}">${score}</div>
        <div class="summary-score-label">${scoreLabel}</div>
      </div>
    </div>

    <div class="summary-grid">
      <div class="summary-col">
        <h4><span class="ico">⚠</span> Top Indicators to Double-Check</h4>
        ${flagsHtml}
      </div>
      <div class="summary-col">
        <h4><span class="ico">☑</span> What You Should Verify</h4>
        ${checkHtml}
      </div>
    </div>

    <div class="summary-actions">
      <button class="btn btn-primary" id="summaryViewBtn">View Full Analysis</button>
      <button class="btn btn-ghost" id="summaryJsonBtn">Download JSON</button>
      <button class="btn btn-ghost" id="summaryPdfBtn">Download PDF</button>
    </div>
  `;

  const viewBtn = $("summaryViewBtn");
  const jsonBtn = $("summaryJsonBtn");
  const pdfBtn = $("summaryPdfBtn");
  if (viewBtn) viewBtn.onclick = () => openResultById(latest.id);
  if (jsonBtn) jsonBtn.onclick = () => window.open(`/api/analyses/${latest.id}/report?format=json`, "_blank");
  if (pdfBtn) pdfBtn.onclick = () => window.open(`/api/analyses/${latest.id}/report?format=pdf`, "_blank");
}

function buildChecklist(a) {
  const out = [];
  const flags = a.triggered_features || [];
  const flagText = flags.map((f) => (f.detail || "").toLowerCase()).join(" | ");

  // SPF / DKIM / DMARC
  if (flagText.includes("spf") || !a.spf_present) {
    out.push({ text: "Verify SPF alignment on the sender domain", done: a.spf_pass === true });
  }
  if (flagText.includes("dkim") || !a.dkim_present) {
    out.push({ text: "Check DKIM signature on the raw headers", done: a.dkim_pass === true });
  }
  if (flagText.includes("dmarc") || !a.dmarc_present) {
    out.push({ text: "Confirm DMARC policy exists for sender domain", done: a.dmarc_pass === true });
  }

  // Reply-To / Return-Path
  if (a.reply_to_domain && a.sender_domain && a.reply_to_domain !== a.sender_domain) {
    out.push({ text: `Confirm Reply-To domain '${a.reply_to_domain}' is legitimate`, done: false });
  }
  if (a.return_path_domain && a.sender_domain && a.return_path_domain !== a.sender_domain) {
    out.push({ text: `Check Return-Path mismatch with From domain`, done: false });
  }

  // Display name spoofing
  if (flagText.includes("impersonates") || flagText.includes("claims")) {
    out.push({ text: "Verify the display name matches the actual sender", done: false });
  }

  // URLs
  const urls = a.urls_found || [];
  const riskyUrls = urls.filter((u) => (u.score || 0) >= 30);
  if (riskyUrls.length) {
    out.push({ text: `Open ${riskyUrls.length} high-risk URL(s) only in a sandbox`, done: false });
  }

  // Attachments
  const atts = a.attachments || [];
  const riskyAtts = atts.filter((at) => (at.score || 0) >= 20);
  if (riskyAtts.length) {
    out.push({ text: `Do NOT open attachment(s): ${riskyAtts.map((x) => x.filename).join(", ")}`, done: false });
  }
  const svgAtts = atts.filter((at) => (at.extension || "").toLowerCase() === "svg");
  if (svgAtts.length) {
    out.push({ text: "SVG attachment found — inspect for embedded redirect", done: false });
  }
  const embeddedUrls = atts.flatMap((at) => at.embedded_urls || []);
  if (embeddedUrls.length) {
    out.push({ text: "Check URLs embedded inside attachments", done: false });
  }

  // Content warnings
  if (flagText.includes("credential") || flagText.includes("otp")) {
    out.push({ text: "Never enter credentials from email links", done: false });
  }
  if (flagText.includes("hidden") || flagText.includes("invisible")) {
    out.push({ text: "Inspect hidden HTML content in the raw body", done: false });
  }

  // Verification contact
  if (a.sender_domain) {
    out.push({ text: `Contact sender via a known phone number, not reply`, done: false });
  }

  return out.slice(0, 8);
}

/* ---------------- Helpers ---------------- */

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

function attachRipple(el) {
  el.addEventListener("click", (e) => {
    const circle = document.createElement("span");
    const d = Math.max(el.clientWidth, el.clientHeight);
    const rect = el.getBoundingClientRect();
    circle.style.position = "absolute";
    circle.style.borderRadius = "50%";
    circle.style.transform = "scale(0)";
    circle.style.animation = "ripple 0.6s linear";
    circle.style.background = "rgba(255,255,255,0.35)";
    circle.style.pointerEvents = "none";
    circle.style.width = circle.style.height = `${d}px`;
    circle.style.left = `${e.clientX - rect.left - d / 2}px`;
    circle.style.top = `${e.clientY - rect.top - d / 2}px`;
    el.style.position = "relative";
    el.style.overflow = "hidden";
    el.appendChild(circle);
    setTimeout(() => circle.remove(), 650);
  });
}

/* ---------------- Threat Map ---------------- */

const CONTINENTS = [
  "M 130 120 L 200 105 L 245 130 L 260 180 L 235 225 L 200 240 L 165 220 L 140 180 Z",
  "M 230 260 L 270 265 L 285 310 L 275 360 L 250 400 L 235 380 L 220 320 L 218 285 Z",
  "M 470 100 L 540 95 L 565 125 L 555 155 L 520 165 L 485 155 L 465 130 Z",
  "M 470 190 L 540 185 L 570 220 L 560 275 L 530 335 L 500 350 L 480 320 L 465 265 L 465 220 Z",
  "M 570 100 L 700 90 L 800 105 L 850 140 L 830 180 L 780 200 L 720 210 L 660 200 L 610 180 L 590 155 L 575 130 Z",
  "M 790 330 L 850 320 L 880 350 L 860 390 L 810 395 L 785 370 Z",
  "M 340 60 L 400 55 L 420 90 L 390 120 L 345 115 L 330 85 Z",
];

function projectToMap(lat, lon) {
  const x = (lon + 180) * (1000 / 360);
  const y = (90 - lat) * (500 / 180);
  return { x, y };
}

function renderContinents() {
  const g = document.getElementById("continents");
  if (!g) return;
  g.innerHTML = CONTINENTS.map((d) => `<path d="${d}" />`).join("");
}

async function loadThreatMap() {
  const attacksG = document.getElementById("attacks");
  if (!attacksG) return;
  renderContinents();

  try {
    const res = await fetch(`${API}/api/threat-map`);
    const data = await res.json();
    renderThreatMap(data);
  } catch (err) {
    console.error("threat-map failed", err);
  }
}

function renderThreatMap(data) {
  const g = document.getElementById("attacks");
  const statsEl = document.getElementById("mapStats");
  if (!g) return;

  g.innerHTML = "";

  const points = data.points || [];
  if (!points.length) {
    if (statsEl) statsEl.innerHTML = `<span class="muted">No public sender IPs found yet — run a scan to populate the map.</span>`;
    return;
  }

  if (statsEl) {
    const statsHtml = `
      <div class="stat-item">Origin emails: <strong>${points.length}</strong></div>
      ${(data.country_counts || []).slice(0, 5).map((c) => `
        <div class="stat-item">
          <img class="flag" src="https://flagcdn.com/w40/${c.cc.toLowerCase()}.png" alt="" onerror="this.style.display='none'">
          ${c.cc} <strong>${c.count}</strong>
        </div>
      `).join("")}
    `;
    statsEl.innerHTML = statsHtml;
  }

  points.forEach((p) => {
    const { x, y } = projectToMap(p.lat, p.lon);
    const color = p.verdict === "Phishing" ? "#ff5470" : "#ffb545";

    const pulse = document.createElementNS("http://www.w3.org/2000/svg", "circle");
    pulse.setAttribute("cx", x);
    pulse.setAttribute("cy", y);
    pulse.setAttribute("r", 3);
    pulse.setAttribute("fill", color);
    pulse.setAttribute("class", "attack-pulse");
    g.appendChild(pulse);

    const dot = document.createElementNS("http://www.w3.org/2000/svg", "circle");
    dot.setAttribute("cx", x);
    dot.setAttribute("cy", y);
    dot.setAttribute("r", 4);
    dot.setAttribute("fill", color);
    dot.setAttribute("stroke", "#ffffff");
    dot.setAttribute("stroke-width", "1");
    dot.setAttribute("class", "attack-marker");
    dot.setAttribute("data-ip", p.ip || "");
    dot.setAttribute("data-country", p.country || "");
    dot.setAttribute("data-city", p.city || "");
    dot.setAttribute("data-isp", p.isp || "");
    dot.setAttribute("data-verdict", p.verdict || "");
    dot.setAttribute("data-sender", p.sender || "");
    dot.setAttribute("data-subject", p.subject || "");
    dot.style.filter = `drop-shadow(0 0 6px ${color})`;
    dot.addEventListener("mouseenter", showMapTooltip);
    dot.addEventListener("mousemove", moveMapTooltip);
    dot.addEventListener("mouseleave", hideMapTooltip);
    g.appendChild(dot);
  });
}

let mapTooltipEl = null;
function ensureMapTooltip() {
  if (!mapTooltipEl) {
    mapTooltipEl = document.createElement("div");
    mapTooltipEl.className = "map-tooltip";
    document.body.appendChild(mapTooltipEl);
  }
  return mapTooltipEl;
}

function showMapTooltip(e) {
  const t = e.currentTarget;
  const el = ensureMapTooltip();
  el.innerHTML = `
    <strong>${escapeHtml(t.dataset.ip || "")}</strong>
    <div class="row">Country: <span>${escapeHtml(t.dataset.country || "—")}</span></div>
    <div class="row">City: <span>${escapeHtml(t.dataset.city || "—")}</span></div>
    <div class="row">ISP: <span>${escapeHtml(t.dataset.isp || "—")}</span></div>
    <div class="row">Verdict: <span>${escapeHtml(t.dataset.verdict || "—")}</span></div>
    <div class="row">Sender: <span>${escapeHtml(t.dataset.sender || "—")}</span></div>
    <div class="row">Subject: <span>${escapeHtml(t.dataset.subject || "—")}</span></div>
  `;
  el.style.display = "block";
}

function moveMapTooltip(e) {
  const el = ensureMapTooltip();
  el.style.left = (e.clientX + 14) + "px";
  el.style.top = (e.clientY + 14) + "px";
}

function hideMapTooltip() {
  if (mapTooltipEl) mapTooltipEl.style.display = "none";
}

/* ---------------- Data loads ---------------- */

async function loadAll() {
  await Promise.all([loadStats(), loadHistory(), loadThreatMap()]);
}

async function loadStats() {
  try {
    const res = await fetch(`${API}/api/stats`);
    const data = await res.json();
    const total = data.total ?? 0;
    const safe = data.safe ?? 0;
    const sus = data.suspicious ?? 0;
    const phish = data.phishing ?? 0;
    animateCounter("statTotal", total);
    animateCounter("statSafe", safe);
    animateCounter("statSuspicious", sus);
    animateCounter("statPhishing", phish);
    renderCharts({ total, safe, sus, phish });
  } catch (err) { console.error("stats failed", err); }
}

function animateCounter(id, target) {
  const el = $(id);
  if (!el) return;
  const from = parseInt(el.textContent.replace(/[^0-9]/g, ""), 10) || 0;
  const duration = 700;
  const start = performance.now();
  const step = (now) => {
    const t = Math.min(1, (now - start) / duration);
    const eased = 1 - Math.pow(1 - t, 3);
    el.textContent = Math.floor(from + (target - from) * eased).toLocaleString();
    if (t < 1) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}

function renderCharts({ total, safe, sus, phish }) {
  const max = Math.max(safe, sus, phish, 1);
  setBar("barSafe", "barSafeVal", safe, max);
  setBar("barSuspicious", "barSuspiciousVal", sus, max);
  setBar("barPhishing", "barPhishingVal", phish, max);

  const threats = sus + phish;
  const rate = total > 0 ? Math.round((threats / total) * 100) : 0;
  const donutValue = $("donutValue");
  const donutFg = $("donutFg");
  if (donutFg) {
    const circ = 2 * Math.PI * 50;
    donutFg.style.strokeDasharray = circ;
    donutFg.style.strokeDashoffset = circ - (rate / 100) * circ;
  }
  if (donutValue) {
    let cur = 0;
    const tick = () => {
      cur += Math.max(1, Math.floor(rate / 40));
      if (cur >= rate) { donutValue.textContent = `${rate}%`; return; }
      donutValue.textContent = `${cur}%`;
      requestAnimationFrame(tick);
    };
    tick();
  }
}

function setBar(barId, valId, value, max) {
  const bar = $(barId);
  const val = $(valId);
  if (bar) {
    const pct = max > 0 ? (value / max) * 100 : 0;
    bar.style.width = `${pct}%`;
    bar.setAttribute("data-w", pct);
  }
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

    // Render latest summary from the most recent item
    if (allItems.length) {
      const latest = allItems.reduce((a, b) => {
        const ta = new Date(a.created_at || 0).getTime();
        const tb = new Date(b.created_at || 0).getTime();
        return ta > tb ? a : b;
      });
      renderLatestSummary(latest);
    } else {
      renderLatestSummary(null);
    }
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="7" class="muted">Failed to load.</td></tr>`;
    renderLatestSummary(null);
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
    const score = it.final_score ?? 0;
    const scoreClass = score >= 60 ? "high" : score >= 30 ? "mid" : "low";
    const date = it.created_at ? new Date(it.created_at).toLocaleString() : "-";
    return `<tr data-id="${it.id}">
      <td class="t-id">#${it.id}</td>
      <td class="t-date">${escapeHtml(date)}</td>
      <td class="t-sender">${escapeHtml(it.sender || "-")}</td>
      <td class="t-subject" title="${escapeHtml(it.subject || "")}">${escapeHtml(it.subject || "(no subject)")}</td>
      <td class="t-score ${scoreClass}">${score}</td>
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
  e.stopPropagation();
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