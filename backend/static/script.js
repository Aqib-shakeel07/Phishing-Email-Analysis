const API = "";

const $ = (id) => document.getElementById(id);

document.addEventListener("DOMContentLoaded", () => {
  $("year").textContent = new Date().getFullYear();
  bindEvents();
});

function bindEvents() {
  const form = $("analyzeForm");
  const fileInput = $("fileInput");
  const fileDrop = document.querySelector(".file-drop");
  const clearBtn = $("clearBtn");

  fileInput.addEventListener("change", () => {
    const name = fileInput.files[0]?.name;
    $("fileName").textContent = name
      ? `📎 ${name}`
      : "📎 Click to choose a file or drag it here";
  });

  ["dragenter", "dragover"].forEach((ev) =>
    fileDrop.addEventListener(ev, (e) => {
      e.preventDefault();
      fileDrop.classList.add("dragover");
    })
  );
  ["dragleave", "drop"].forEach((ev) =>
    fileDrop.addEventListener(ev, (e) => {
      e.preventDefault();
      fileDrop.classList.remove("dragover");
    })
  );
  fileDrop.addEventListener("drop", (e) => {
    const file = e.dataTransfer.files[0];
    if (file) {
      fileInput.files = e.dataTransfer.files;
      $("fileName").textContent = `📎 ${file.name}`;
    }
  });

  form.addEventListener("submit", handleSubmit);
  clearBtn.addEventListener("click", resetForm);
}

function resetForm() {
  $("fileInput").value = "";
  $("rawInput").value = "";
  $("fileName").textContent = "📎 Click to choose a file or drag it here";
  $("results").classList.add("hidden");
  $("loading").classList.add("hidden");
}

async function handleSubmit(e) {
  e.preventDefault();
  const file = $("fileInput").files[0];
  const raw = $("rawInput").value.trim();

  if (!file && !raw) {
    alert("Please upload a file or paste raw email source.");
    return;
  }

  $("results").classList.add("hidden");
  $("loading").classList.remove("hidden");

  try {
    let response;
    if (file) {
      const fd = new FormData();
      fd.append("file", file);
      response = await fetch(`${API}/api/analyze`, { method: "POST", body: fd });
    } else {
      response = await fetch(`${API}/api/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ raw }),
      });
    }

    const data = await response.json();
    if (!response.ok || !data.success) {
      throw new Error(data.error || "Analysis failed");
    }
    renderResults(data.analysis);
  } catch (err) {
    alert("Error: " + err.message);
  } finally {
    $("loading").classList.add("hidden");
  }
}

function renderResults(a) {
  const verdictEl = $("verdictText");
  verdictEl.textContent = a.verdict;
  verdictEl.className = a.verdict.toLowerCase();

  const verdictCard = document.querySelector(".verdict-card");
  verdictCard.classList.remove("safe", "suspicious", "phishing");
  verdictCard.classList.add(a.verdict.toLowerCase());

  $("scoreBadge").textContent = `${a.final_score}/100`;
  $("explanation").textContent = a.explanation || "";

  renderScoreBars(a.component_scores || {});
  renderAuth(a);
  renderSummary(a);
  renderRawHeaders(a.raw_headers);
  renderFlags(a.triggered_features || []);
  renderUrls(a.urls_found || []);
  renderIps(a.ips_found || []);
  renderAttachments(a.attachments || []);
  bindReportButtons(a.id);

  $("results").classList.remove("hidden");
  $("results").scrollIntoView({ behavior: "smooth" });
}

function renderScoreBars(scores) {
  const container = $("scoreBars");
  container.innerHTML = "";
  Object.entries(scores).forEach(([key, value]) => {
    const v = Math.round(value);
    const cls = v >= 60 ? "phishing" : v >= 30 ? "suspicious" : "safe";
    const div = document.createElement("div");
    div.className = "score-bar";
    div.innerHTML = `
      <div class="label"><span>${key.toUpperCase()}</span><span>${v}</span></div>
      <div class="bar"><div class="fill ${cls}" style="width:${v}%"></div></div>
    `;
    container.appendChild(div);
  });
}

/* ------------ Authentication table ------------ */
function renderAuth(a) {
  const rows = [
    ["SPF",   authCell(a.spf_present,   a.spf_pass)],
    ["DKIM",  authCell(a.dkim_present,  a.dkim_pass)],
    ["DMARC", authCell(a.dmarc_present, a.dmarc_pass)],
  ];
  let html = rows
    .map(([k, v]) => `<tr><td>${escapeHtml(k)}</td><td>${v}</td></tr>`)
    .join("");

  if (!a.spf_present && !a.dkim_present && !a.dmarc_present) {
    html += `
      <tr><td colspan="2" class="muted" style="color:#f59e0b;">
        ⚠ No SPF / DKIM / DMARC headers found in this email.
        The message cannot be verified as coming from the claimed sender.
      </td></tr>`;
  }
  $("authTable").innerHTML = html;
}

function authCell(present, pass) {
  if (!present) return `<span class="badge suspicious">NOT PRESENT</span>`;
  if (pass === true) return `<span class="badge safe">PASS</span>`;
  if (pass === false) return `<span class="badge phishing">FAIL</span>`;
  return `<span class="badge suspicious">PRESENT (unknown result)</span>`;
}

/* ------------ Message header table ------------ */
function renderSummary(a) {
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

  $("summaryTable").innerHTML = rows
    .map(
      ([k, v]) =>
        `<tr><td>${escapeHtml(k)}</td><td>${escapeHtml(String(v))}</td></tr>`
    )
    .join("");

  if (a.received_chain && a.received_chain.length) {
    const hops = a.received_chain
      .map((h, i) => `[${i + 1}] ${escapeHtml(h)}`)
      .join("\n");
    $("summaryTable").innerHTML += `
      <tr><td>Received Chain</td>
          <td><pre class="raw-pre small-pre">${hops}</pre></td></tr>`;
  }
}

function formatAddress(entry) {
  if (!entry) return "";
  if (typeof entry === "string") return entry;
  const name = entry[0] || "";
  const email = entry[1] || "";
  return name ? `${name} <${email}>` : email;
}

/* ------------ Raw headers ------------ */
function renderRawHeaders(raw) {
  const pre = $("rawHeadersPre");
  if (!raw) {
    pre.textContent = "(no headers)";
    return;
  }
  pre.textContent = raw;
}

/* ------------ Flags ------------ */
function renderFlags(flags) {
  const list = $("flagsList");
  if (!flags.length) {
    list.innerHTML = `<li class="muted">No suspicious features detected.</li>`;
    return;
  }
  list.innerHTML = flags
    .map(
      (f) =>
        `<li><span class="module-tag">${escapeHtml(f.module)}</span>${escapeHtml(f.detail)}</li>`
    )
    .join("");
}

/* ------------ URLs ------------ */
const URL_PREVIEW_LEN = 90;

function shortenUrl(url) {
  if (!url) return "";
  if (url.length <= URL_PREVIEW_LEN) return url;
  return (
    url.slice(0, 55) + "…" + url.slice(-25) + `  [${url.length} chars]`
  );
}

function cleanFlag(flagText, fullUrl) {
  if (!flagText) return "";
  let t = flagText;

  // Strip the URL from the flag text
  if (fullUrl) {
    t = t.split(fullUrl).join("");
  }

  // Strip any remaining http(s)://... token
  t = t.replace(/https?:\/\/\S+/g, "");

  // Drop flags that only mention the URL length (already shown in meta)
  t = t.replace(/(Unusually long URL|Extremely long URL)\s*:?\s*/gi, "");

  // Collapse leftover separators
  t = t.replace(/\s*·\s*·/g, " · ");
  t = t.replace(/^\s*·\s*|\s*·\s*$/g, "");
  t = t.replace(/\s{2,}/g, " ").trim();

  return t;
}

function renderUrls(urls) {
  const c = $("urlsContainer");
  if (!urls.length) {
    c.innerHTML = `<p class="muted">No URLs extracted.</p>`;
    return;
  }

  // Group by domain
  const groups = {};
  urls.forEach((u) => {
    const d = u.domain || "(unknown)";
    if (!groups[d]) groups[d] = [];
    groups[d].push(u);
  });

  const domainOrder = Object.keys(groups).sort(
    (a, b) => getGroupScore(groups[b]) - getGroupScore(groups[a])
  );

  let html = "";
  domainOrder.forEach((domain) => {
    const items = groups[domain];
    const maxScore = getGroupScore(items);
    const cls = maxScore >= 60 ? "phishing" : maxScore >= 30 ? "suspicious" : "safe";
    html += `
      <div class="url-group">
        <div class="url-group-header">
          <span class="url-group-domain">${escapeHtml(domain)}</span>
          <span class="badge ${cls}">${items.length} URL${items.length > 1 ? "s" : ""} · max ${maxScore}</span>
        </div>
    `;

    items.forEach((u) => {
      const full = u.url || "";
      const preview = shortenUrl(full);

      // Clean + dedupe flags, drop empties
      const uniqueFlags = [...new Set(u.flags || [])]
        .map((f) => cleanFlag(f, full))
        .filter((f) => f && f.length > 0);

      const flagText = uniqueFlags.length
        ? " · ⚠ " + uniqueFlags.map(escapeHtml).join(" · ")
        : "";

      html += `
        <div class="url-item">
          <div class="url url-preview" title="${escapeHtml(full)}">${escapeHtml(preview)}</div>
          <details class="url-details">
            <summary class="muted">show full URL</summary>
            <pre class="raw-pre small-pre">${escapeHtml(full)}</pre>
          </details>
          <div class="meta">Score: ${u.score}${flagText}</div>
        </div>
      `;
    });

    html += `</div>`;
  });

  c.innerHTML = html;
}

function getGroupScore(items) {
  return Math.max(...items.map((i) => i.score || 0));
}

/* ------------ IPs ------------ */
function renderIps(ips) {
  const c = $("ipsContainer");
  if (!ips || !ips.length) {
    c.innerHTML = `<p class="muted">No IP addresses found.</p>`;
    return;
  }
  c.innerHTML = ips
    .map((i) => {
      const tags = [];
      if (i.private) tags.push("private");
      if (i.loopback) tags.push("loopback");
      if (i.link_local) tags.push("link-local");
      if (i.multicast) tags.push("multicast");
      if (i.public) tags.push("public");
      const cls = i.public ? "phishing" : "safe";
      return `
        <div class="url-item">
          <div class="url">${escapeHtml(i.ip)}</div>
          <div class="meta">
            <span class="badge ${cls}">${i.public ? "PUBLIC" : "PRIVATE"}</span>
            ${tags.map((t) => `<span class="module-tag">${t}</span>`).join(" ")}
          </div>
        </div>`;
    })
    .join("");
}

/* ------------ Attachments ------------ */
function renderAttachments(atts) {
  const c = $("attachmentsContainer");
  if (!atts.length) {
    c.innerHTML = `<p class="muted">No attachments.</p>`;
    return;
  }
  c.innerHTML = atts
    .map(
      (a) => `
      <div class="att-item">
        <div class="name">${escapeHtml(a.filename || "")}</div>
        <div class="muted">${escapeHtml(a.content_type || "")} · ${a.size} bytes · Score: ${a.score}</div>
        ${a.flags && a.flags.length
          ? `<div class="muted">⚠ ${a.flags.map(escapeHtml).join(" · ")}</div>`
          : ""}
      </div>`
    )
    .join("");
}

function bindReportButtons(id) {
  const jsonBtn = $("downloadJsonBtn");
  const pdfBtn = $("downloadPdfBtn");
  jsonBtn.onclick = () => window.open(`/api/analyses/${id}/report?format=json`, "_blank");
  pdfBtn.onclick = () => window.open(`/api/analyses/${id}/report?format=pdf`, "_blank");
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}