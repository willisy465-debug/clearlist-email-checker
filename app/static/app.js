const SAMPLE = [
  "satyan@microsoft.com",
  "matt@automattic.com",
  "foo@",
  "jane.doe@gmial.com",
  "newsletter@mailinator.com",
  "person@example.invalid",
  "name@clearlist-no-such-domain-zz12345.com",
  "info@gmail.com",
].join("\n");

const MAX_EMAILS = 60000;
const MAX_UPLOAD_LISTS = 3;
const DOM_RENDER_LIMIT = 400;

const VERDICTS = {
  send: ["Safe to send", "safe"],
  suppress: ["Do not send", "bad"],
  retry: ["Soft-bounce risk", "soft"],
  review: ["Needs review", "risk"],
};

const BOUNCE = {
  none: "No bounce signal",
  hard: "Hard bounce",
  soft: "Soft bounce",
  unknown: "Bounce unknown",
};

const state = {
  rows: [],
  filter: "all",
  query: "",
  running: false,
  abort: null,
  forceSmtp: false,
  uploadedLists: [null, null, null], // Up to 3 uploaded lists: { name, emails }
  targetSlot: null,
};

const input = document.querySelector("#input");
const count = document.querySelector("#count");
const verifyBtn = document.querySelector("#verify");
const stopBtn = document.querySelector("#stop");
const permit = document.querySelector("#permit");
const banner = document.querySelector("#banner");
const bannerText = document.querySelector("#banner-text");
const results = document.querySelector("#results");
const list = document.querySelector("#list");
const renderCapNote = document.querySelector("#render-cap-note");
const empty = document.querySelector("#empty");
const progress = document.querySelector("#progress");
const bar = document.querySelector("#bar");
const progressLabel = document.querySelector("#progress-label");
const search = document.querySelector("#search");
const cleanOutput = document.querySelector("#clean-output");
const cleanSummary = document.querySelector("#clean-summary");
const includeReview = document.querySelector("#include-review");
const copyCleanBtn = document.querySelector("#copy-clean");
const clearListsBtn = document.querySelector("#clear-lists");
const smtpBox = document.querySelector("#opt-smtp");
const catchBox = document.querySelector("#opt-catch");
const helo = document.querySelector("#helo");
const mailFrom = document.querySelector("#mailfrom");
const proxyUrl = document.querySelector("#proxy-url");
const apiUrl = document.querySelector("#api-url");
const apiKey = document.querySelector("#api-key");
const fileInput = document.querySelector("#file");
const composer = document.querySelector("#composer");

permit.checked = sessionStorage.getItem("clearlist-permit") === "1";
helo.value = localStorage.getItem("clearlist-helo") || "";
mailFrom.value = localStorage.getItem("clearlist-mailfrom") || "";
proxyUrl.value = localStorage.getItem("clearlist-proxy") || "";
apiUrl.value = localStorage.getItem("clearlist-api-url") || "";
apiKey.value = sessionStorage.getItem("clearlist-api-key") || "";
smtpBox.checked = localStorage.getItem("clearlist-smtp") !== "0";
catchBox.checked = localStorage.getItem("clearlist-catch") !== "0";

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text != null) node.textContent = text;
  return node;
}

function extractTokensFromText(raw) {
  const skip = new Set([
    "email",
    "e-mail",
    "emails",
    "email address",
    "mail",
    "address",
    "name",
    "first name",
    "last name",
  ]);
  const text = raw.replace(/[\u200b\u200c\u200d\ufeff]/g, "");
  const tokens = [];

  for (let piece of text.split(/[\s,;|]+/)) {
    piece = piece.replace(/^mailto:/i, "").replace(/^["'<([]+/, "").replace(/[>"')\]]+$/, "").trim();
    if (!piece || skip.has(piece.toLowerCase())) continue;
    if (piece.includes("@") || piece.includes(".")) tokens.push(piece);
  }

  if (!tokens.length) {
    for (const line of text.split(/\r?\n/)) {
      const value = line.trim();
      if (value && !skip.has(value.toLowerCase())) tokens.push(value);
    }
  }
  return tokens;
}

function parseCombinedAddresses() {
  const seen = new Set();
  const emails = [];
  let dupes = 0;

  function push(token) {
    const value = token.trim();
    if (!value) return;
    const key = value.toLowerCase();
    if (seen.has(key)) {
      dupes += 1;
      return;
    }
    seen.add(key);
    emails.push(value);
  }

  // Merge all uploaded list slots (List 1, List 2, List 3) + textarea
  for (const slot of state.uploadedLists) {
    if (!slot || !slot.emails) continue;
    for (const addr of slot.emails) push(addr);
  }
  for (const addr of extractTokensFromText(input.value)) {
    push(addr);
  }

  return { emails, dupes };
}

function renderSlots() {
  let activeCount = 0;
  for (let i = 0; i < MAX_UPLOAD_LISTS; i += 1) {
    const slotEl = document.querySelector(`.slot[data-slot="${i}"]`);
    const nameEl = document.querySelector(`[data-slot-name="${i}"]`);
    const metaEl = document.querySelector(`[data-slot-meta="${i}"]`);
    const removeBtn = document.querySelector(`[data-slot-remove="${i}"]`);
    const data = state.uploadedLists[i];
    if (!slotEl || !nameEl || !metaEl || !removeBtn) continue;

    if (data) {
      activeCount += 1;
      slotEl.classList.add("filled");
      nameEl.textContent = data.name;
      metaEl.textContent = `${data.emails.length.toLocaleString()} emails loaded`;
      removeBtn.hidden = false;
    } else {
      slotEl.classList.remove("filled");
      nameEl.textContent = "No file uploaded";
      metaEl.textContent = "Click to upload CSV/TXT";
      removeBtn.hidden = true;
    }
  }
  if (clearListsBtn) {
    clearListsBtn.hidden = activeCount === 0;
  }
}

function syncComposer() {
  renderSlots();
  const { emails, dupes } = parseCombinedAddresses();
  const tooMany = emails.length > MAX_EMAILS;
  const activeLists = state.uploadedLists.filter(Boolean).length;
  const listTag = activeLists ? ` across ${activeLists} uploaded ${activeLists === 1 ? "list" : "lists"}` : "";

  if (!permit.checked) {
    count.textContent = "Confirm you are allowed to verify this list.";
  } else if (!emails.length) {
    count.textContent = "Upload up to 3 CSV/TXT lists or paste addresses (up to 60,000 total).";
  } else if (tooMany) {
    count.textContent = `${emails.length.toLocaleString()} unique addresses loaded — exceeds the ${MAX_EMAILS.toLocaleString()} maximum per run.`;
  } else if (dupes) {
    count.textContent = `${emails.length.toLocaleString()} unique addresses${listTag} (${dupes.toLocaleString()} duplicates merged).`;
  } else {
    count.textContent =
      emails.length === 1
        ? `1 address${listTag}`
        : `${emails.length.toLocaleString()} addresses${listTag}`;
  }

  verifyBtn.disabled = state.running || !permit.checked || !emails.length || tooMany;
  verifyBtn.textContent = state.running ? "Checking..." : "Verify & Clean Lists";
  stopBtn.hidden = !state.running;
}

function showBanner(text, kind) {
  banner.hidden = !text;
  banner.classList.toggle("bad", kind === "bad");
  bannerText.textContent = text || "";
}

function errorMessage(payload, status) {
  if (!payload) return `Verification failed (${status}).`;
  if (typeof payload.detail === "string") return payload.detail;
  if (Array.isArray(payload.detail)) {
    return payload.detail.map((item) => item.msg || "Invalid request").join(" ");
  }
  return `Verification failed (${status}).`;
}

function tally(rows) {
  const totals = { all: rows.length, send: 0, suppress: 0, retry: 0, review: 0 };
  for (const row of rows) totals[row.action] = (totals[row.action] || 0) + 1;
  return totals;
}

function getCleanRows() {
  const allowed = includeReview?.checked ? new Set(["send", "review"]) : new Set(["send"]);
  return state.rows.filter((row) => allowed.has(row.action));
}

function updateStats() {
  const totals = tally(state.rows);
  for (const key of Object.keys(totals)) {
    const node = document.querySelector(`[data-count="${key}"]`);
    if (node) node.textContent = totals[key].toLocaleString();
  }
  const cleanRows = getCleanRows();
  if (cleanOutput) {
    const previewSlice = cleanRows.slice(0, 500).map((row) => row.email || row.input);
    if (cleanRows.length > 500) {
      previewSlice.push(`... and ${(cleanRows.length - 500).toLocaleString()} more clean emails (all ${cleanRows.length.toLocaleString()} included in download)`);
    }
    cleanOutput.value = previewSlice.join("\n");
  }
  document.querySelectorAll("[data-clean-count]").forEach((node) => {
    node.textContent = cleanRows.length.toLocaleString();
  });
  if (cleanSummary) {
    const removed = state.rows.length - cleanRows.length;
    if (!state.rows.length) {
      cleanSummary.textContent =
        "Verified safe-to-send addresses from all uploaded lists are merged and deduplicated here into one final download. Hard bounces, syntax errors, and disposable inboxes are removed.";
    } else {
      cleanSummary.textContent = `${cleanRows.length.toLocaleString()} clean deliverable ${
        cleanRows.length === 1 ? "address" : "addresses"
      } ready in one final download (${removed.toLocaleString()} risky or bouncing ${
        removed === 1 ? "address" : "addresses"
      } removed).`;
    }
  }
  if (copyCleanBtn) {
    copyCleanBtn.disabled = cleanRows.length === 0;
  }
  document.querySelectorAll("[data-download]").forEach((button) => {
    const kind = button.dataset.download;
    if (kind === "clean-csv" || kind === "clean-txt") {
      button.disabled = cleanRows.length === 0;
    } else if (kind === "csv") {
      button.disabled = state.rows.length === 0;
    } else {
      button.disabled = !totals[kind];
    }
  });
}

function matches(row) {
  if (state.filter !== "all" && row.action !== state.filter) return false;
  const query = state.query.trim().toLowerCase();
  if (!query) return true;
  const risks = (row.risks || []).map((item) => `${item.label} ${item.detail}`).join(" ");
  return `${row.input} ${row.email} ${row.summary} ${risks}`.toLowerCase().includes(query);
}

function verdictFor(row) {
  if (row.action === "review" && row.status === "unknown") return ["Not confirmed", "unknown"];
  return VERDICTS[row.action] || ["Needs review", "risk"];
}

function rowCard(row) {
  const [label, tone] = verdictFor(row);
  const card = el("article", `result ${tone}`);
  const top = el("div", "result-top");
  top.append(el("span", `pill ${tone}`, label));
  top.append(el("span", "bounce", BOUNCE[row.bounce] || row.bounce));
  const score = el("span", "score", `Score ${row.score}`);
  score.title = "How likely this address is to accept mail without bouncing. Not inbox placement.";
  top.append(score);
  card.append(top);
  card.append(el("p", "addr", row.email || row.input));
  if (row.email && row.input && row.email !== row.input.trim()) {
    card.append(el("p", "checked-as", `From your list: ${row.input.trim()}`));
  }
  card.append(el("p", "why", row.summary));
  if (row.suggestion) card.append(el("p", "suggestion", `Suggested: ${row.suggestion}`));

  const chips = el("div", "chips");
  for (const item of row.risks || []) {
    chips.append(el("span", `chip ${item.severity || "info"}`, item.label));
  }
  if (chips.childNodes.length) card.append(chips);

  const toggle = el("button", "toggle", "Details");
  toggle.type = "button";
  toggle.setAttribute("aria-expanded", "false");
  const detail = el("div", "detail");
  detail.hidden = true;
  detail.append(detailList(row));
  toggle.addEventListener("click", () => {
    detail.hidden = !detail.hidden;
    toggle.setAttribute("aria-expanded", String(!detail.hidden));
    toggle.textContent = detail.hidden ? "Details" : "Hide details";
  });
  card.append(toggle, detail);
  return card;
}

function detailList(row) {
  const wrap = document.createElement("div");
  const dl = document.createElement("dl");
  const checks = row.checks || {};
  const rows = [
    ["Syntax", checks.syntax?.detail],
    ["DNS", checks.dns?.detail],
    ["MX", mxLine(checks.mx)],
    ["SMTP", checks.smtp?.detail],
    ["Catch-all", catchLine(checks.smtp?.catch_all)],
  ];
  for (const [name, value] of rows) {
    dl.append(el("dt", "", name), el("dd", "", value || "Not checked."));
  }
  wrap.append(dl);
  if ((row.risks || []).length) {
    const ul = document.createElement("ul");
    for (const item of row.risks) ul.append(el("li", "", `${item.label}: ${item.detail}`));
    wrap.append(ul);
  }
  return wrap;
}

function mxLine(mx) {
  if (!mx) return "Not checked.";
  const hosts = (mx.hosts || []).slice(0, 3).join(", ");
  return hosts ? `${mx.detail} Hosts: ${hosts}.` : mx.detail;
}

function catchLine(value) {
  if (value === true) return "Yes. The server accepted a made-up address.";
  if (value === false) return "No. The server rejected a made-up address.";
  return "Not tested.";
}

function renderList() {
  const visible = state.rows.filter(matches);
  list.replaceChildren();
  const capped = visible.slice(0, DOM_RENDER_LIMIT);
  const fragment = document.createDocumentFragment();
  for (const row of capped) fragment.append(rowCard(row));
  list.append(fragment);
  if (renderCapNote) {
    if (visible.length > DOM_RENDER_LIMIT) {
      renderCapNote.hidden = false;
      renderCapNote.textContent = `Showing first ${DOM_RENDER_LIMIT.toLocaleString()} of ${visible.length.toLocaleString()} matching addresses to keep your browser fast. All ${state.rows.length.toLocaleString()} addresses are included in the final downloads above.`;
    } else {
      renderCapNote.hidden = true;
    }
  }
  empty.hidden = visible.length !== 0;
}

function addRows(rows) {
  const previousCount = state.rows.length;
  state.rows.push(...rows);
  updateStats();
  if (state.filter === "all" && !state.query.trim()) {
    if (previousCount < DOM_RENDER_LIMIT) {
      const slice = rows.slice(0, DOM_RENDER_LIMIT - previousCount);
      const fragment = document.createDocumentFragment();
      for (const row of slice) fragment.append(rowCard(row));
      list.append(fragment);
    }
    if (renderCapNote) {
      if (state.rows.length > DOM_RENDER_LIMIT) {
        renderCapNote.hidden = false;
        renderCapNote.textContent = `Showing first ${DOM_RENDER_LIMIT.toLocaleString()} of ${state.rows.length.toLocaleString()} addresses to keep your browser fast. All ${state.rows.length.toLocaleString()} addresses are included in the final downloads above.`;
      } else {
        renderCapNote.hidden = true;
      }
    }
    empty.hidden = state.rows.length !== 0;
  } else {
    renderList();
  }
}

function csvCell(value) {
  let text = String(value ?? "");
  if (/^[=+\-@]/.test(text)) text = `'${text}`;
  if (/[",\n]/.test(text)) return `"${text.replaceAll('"', '""')}"`;
  return text;
}

function download(filename, content, type) {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

function exportRows(kind) {
  if (kind === "clean-txt") {
    const cleanRows = getCleanRows();
    const lines = cleanRows.map((row) => row.email || row.input);
    download("clearlist-final-cleaned-emails.txt", lines.join("\n"), "text/plain");
    return;
  }
  if (kind === "clean-csv") {
    const cleanRows = getCleanRows();
    const headers = ["email", "status", "action", "score", "domain_mx", "verification_detail"];
    const lines = [headers.join(",")];
    for (const row of cleanRows) {
      const values = [
        row.email || row.input,
        row.status,
        row.action,
        row.score,
        (row.checks?.mx?.hosts || []).join(" "),
        row.summary,
      ];
      lines.push(values.map(csvCell).join(","));
    }
    download("clearlist-final-cleaned-emails.csv", lines.join("\n"), "text/csv");
    return;
  }
  if (kind === "csv") {
    const headers = ["input", "email", "status", "action", "bounce", "score", "summary", "suggestion", "mx", "smtp_state", "smtp_code", "smtp_detail", "risks"];
    const lines = [headers.join(",")];
    for (const row of state.rows) {
      const values = [
        row.input,
        row.email,
        row.status,
        row.action,
        row.bounce,
        row.score,
        row.summary,
        row.suggestion || "",
        (row.checks?.mx?.hosts || []).join(" "),
        row.checks?.smtp?.state || "",
        row.checks?.smtp?.code ?? "",
        row.checks?.smtp?.detail || "",
        (row.risks || []).map((item) => item.label).join("; "),
      ];
      lines.push(values.map(csvCell).join(","));
    }
    download("clearlist-full-audit-report.csv", lines.join("\n"), "text/csv");
    return;
  }
  const lines = state.rows.filter((row) => row.action === kind).map((row) => row.email || row.input);
  download(`clearlist-${kind}.txt`, lines.join("\n"), "text/plain");
}

async function loadFilesIntoSlots(fileList, preferredSlot = null) {
  const files = Array.from(fileList || []).slice(0, MAX_UPLOAD_LISTS);
  if (!files.length) return;

  for (let idx = 0; idx < files.length; idx += 1) {
    const file = files[idx];
    const text = await file.text();
    const extracted = extractTokensFromText(text);
    let slotIndex = preferredSlot !== null && files.length === 1 ? preferredSlot : state.uploadedLists.findIndex((item) => item === null);
    if (slotIndex === -1) {
      slotIndex = idx % MAX_UPLOAD_LISTS;
    }
    state.uploadedLists[slotIndex] = {
      name: file.name,
      emails: extracted,
    };
  }
  state.targetSlot = null;
  syncComposer();
}

async function runVerification() {
  const { emails } = parseCombinedAddresses();
  if (!permit.checked || !emails.length || emails.length > MAX_EMAILS || state.running) return;
  const sender = mailFrom.value.trim();
  if (sender && !sender.includes("@")) {
    showBanner("MAIL FROM should be a full email address, or left empty.", "bad");
    return;
  }

  state.running = true;
  state.rows = [];
  list.replaceChildren();
  updateStats();
  results.hidden = false;
  empty.hidden = true;
  progress.hidden = false;
  showBanner("");
  syncComposer();

  const controller = new AbortController();
  state.abort = controller;

  const isBulk = emails.length >= 250;
  const chunkSize = isBulk ? 250 : smtpBox.checked ? 20 : 80;
  const concurrency = isBulk ? 4 : 1;
  let completed = 0;
  let network = "disabled";

  const chunks = [];
  for (let i = 0; i < emails.length; i += chunkSize) {
    chunks.push(emails.slice(i, i + chunkSize));
  }

  let chunkCursor = 0;

  async function worker() {
    while (chunkCursor < chunks.length) {
      const myIndex = chunkCursor;
      chunkCursor += 1;
      const chunk = chunks[myIndex];
      progressLabel.textContent = `Checking ${completed.toLocaleString()} of ${emails.length.toLocaleString()} addresses...`;
      bar.style.width = `${Math.round((completed / emails.length) * 100)}%`;

      const response = await fetch("/api/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        signal: controller.signal,
        body: JSON.stringify({
          emails: chunk,
          smtp: smtpBox.checked,
          catch_all: catchBox.checked,
          helo: helo.value.trim(),
          mail_from: sender,
          force_smtp: state.forceSmtp,
          proxy_url: proxyUrl.value.trim(),
          api_url: apiUrl.value.trim(),
          api_key: apiKey.value.trim(),
          fast_bulk: isBulk,
        }),
      });
      const payload = await response.json().catch(() => null);
      if (!response.ok) throw new Error(errorMessage(payload, response.status));
      network = payload.smtp_network || network;
      addRows(payload.results || []);
      completed += chunk.length;
      progressLabel.textContent = `Checked ${completed.toLocaleString()} of ${emails.length.toLocaleString()} addresses`;
      bar.style.width = `${Math.round((completed / emails.length) * 100)}%`;
    }
  }

  try {
    const workers = [];
    for (let w = 0; w < Math.min(concurrency, chunks.length); w += 1) {
      workers.push(worker());
    }
    await Promise.all(workers);

    bar.style.width = "100%";
    const totals = tally(state.rows);
    progressLabel.textContent = `Complete: ${totals.send.toLocaleString()} safe to send, ${totals.suppress.toLocaleString()} to suppress, ${totals.retry.toLocaleString()} to retry, ${totals.review.toLocaleString()} to review.`;
    showBanner("");
  } catch (error) {
    if (error.name === "AbortError") {
      showBanner("Stopped. Partial results are kept below and ready to download.");
      progressLabel.textContent = "Stopped.";
    } else {
      showBanner(error.message || "Verification failed.", "bad");
    }
  } finally {
    state.running = false;
    state.abort = null;
    syncComposer();
  }
}

input.addEventListener("input", syncComposer);
permit.addEventListener("change", () => {
  sessionStorage.setItem("clearlist-permit", permit.checked ? "1" : "0");
  syncComposer();
});
helo.addEventListener("change", () => localStorage.setItem("clearlist-helo", helo.value.trim()));
mailFrom.addEventListener("change", () => localStorage.setItem("clearlist-mailfrom", mailFrom.value.trim()));
proxyUrl.addEventListener("change", () => localStorage.setItem("clearlist-proxy", proxyUrl.value.trim()));
apiUrl.addEventListener("change", () => localStorage.setItem("clearlist-api-url", apiUrl.value.trim()));
apiKey.addEventListener("change", () => sessionStorage.setItem("clearlist-api-key", apiKey.value.trim()));
smtpBox.addEventListener("change", () => localStorage.setItem("clearlist-smtp", smtpBox.checked ? "1" : "0"));
catchBox.addEventListener("change", () => localStorage.setItem("clearlist-catch", catchBox.checked ? "1" : "0"));

document.querySelector("#sample").addEventListener("click", () => {
  if (input.value.trim() && !window.confirm("Replace the current text box with examples?")) return;
  input.value = SAMPLE;
  syncComposer();
});

document.querySelector("#upload").addEventListener("click", () => {
  state.targetSlot = null;
  fileInput.click();
});

if (clearListsBtn) {
  clearListsBtn.addEventListener("click", () => {
    state.uploadedLists = [null, null, null];
    syncComposer();
  });
}

document.querySelectorAll(".slot").forEach((slotEl) => {
  slotEl.addEventListener("click", (event) => {
    if (event.target.closest(".slot-remove")) return;
    state.targetSlot = Number(slotEl.dataset.slot);
    fileInput.click();
  });
});

document.querySelectorAll("[data-slot-remove]").forEach((btn) => {
  btn.addEventListener("click", (event) => {
    event.stopPropagation();
    const idx = Number(btn.dataset.slotRemove);
    state.uploadedLists[idx] = null;
    syncComposer();
  });
});

fileInput.addEventListener("change", async () => {
  const files = fileInput.files;
  if (!files || !files.length) return;
  await loadFilesIntoSlots(files, state.targetSlot);
  fileInput.value = "";
});

composer.addEventListener("dragover", (event) => {
  event.preventDefault();
  composer.classList.add("drag");
});
composer.addEventListener("dragleave", () => composer.classList.remove("drag"));
composer.addEventListener("drop", async (event) => {
  event.preventDefault();
  composer.classList.remove("drag");
  const files = event.dataTransfer?.files;
  if (files && files.length) {
    await loadFilesIntoSlots(files, null);
  } else {
    input.value = event.dataTransfer?.getData("text") || input.value;
    syncComposer();
  }
});

verifyBtn.addEventListener("click", () => {
  state.forceSmtp = true;
  runVerification();
});
stopBtn.addEventListener("click", () => state.abort?.abort());
input.addEventListener("keydown", (event) => {
  if ((event.ctrlKey || event.metaKey) && event.key === "Enter") {
    event.preventDefault();
    state.forceSmtp = true;
    runVerification();
  }
});

document.querySelectorAll("[data-filter]").forEach((button) => {
  button.addEventListener("click", () => {
    state.filter = button.dataset.filter;
    document.querySelectorAll("[data-filter]").forEach((item) => {
      item.classList.toggle("active", item === button);
    });
    renderList();
  });
});
search.addEventListener("input", () => {
  state.query = search.value;
  renderList();
});
document.querySelectorAll("[data-download]").forEach((button) => {
  button.addEventListener("click", () => exportRows(button.dataset.download));
});
if (includeReview) {
  includeReview.addEventListener("change", () => updateStats());
}
if (copyCleanBtn) {
  copyCleanBtn.addEventListener("click", async () => {
    const cleanRows = getCleanRows();
    const text = cleanRows.map((row) => row.email || row.input).join("\n");
    if (!text) return;
    try {
      await navigator.clipboard.writeText(text);
      const prev = copyCleanBtn.textContent;
      copyCleanBtn.textContent = "Copied!";
      setTimeout(() => {
        copyCleanBtn.textContent = prev;
      }, 1800);
    } catch {
      cleanOutput.select();
    }
  });
}

fetch("/api/health")
  .then((response) => response.json())
  .then((data) => {
    if (data.helo) helo.placeholder = data.helo;
  })
  .catch(() => {});

syncComposer();
