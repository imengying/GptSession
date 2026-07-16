import {
  buildZipArchive,
  buildOutputDocument,
  getDownloadDescriptor,
  parseCredentialText,
  redactSensitiveDocument,
  type AccountSourceType,
  type DownloadDescriptor,
  type NormalizedAccount,
  type OutputDocument,
  type OutputFormat,
  type ParseIssue,
} from "./core";

interface AppState {
  format: OutputFormat;
  accounts: NormalizedAccount[];
  issues: ParseIssue[];
  revealSecrets: boolean;
  generatedAt?: Date;
}

const state: AppState = {
  format: "sub2api",
  accounts: [],
  issues: [],
  revealSecrets: false,
};

function element<T extends HTMLElement>(selector: string): T {
  const found = document.querySelector<T>(selector);
  if (!found) {
    throw new Error("Missing required element: " + selector);
  }
  return found;
}

const elements = {
  accountBody: element<HTMLTableSectionElement>("#account-body"),
  clearAll: element<HTMLButtonElement>("#clear-all"),
  clearResults: element<HTMLButtonElement>("#clear-results"),
  copyOutput: element<HTMLButtonElement>("#copy-output"),
  downloadOutput: element<HTMLButtonElement>("#download-output"),
  dropzone: element<HTMLElement>("#dropzone"),
  fileInput: element<HTMLInputElement>("#file-input"),
  folderInput: element<HTMLInputElement>("#folder-input"),
  formatButtons: Array.from(
    document.querySelectorAll<HTMLButtonElement>("[data-format]"),
  ),
  formatDescription: element<HTMLElement>("#format-description"),
  input: element<HTMLTextAreaElement>("#session-input"),
  inputStatus: element<HTMLElement>("#input-status"),
  issuesBox: element<HTMLDetailsElement>("#issues-box"),
  issuesList: element<HTMLUListElement>("#issues-list"),
  issuesSummary: element<HTMLElement>("#issues-summary"),
  outputMeta: element<HTMLElement>("#output-meta"),
  outputPanel: element<HTMLElement>("#output-panel"),
  outputPreview: element<HTMLTextAreaElement>("#output-preview"),
  outputTitle: element<HTMLElement>("#output-title"),
  pickFiles: element<HTMLButtonElement>("#pick-files"),
  pickFolder: element<HTMLButtonElement>("#pick-folder"),
  previewBadge: element<HTMLElement>("#preview-badge"),
  statAccounts: element<HTMLElement>("#stat-accounts"),
  statIssues: element<HTMLElement>("#stat-issues"),
  statRefreshable: element<HTMLElement>("#stat-refreshable"),
  toast: element<HTMLElement>("#toast"),
  toggleSecrets: element<HTMLButtonElement>("#toggle-secrets"),
};

const MAX_FILE_SIZE = 10 * 1024 * 1024;
const MAX_FILES = 500;
let toastTimer: number | undefined;

const SOURCE_LABELS: Record<AccountSourceType, string> = {
  chatgpt_web_session: "SESSION",
  cpa: "CPA",
  sub2api: "SUB2API",
};

function escapeHtml(value: unknown): string {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function getBaseName(value: string): string {
  const normalized = value.replaceAll("\\", "/");
  return normalized.split("/").filter(Boolean).pop() ?? "未命名来源";
}

function getDirectoryName(value: string): string {
  const parts = value.replaceAll("\\", "/").split("/").filter(Boolean);
  parts.pop();
  return parts.join("/");
}

function formatDate(value?: string): string | undefined {
  if (!value) {
    return undefined;
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }
  const pad = (number: number) => String(number).padStart(2, "0");
  return [
    date.getFullYear(),
    pad(date.getMonth() + 1),
    pad(date.getDate()),
  ].join("-") + " " + [
    pad(date.getHours()),
    pad(date.getMinutes()),
  ].join(":");
}

function formatAccountId(value?: string): string {
  if (!value) {
    return "account_id 未识别";
  }
  return value.length <= 18
    ? value
    : value.slice(0, 8) + "…" + value.slice(-6);
}

function setInputStatus(
  message: string,
  tone?: "working" | "success" | "error",
): void {
  elements.inputStatus.classList.remove("is-working", "is-success", "is-error");
  if (tone) {
    elements.inputStatus.classList.add("is-" + tone);
  }
  elements.inputStatus.innerHTML = '<span class="status-light"></span>'
    + escapeHtml(message);
}

function showToast(message: string, tone?: "error"): void {
  window.clearTimeout(toastTimer);
  elements.toast.textContent = message;
  elements.toast.classList.toggle("is-error", tone === "error");
  elements.toast.classList.add("is-visible");
  toastTimer = window.setTimeout(() => {
    elements.toast.classList.remove("is-visible");
  }, 2600);
}

function getWarningCount(): number {
  return state.issues.length + state.accounts.reduce(
    (total, account) => total + account.warnings.length,
    0,
  );
}

function getExportDate(): Date {
  return state.generatedAt ?? new Date();
}

function getCurrentDocument(): OutputDocument {
  return buildOutputDocument(state.accounts, state.format, {
    now: getExportDate(),
  });
}

function getCurrentOutputText(): string {
  return state.accounts.length
    ? JSON.stringify(getCurrentDocument(), null, 2)
    : "";
}

function renderFormatControls(): void {
  for (const button of elements.formatButtons) {
    const active = button.dataset.format === state.format;
    button.classList.toggle("is-active", active);
    button.setAttribute("aria-selected", String(active));
    button.tabIndex = active ? 0 : -1;
    if (active && button.id) {
      elements.outputPanel.setAttribute("aria-labelledby", button.id);
    }
  }

  if (state.format === "cpa") {
    elements.outputTitle.textContent = "CPA 认证文件";
    elements.formatDescription.textContent = state.accounts.length > 1
      ? "将 Session 或 sub2api 账号转换为独立 Codex CPA JSON；批量下载时自动打包为 ZIP。"
      : "生成 Codex CPA auth JSON，并保留可恢复的 token、账号信息与过期时间。";
    elements.downloadOutput.textContent = state.accounts.length > 1
      ? "下载 CPA ZIP"
      : "下载 CPA JSON";
  } else {
    elements.outputTitle.textContent = "sub2api 导入包";
    elements.formatDescription.textContent =
      "将 Session 或 CPA 凭证转换为 exported_at / proxies / accounts 批量导入结构。";
    elements.downloadOutput.textContent = "下载 JSON";
  }
}

function renderOutput(): void {
  const hasAccounts = state.accounts.length > 0;
  const fullDocument = hasAccounts ? getCurrentDocument() : undefined;
  const previewDocument = fullDocument && !state.revealSecrets
    ? redactSensitiveDocument(fullDocument)
    : fullDocument;

  elements.outputPreview.value = previewDocument
    ? JSON.stringify(previewDocument, null, 2)
    : "";
  elements.copyOutput.disabled = !hasAccounts;
  elements.downloadOutput.disabled = !hasAccounts;
  elements.toggleSecrets.disabled = !hasAccounts;
  elements.clearResults.disabled = !hasAccounts && !state.issues.length;
  elements.toggleSecrets.setAttribute(
    "aria-pressed",
    String(state.revealSecrets),
  );
  elements.toggleSecrets.textContent = state.revealSecrets
    ? "恢复脱敏预览"
    : "显示完整凭证";
  elements.previewBadge.textContent = state.revealSecrets
    ? "完整凭证可见"
    : "已脱敏预览";
  elements.previewBadge.classList.toggle(
    "is-revealed",
    state.revealSecrets,
  );

  if (!hasAccounts) {
    elements.outputMeta.textContent = "等待账号";
  } else if (state.format === "cpa" && state.accounts.length > 1) {
    elements.outputMeta.textContent = state.accounts.length
      + " 个认证文件 · ZIP 下载";
  } else if (state.format === "cpa") {
    elements.outputMeta.textContent = "1 个认证文件 · JSON 下载";
  } else {
    elements.outputMeta.textContent = state.accounts.length
      + " 个账号 · 合并 JSON";
  }

  renderFormatControls();
}

function renderStatus(label: string, tone: string, detail?: string): string {
  const detailHtml = detail
    ? `<span class="expiry-detail">${escapeHtml(detail)}</span>`
    : "";
  return `<div class="status-stack">
    <span class="status-chip ${tone}">${escapeHtml(label)}</span>
    ${detailHtml}
  </div>`;
}

function renderAccountStatus(account: NormalizedAccount): string {
  const expiresAt = formatDate(account.tokenExpiresAt);
  if (account.isRefreshable) {
    return renderStatus(
      "可自动刷新",
      "is-refreshable",
      expiresAt ? "当前 token " + expiresAt : undefined,
    );
  }
  if (account.isExpired) {
    return renderStatus("已过期", "is-expired", expiresAt);
  }
  if (expiresAt) {
    return renderStatus("不可刷新", "is-warning", "到期 " + expiresAt);
  }
  return renderStatus("有效期未知", "is-warning", "不可自动刷新");
}

function renderAccounts(): void {
  elements.statAccounts.textContent = String(state.accounts.length);
  elements.statRefreshable.textContent = String(
    state.accounts.filter((account) => account.isRefreshable).length,
  );
  elements.statIssues.textContent = String(getWarningCount());

  if (!state.accounts.length) {
    elements.accountBody.innerHTML =
      '<tr class="empty-row"><td colspan="5">解析后的账号与来源格式会显示在这里。</td></tr>';
    return;
  }

  elements.accountBody.innerHTML = state.accounts.map((account, index) => {
    const sourceBase = getBaseName(account.sourceName);
    const sourceDirectory = getDirectoryName(account.sourceName);
    const sourcePath = account.sourcePath !== "$"
      ? account.sourcePath
      : sourceDirectory;
    const warningTitle = account.warnings.length
      ? account.warnings.join("\n")
      : "未发现额外提示";
    const accountName = escapeHtml(account.email ?? account.name);
    const accountId = escapeHtml(formatAccountId(account.accountId));
    const sourceLabel = escapeHtml(SOURCE_LABELS[account.sourceType]);
    const sourceDetail = sourceBase + (sourcePath ? " · " + sourcePath : "");
    const sourceTitle = account.sourceName
      + (sourcePath ? " · " + sourcePath : "");
    return `<tr>
      <td>
        <span class="account-primary" title="${accountName}">${accountName}</span>
        <span class="account-secondary" title="${escapeHtml(account.accountId)}">${accountId}</span>
      </td>
      <td><span class="plan-chip">${escapeHtml(account.planType ?? "未知")}</span></td>
      <td title="${escapeHtml(warningTitle)}">${renderAccountStatus(account)}</td>
      <td>
        <span class="source-chip source-${account.sourceType}" title="${escapeHtml(account.sourceName)}">${sourceLabel}</span>
        <span class="account-secondary" title="${escapeHtml(sourceTitle)}">${escapeHtml(sourceDetail)}</span>
      </td>
      <td>
        <button class="inline-button" type="button" data-download-index="${index}">下载 JSON</button>
      </td>
    </tr>`;
  }).join("");
}

function renderIssues(): void {
  const entries: ParseIssue[] = [...state.issues];
  for (const account of state.accounts) {
    for (const warning of account.warnings) {
      entries.push({
        sourceName: account.email ?? account.name,
        sourcePath: account.sourcePath,
        reason: warning,
      });
    }
  }

  if (!entries.length) {
    elements.issuesSummary.textContent = "暂无问题";
    elements.issuesList.innerHTML = '<li class="issue-empty">未发现问题。</li>';
    elements.issuesBox.open = false;
    return;
  }

  elements.issuesSummary.textContent = entries.length + " 条提示";
  elements.issuesList.innerHTML = entries.map((issue) => {
    const location = issue.sourcePath && issue.sourcePath !== "$"
      ? " · " + issue.sourcePath
      : "";
    return `<li><strong>${escapeHtml(issue.sourceName + location)}</strong> — ${escapeHtml(issue.reason)}</li>`;
  }).join("");
  if (!state.accounts.length || state.issues.length) {
    elements.issuesBox.open = true;
  }
}

function renderAll(): void {
  renderAccounts();
  renderIssues();
  renderOutput();
}

function resetResults(): void {
  state.accounts = [];
  state.issues = [];
  state.generatedAt = undefined;
  state.revealSecrets = false;
  renderAll();
}

function autoSelectOutput(accounts: NormalizedAccount[]): void {
  const sourceTypes = new Set(accounts.map((account) => account.sourceType));
  if (sourceTypes.size !== 1) {
    return;
  }
  if (sourceTypes.has("cpa")) {
    state.format = "sub2api";
  } else if (sourceTypes.has("sub2api")) {
    state.format = "cpa";
  }
}

function mergeParsedResult(
  result: ReturnType<typeof parseCredentialText>,
  replace: boolean,
): void {
  if (replace) {
    state.accounts = [];
    state.issues = [];
  }
  const seenTokens = new Set(
    state.accounts.map((account) => account.accessToken),
  );
  for (const account of result.accounts) {
    if (seenTokens.has(account.accessToken)) {
      state.issues.push({
        sourceName: account.sourceName,
        sourcePath: account.sourcePath,
        reason: "检测到重复凭证，已忽略",
      });
      continue;
    }
    seenTokens.add(account.accessToken);
    state.accounts.push(account);
  }
  state.issues.push(...result.issues);
  state.generatedAt = new Date();
  state.revealSecrets = false;
}

function processPastedInput(): void {
  const text = elements.input.value;
  if (!text.trim()) {
    setInputStatus("请先粘贴 Session、CPA 或 sub2api JSON。", "error");
    showToast("没有可解析的输入", "error");
    return;
  }
  setInputStatus("正在本地解析粘贴内容…", "working");
  window.setTimeout(() => {
    const result = parseCredentialText(text, {
      sourceName: "粘贴内容",
      now: new Date(),
    });
    autoSelectOutput(result.accounts);
    mergeParsedResult(result, true);
    renderAll();
    if (state.accounts.length) {
      setInputStatus(
        "解析完成：可导出 " + state.accounts.length
          + " 个账号，发现 " + getWarningCount() + " 条提示。",
        "success",
      );
    } else {
      setInputStatus("未找到可导出的凭证，请检查 JSON 结构。", "error");
    }
  }, 20);
}

async function processFiles(fileList: FileList | File[]): Promise<void> {
  const allFiles = Array.from(fileList);
  const jsonFiles = allFiles
    .filter((file) => file.name.toLowerCase().endsWith(".json"))
    .slice(0, MAX_FILES);
  if (!jsonFiles.length) {
    setInputStatus("没有找到 JSON 文件。", "error");
    showToast("请选择 JSON 文件", "error");
    return;
  }

  setInputStatus(
    "正在读取并解析 " + jsonFiles.length + " 个文件…",
    "working",
  );
  const oversizedIssues: ParseIssue[] = [];
  const readableFiles = jsonFiles.filter((file) => {
    if (file.size <= MAX_FILE_SIZE) {
      return true;
    }
    oversizedIssues.push({
      sourceName: file.webkitRelativePath || file.name,
      reason: "文件超过 10 MB，已跳过",
    });
    return false;
  });

  const results = await Promise.all(readableFiles.map(async (file) => {
    const sourceName = file.webkitRelativePath || file.name;
    try {
      return parseCredentialText(await file.text(), {
        sourceName,
        now: new Date(),
      });
    } catch (error) {
      return {
        accounts: [],
        issues: [{
          sourceName,
          reason: error instanceof Error ? error.message : "无法读取文件",
        }],
      };
    }
  }));

  if (!state.accounts.length) {
    autoSelectOutput(results.flatMap((result) => result.accounts));
  }
  for (const result of results) {
    mergeParsedResult(result, false);
  }
  state.issues.push(...oversizedIssues);
  if (allFiles.length > MAX_FILES) {
    state.issues.push({
      sourceName: "文件导入",
      reason: "一次最多处理 " + MAX_FILES + " 个文件，其余文件已跳过",
    });
  }
  renderAll();
  setInputStatus(
    state.accounts.length
      ? "文件解析完成：当前共有 " + state.accounts.length
        + " 个可导出账号，" + getWarningCount() + " 条提示。"
      : "文件中未找到可导出的 Session、CPA 或 sub2api 账号。",
    state.accounts.length ? "success" : "error",
  );
}

async function copyText(text: string): Promise<void> {
  if (navigator.clipboard && window.isSecureContext) {
    await navigator.clipboard.writeText(text);
    return;
  }
  const temporary = document.createElement("textarea");
  temporary.value = text;
  temporary.readOnly = true;
  temporary.style.position = "fixed";
  temporary.style.opacity = "0";
  temporary.style.pointerEvents = "none";
  document.body.append(temporary);
  temporary.select();
  const copied = document.execCommand("copy");
  temporary.remove();
  if (!copied) {
    throw new Error("浏览器拒绝了剪贴板操作");
  }
}

function triggerDownload(blob: Blob, fileName: string): void {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = fileName;
  anchor.hidden = true;
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function downloadDescriptor(descriptor: DownloadDescriptor): void {
  if (descriptor.kind === "zip") {
    triggerDownload(
      buildZipArchive(descriptor.entries, { modifiedAt: getExportDate() }),
      descriptor.fileName,
    );
    return;
  }
  const text = JSON.stringify(descriptor.document, null, 2) + "\n";
  triggerDownload(
    new Blob([text], { type: "application/json;charset=utf-8" }),
    descriptor.fileName,
  );
}

function downloadAll(): void {
  if (!state.accounts.length) {
    return;
  }
  const descriptor = getDownloadDescriptor(state.accounts, state.format, {
    now: getExportDate(),
  });
  downloadDescriptor(descriptor);
  showToast("已生成 " + descriptor.fileName);
}

function downloadSingle(index: number): void {
  const account = state.accounts[index];
  if (!account) {
    return;
  }
  const descriptor = getDownloadDescriptor([account], state.format, {
    now: getExportDate(),
  });
  downloadDescriptor(descriptor);
  showToast("已生成 " + descriptor.fileName);
}

function setFormat(format: string | undefined): void {
  if (format !== "cpa" && format !== "sub2api") {
    return;
  }
  state.format = format;
  state.revealSecrets = false;
  renderAll();
}

for (const button of elements.formatButtons) {
  button.addEventListener("click", () => setFormat(button.dataset.format));
  button.addEventListener("keydown", (event) => {
    const currentIndex = elements.formatButtons.indexOf(button);
    let nextIndex: number | undefined;
    if (event.key === "ArrowLeft" || event.key === "ArrowUp") {
      nextIndex = (currentIndex - 1 + elements.formatButtons.length)
        % elements.formatButtons.length;
    } else if (event.key === "ArrowRight" || event.key === "ArrowDown") {
      nextIndex = (currentIndex + 1) % elements.formatButtons.length;
    } else if (event.key === "Home") {
      nextIndex = 0;
    } else if (event.key === "End") {
      nextIndex = elements.formatButtons.length - 1;
    }
    if (nextIndex === undefined) {
      return;
    }
    event.preventDefault();
    const nextButton = elements.formatButtons[nextIndex];
    setFormat(nextButton.dataset.format);
    nextButton.focus();
  });
}

elements.input.addEventListener("paste", () => {
  window.setTimeout(() => {
    if (elements.input.value.trim()) {
      processPastedInput();
    }
  }, 0);
});
elements.input.addEventListener("keydown", (event) => {
  if ((event.ctrlKey || event.metaKey) && event.key === "Enter") {
    event.preventDefault();
    processPastedInput();
  }
});
elements.clearAll.addEventListener("click", () => {
  elements.input.value = "";
  resetResults();
  setInputStatus("已清空输入和转换结果。");
});
elements.clearResults.addEventListener("click", () => {
  resetResults();
  setInputStatus("已清除转换结果，输入内容仍保留。");
});
elements.pickFiles.addEventListener("click", (event) => {
  event.stopPropagation();
  elements.fileInput.click();
});
elements.pickFolder.addEventListener("click", (event) => {
  event.stopPropagation();
  elements.folderInput.click();
});
elements.fileInput.addEventListener("change", () => {
  if (elements.fileInput.files) {
    void processFiles(elements.fileInput.files);
  }
  elements.fileInput.value = "";
});
elements.folderInput.addEventListener("change", () => {
  if (elements.folderInput.files) {
    void processFiles(elements.folderInput.files);
  }
  elements.folderInput.value = "";
});
for (const eventName of ["dragenter", "dragover"] as const) {
  elements.dropzone.addEventListener(eventName, (event) => {
    event.preventDefault();
    elements.dropzone.classList.add("is-dragging");
  });
}
for (const eventName of ["dragleave", "drop"] as const) {
  elements.dropzone.addEventListener(eventName, (event) => {
    event.preventDefault();
    elements.dropzone.classList.remove("is-dragging");
  });
}
elements.dropzone.addEventListener("drop", (event) => {
  if (event.dataTransfer) {
    void processFiles(event.dataTransfer.files);
  }
});
elements.toggleSecrets.addEventListener("click", () => {
  state.revealSecrets = !state.revealSecrets;
  renderOutput();
});
elements.copyOutput.addEventListener("click", async () => {
  if (!state.accounts.length) {
    return;
  }
  try {
    await copyText(getCurrentOutputText());
    showToast("完整 JSON 已复制");
  } catch (error) {
    showToast(error instanceof Error ? error.message : "复制失败", "error");
  }
});
elements.downloadOutput.addEventListener("click", downloadAll);
elements.accountBody.addEventListener("click", (event) => {
  const target = event.target;
  if (!(target instanceof Element)) {
    return;
  }
  const button = target.closest<HTMLElement>("[data-download-index]");
  if (button?.dataset.downloadIndex) {
    downloadSingle(Number(button.dataset.downloadIndex));
  }
});

renderAll();
