const ui = {
  connected: false,
  rootAvailable: false,
  busy: false,
  checking: false,
  retrying: false,
  lastError: null,
  pollTimer: null,
  rebootCountdownTimer: null,
};

const elements = {};

document.addEventListener("DOMContentLoaded", () => {
  [
    "connectionPill",
    "connectionPillText",
    "connectionBanner",
    "connectionBannerTitle",
    "connectionBannerText",
    "bannerGuideButton",
    "bannerRetryButton",
    "helpButton",
    "rootButton",
    "rootButtonLabel",
    "verifyButton",
    "refreshButton",
    "diagnosticsButton",
    "copyLogsButton",
    "clearLogButton",
    "actionTitle",
    "actionDescription",
    "deviceStatus",
    "buildStatus",
    "rootStatus",
    "magiskStatus",
    "zygiskStatus",
    "vectorStatus",
    "progressPanel",
    "progressText",
    "runSummary",
    "logView",
    "guideModal",
    "guideTitle",
    "guideMessage",
    "guideRetryButton",
    "rebootModal",
    "rebootTitle",
    "rebootCountdown",
    "rebootMessage",
    "rebootCloseButton",
    "toast",
  ].forEach((elementId) => {
    elements[elementId] = document.getElementById(elementId);
  });

  bindEvents();
  window.addEventListener("pywebviewready", initializeApplication);

  if (window.pywebview && window.pywebview.api) {
    initializeApplication();
  }
});

function bindEvents() {
  elements.rootButton.addEventListener("click", startOneClickRoot);
  elements.verifyButton.addEventListener("click", startVerification);
  elements.refreshButton.addEventListener("click", () => checkDevice(false));
  elements.bannerRetryButton.addEventListener("click", retryConnection);
  elements.guideRetryButton.addEventListener("click", retryConnection);
  elements.bannerGuideButton.addEventListener("click", showCurrentGuide);
  elements.helpButton.addEventListener("click", showCurrentGuide);
  elements.diagnosticsButton.addEventListener("click", exportDiagnostics);
  elements.copyLogsButton.addEventListener("click", copyLogs);
  elements.clearLogButton.addEventListener("click", clearLogs);
  elements.rebootCloseButton.addEventListener("click", hideRebootNotice);

  document.querySelectorAll("[data-close-guide]").forEach((button) => {
    button.addEventListener("click", hideGuide);
  });
  document.querySelectorAll("[data-close-reboot]").forEach((button) => {
    button.addEventListener("click", hideRebootNotice);
  });
}

async function initializeApplication() {
  if (ui.pollTimer) {
    return;
  }
  appendLog("正在检测设备...");
  await checkDevice(true);
  ui.pollTimer = window.setInterval(() => {
    if (!ui.busy && !ui.checking && !ui.retrying && !ui.connected) {
      checkDevice(true);
    }
  }, 5000);
}

async function checkDevice(silent, waitForCurrentCheck = false) {
  if (!window.pywebview?.api) {
    return;
  }
  if (ui.checking) {
    if (!waitForCurrentCheck) {
      return;
    }
    while (ui.checking) {
      await delay(100);
    }
  }
  ui.checking = true;
  setConnectionPill("checking", "正在检测设备");
  try {
    const result = await window.pywebview.api.probe_device();
    if (result.ok) {
      handleDeviceConnected(result.device);
      if (!silent) {
        showToast("设备连接正常");
      }
    } else {
      handleDeviceError(result.error, silent);
    }
  } catch (error) {
    handleDeviceError(
      {
        code: "bridge_error",
        title: "程序通信失败",
        message: String(error),
        show_guide: false,
      },
      silent,
    );
  } finally {
    ui.checking = false;
  }
}

function handleDeviceConnected(device) {
  ui.connected = true;
  ui.rootAvailable = Boolean(device.root_available);
  ui.lastError = null;
  elements.connectionBanner.classList.add("hidden");
  setConnectionPill("online", "设备已连接");
  setButtonEnabled(elements.rootButton, !ui.busy);
  setButtonEnabled(elements.verifyButton, !ui.busy && ui.rootAvailable);
  renderDevice(device);

  if (device.root_available) {
    elements.actionTitle.textContent = "Root 已激活";
    elements.actionDescription.textContent =
      "重启后再次点击一键 Root 即可恢复。";
    elements.rootButtonLabel.textContent = "恢复 Root";
  } else {
    elements.actionTitle.textContent = "设备已连接";
    elements.actionDescription.textContent = "连接后自动通过 USB ADB 获取 Root。";
    elements.rootButtonLabel.textContent = "一键 Root";
  }
}

function handleDeviceError(error, silent) {
  ui.connected = false;
  ui.rootAvailable = false;
  ui.lastError = error;
  setConnectionPill("error", error.title || "设备不可用");
  elements.connectionBanner.classList.remove("hidden");
  elements.connectionBannerTitle.textContent = error.title || "设备连接失败";
  elements.connectionBannerText.textContent = error.message || "";
  elements.actionTitle.textContent = "设备未连接";
  elements.actionDescription.textContent = "开启 USB 调试后自动继续。";
  setButtonEnabled(elements.rootButton, false);
  setButtonEnabled(elements.verifyButton, false);
  setMutedStatus("未连接");

  if (!silent) {
    showGuide(error);
  }
}

function renderDevice(device) {
  setStatus(
    elements.deviceStatus,
    `${device.model} · Android ${device.android_release}`,
    "success",
  );
  setStatus(elements.buildStatus, device.display_id, "normal");
  setStatus(
    elements.rootStatus,
    device.root_available ? "临时 Root 已激活" : "当前 boot 未 Root",
    device.root_available ? "success" : "warning",
  );
  setStatus(
    elements.magiskStatus,
    device.magisk_version || "未运行",
    device.magisk_version ? "success" : "warning",
  );
  setStatus(
    elements.zygiskStatus,
    device.zygisk_status === "injected" ? "已注入" : "未运行",
    device.zygisk_status === "injected" ? "success" : "warning",
  );
  setStatus(
    elements.vectorStatus,
    device.vector_version
      ? `${device.vector_version} / API ${device.vector_api || "未知"}`
      : "未运行",
    device.vector_version ? "success" : "warning",
  );
}

function setMutedStatus(value) {
  [
    elements.deviceStatus,
    elements.buildStatus,
    elements.rootStatus,
    elements.magiskStatus,
    elements.zygiskStatus,
    elements.vectorStatus,
  ].forEach((element) => setStatus(element, value, "muted"));
}

function setStatus(element, text, variant) {
  element.textContent = text;
  element.className = `status-value ${variant === "normal" ? "" : variant}`.trim();
}

function setConnectionPill(state, text) {
  elements.connectionPill.className = "connection-pill";
  if (state === "online") {
    elements.connectionPill.classList.add("is-online");
  } else if (state === "error") {
    elements.connectionPill.classList.add("is-error");
  } else {
    elements.connectionPill.classList.add("is-checking");
  }
  elements.connectionPillText.textContent = text;
}

async function startOneClickRoot() {
  if (!ui.connected) {
    showCurrentGuide();
    return;
  }
  clearLogs();
  setBusy(true);
  elements.actionTitle.textContent = "正在获取 Root";
  elements.actionDescription.textContent =
    "正在通过 ADB 提权，请保持 USB 数据线连接。";
  elements.runSummary.textContent = "正在执行";
  try {
    const result = await window.pywebview.api.start_one_click();
    if (!result.started) {
      throw new Error(result.message || "操作未能启动");
    }
  } catch (error) {
    handleOperationError({
      title: "无法开始操作",
      message: String(error),
    });
  }
}

async function startVerification() {
  if (!ui.connected) {
    showCurrentGuide();
    return;
  }
  setBusy(true);
  elements.runSummary.textContent = "正在验证";
  try {
    const result = await window.pywebview.api.start_verification();
    if (!result.started) {
      throw new Error(result.message || "验证未能启动");
    }
  } catch (error) {
    handleOperationError({
      title: "无法开始验证",
      message: String(error),
    });
  }
}

async function retryConnection() {
  if (ui.retrying) {
    return;
  }
  ui.retrying = true;
  hideGuide();
  setConnectionPill("checking", "正在重新连接");
  setButtonEnabled(elements.bannerRetryButton, false);
  setButtonEnabled(elements.guideRetryButton, false);
  appendLog("正在刷新 ADB 设备状态，不会重启 ADB 服务...");
  try {
    if (!window.pywebview?.api) {
      throw new Error("图形界面通信尚未就绪，请重新打开程序。");
    }
    await checkDevice(false, true);
  } catch (error) {
    handleOperationError({
      title: "ADB 重新连接失败",
      message: String(error.message || error),
    });
    showCurrentGuide();
  } finally {
    ui.retrying = false;
    setButtonEnabled(elements.bannerRetryButton, true);
    setButtonEnabled(elements.guideRetryButton, true);
  }
}

function delay(milliseconds) {
  return new Promise((resolve) => window.setTimeout(resolve, milliseconds));
}

async function exportDiagnostics() {
  if (!ui.connected) {
    showCurrentGuide();
    return;
  }
  try {
    const result = await window.pywebview.api.save_diagnostics();
    if (result.ok) {
      showToast(`诊断包已保存：${result.path}`);
    } else if (!result.cancelled) {
      handleOperationError(result.error);
    }
  } catch (error) {
    handleOperationError({
      title: "诊断导出失败",
      message: String(error),
    });
  }
}

function showCurrentGuide() {
  showGuide(
    ui.lastError || {
      title: "连接 HarmonyOS 4.2 平板",
      message: "开启 USB 调试并连接数据线。",
    },
  );
}

function showGuide(error) {
  elements.guideTitle.textContent = error.title || "请检查设备连接";
  elements.guideMessage.textContent =
    error.message || "按下面步骤开启 USB 调试。";
  elements.guideModal.classList.remove("hidden");
  syncBodyScrollLock();
}

function hideGuide() {
  elements.guideModal.classList.add("hidden");
  syncBodyScrollLock();
}

function showRebootNotice(data) {
  const delaySeconds = Math.max(0, Number(data.delay_seconds) || 0);
  const deadline = Date.now() + delaySeconds * 1000;
  elements.rebootTitle.textContent = data.title || "Root 环境已启动";
  elements.rebootMessage.textContent =
    data.message || "系统框架即将软重启，请等待平板恢复。";
  elements.rebootCountdown.textContent = `${delaySeconds} 秒后软重启`;
  elements.rebootModal.querySelector(".reboot-notice").classList.remove("is-error");
  elements.rebootModal.classList.remove("hidden");
  syncBodyScrollLock();

  window.clearInterval(ui.rebootCountdownTimer);
  const updateCountdown = () => {
    const remainingSeconds = Math.max(
      0,
      Math.ceil((deadline - Date.now()) / 1000),
    );
    if (remainingSeconds > 0) {
      elements.rebootCountdown.textContent = `${remainingSeconds} 秒后软重启`;
      return;
    }
    window.clearInterval(ui.rebootCountdownTimer);
    ui.rebootCountdownTimer = null;
    elements.rebootCountdown.textContent = "正在软重启系统框架";
    elements.rebootMessage.textContent = "平板会短暂黑屏，恢复后请重新连接并验证状态。";
  };
  updateCountdown();
  if (delaySeconds > 0) {
    ui.rebootCountdownTimer = window.setInterval(updateCountdown, 250);
  }
}

function hideRebootNotice() {
  window.clearInterval(ui.rebootCountdownTimer);
  ui.rebootCountdownTimer = null;
  elements.rebootModal.classList.add("hidden");
  syncBodyScrollLock();
}

function showSoftRebootResult(data) {
  if (!elements.rebootModal.classList.contains("hidden")) {
    const notice = elements.rebootModal.querySelector(".reboot-notice");
    if (data.ok) {
      elements.rebootCountdown.textContent = "正在软重启系统框架";
      elements.rebootMessage.textContent =
        "平板会短暂黑屏，恢复后请重新连接并验证状态。";
    } else {
      notice.classList.add("is-error");
      elements.rebootCountdown.textContent = "软重启未执行";
      elements.rebootMessage.textContent =
        data.message || "请稍后从平板 Magisk 或 DBY2 RootKit 中手动软重启。";
    }
  }
  if (!data.ok) {
    showToast(data.message || "软重启未执行", true);
  }
}

function syncBodyScrollLock() {
  const hasVisibleModal =
    !elements.guideModal.classList.contains("hidden") ||
    !elements.rebootModal.classList.contains("hidden");
  document.body.style.overflow = hasVisibleModal ? "hidden" : "";
}

function setBusy(busy) {
  ui.busy = busy;
  elements.progressPanel.classList.toggle("hidden", !busy);
  elements.progressText.textContent = busy
    ? "正在执行，请勿断开数据线"
    : "";
  setButtonEnabled(elements.refreshButton, !busy);
  setButtonEnabled(elements.helpButton, !busy);
  setButtonEnabled(elements.diagnosticsButton, !busy);
  setButtonEnabled(elements.rootButton, !busy && ui.connected);
  setButtonEnabled(
    elements.verifyButton,
    !busy && ui.connected && ui.rootAvailable,
  );
}

function setButtonEnabled(button, enabled) {
  button.disabled = !enabled;
}

function appendLog(message, level = "info") {
  const empty = elements.logView.querySelector(".log-empty");
  if (empty) {
    empty.remove();
  }
  const now = new Date();
  const time = now.toLocaleTimeString("zh-CN", { hour12: false });
  const cleaned = String(message).replace(/\r/g, "").trim();
  if (!cleaned) {
    return;
  }
  for (const line of cleaned.split("\n")) {
    const row = document.createElement("div");
    row.className = `log-line ${level === "error" ? "error" : ""}`;
    const timeElement = document.createElement("span");
    timeElement.className = "log-time";
    timeElement.textContent = `[${time}]`;
    const textElement = document.createElement("span");
    textElement.className = "log-text";
    textElement.textContent = line;
    row.append(timeElement, textElement);
    elements.logView.append(row);
  }
  elements.logView.scrollTop = elements.logView.scrollHeight;
}

function clearLogs() {
  elements.logView.innerHTML = '<div class="log-empty">等待操作</div>';
}

async function copyLogs() {
  const logText = Array.from(
    elements.logView.querySelectorAll(".log-line"),
  )
    .map((row) => {
      const time = row.querySelector(".log-time")?.textContent || "";
      const text = row.querySelector(".log-text")?.textContent || "";
      return `${time}${text}`;
    })
    .join("\n");

  if (!logText) {
    showToast("暂无可复制的执行记录", true);
    return;
  }

  try {
    await writeClipboardText(logText);
    showToast("执行记录已复制");
  } catch (error) {
    showToast(`复制失败：${String(error.message || error)}`, true);
  }
}

async function writeClipboardText(text) {
  if (navigator.clipboard?.writeText) {
    try {
      await navigator.clipboard.writeText(text);
      return;
    } catch (_) {
      // Fall through to the selection-based path for restricted WebView origins.
    }
  }

  const textarea = document.createElement("textarea");
  textarea.value = text;
  textarea.setAttribute("readonly", "");
  textarea.style.position = "fixed";
  textarea.style.opacity = "0";
  document.body.append(textarea);
  textarea.focus();
  textarea.select();
  const copied = document.execCommand("copy");
  textarea.remove();
  if (!copied) {
    throw new Error("系统剪贴板不可用");
  }
}

function handleOperationError(error) {
  const message = error?.message || String(error);
  appendLog(message, "error");
  elements.runSummary.textContent = "操作失败";
  elements.actionTitle.textContent = error?.title || "操作未完成";
  elements.actionDescription.textContent = "请按提示处理后重试。";
  showToast(message, true);
  if (error?.show_guide) {
    showGuide(error);
  }
}

function showToast(message, isError = false) {
  elements.toast.textContent = message;
  elements.toast.className = `toast${isError ? " error" : ""}`;
  window.clearTimeout(showToast.timer);
  showToast.timer = window.setTimeout(() => {
    elements.toast.classList.add("hidden");
  }, 5000);
}

window.DBY2_UI = {
  onEvent(event) {
    if (!event || !event.type) {
      return;
    }
    const data = event.data || {};
    if (event.type === "log") {
      appendLog(data.message || "", data.level || "info");
    } else if (event.type === "busy") {
      setBusy(Boolean(data.busy));
    } else if (event.type === "device") {
      handleDeviceConnected(data);
    } else if (event.type === "soft_reboot") {
      showRebootNotice(data);
    } else if (event.type === "soft_reboot_result") {
      showSoftRebootResult(data);
    } else if (event.type === "summary") {
      elements.runSummary.textContent = data.text || "正在执行";
    } else if (event.type === "progress") {
      elements.progressText.textContent = data.text || "正在执行";
    } else if (event.type === "error") {
      handleOperationError(data);
    } else if (event.type === "success") {
      elements.runSummary.textContent = data.text || "操作完成";
      showToast(data.text || "操作完成");
    }
  },
};
