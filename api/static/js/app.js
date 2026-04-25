const sidebar = document.getElementById("sidebar");
const sidebarBrand = document.getElementById("sidebarBrand");
const sidebarMobileToggle = document.getElementById("sidebarMobileToggle");

const serverForm = document.getElementById("server-form");
const runForm = document.getElementById("run-form");
const scheduleForm = document.getElementById("schedule-form");
const jobsBody = document.getElementById("jobs-body");
const schedulesBody = document.getElementById("schedules-body");
const serverStatusBody = document.getElementById("server-status-body");
const refreshAllServerStatusBtn = document.getElementById("refresh_all_server_status_btn");
const serverStatusLastUpdated = document.getElementById("server_status_last_updated");
const serverStatusAutoCheckToggle = document.getElementById("server_status_auto_check_toggle");
const serverStatusAutoCheckInterval = document.getElementById("server_status_auto_check_interval");
const latestLog = document.getElementById("latest-log");
const selectedJobLabel = document.getElementById("selected-job-label");
const scheduleFormCard = document.getElementById("scheduleFormCard");
const scheduledUpdatesCard = document.getElementById("scheduledUpdatesCard");
const createScheduleBtn = document.getElementById("create_schedule_btn");
const createScheduleBtnEmpty = document.getElementById("create_schedule_btn_empty");
const cancelScheduleBtn = document.getElementById("cancel_schedule_btn");
const scheduleFormCloseBtn = document.getElementById("schedule_form_close_btn");
const scheduleFormTitle = document.getElementById("schedule-form-title");
const scheduleFormIcon = document.getElementById("schedule-form-icon");
const saveScheduleBtn = document.getElementById("save_schedule_btn");
const scheduleIdInput = document.getElementById("schedule_id");
const autoDisableOnFailuresInput = document.getElementById("auto_disable_on_failures");
const failureThresholdInput = document.getElementById("failure_threshold");
const failureThresholdGroup = document.getElementById("failure_threshold_group");
const authMethod = document.getElementById("auth_method");
const passwordLabel = document.getElementById("password_label");
const keyLabel = document.getElementById("key_label");
const cancelEditBtn = document.getElementById("cancel_edit_btn");
const saveServerBtn = document.getElementById("save_server_btn");
const testConnectionBtn = document.getElementById("test_connection_btn");
const serverFormTitle = document.getElementById("server-form-title");
const serverFormCard = document.getElementById("serverFormCard");
const serversListCard = document.getElementById("serversListCard");
const createServerBtn = document.getElementById("create_server_btn");
const createServerBtnEmpty = document.getElementById("create_server_btn_empty");
const serverFormCloseBtn = document.getElementById("server_form_close_btn");
const userForm = document.getElementById("user-form");
const userFormTitle = document.getElementById("user-form-title");
const userFormIcon = document.getElementById("user-form-icon");
const userSubmitBtn = document.getElementById("user_submit_btn");
const userCancelBtn = document.getElementById("user_cancel_btn");
const userFormCloseBtn = document.getElementById("user_form_close_btn");
const userFormCard = document.getElementById("userFormCard");
const usersListCard = document.getElementById("usersListCard");
const createUserBtn = document.getElementById("create_user_btn");
const userPasswordInput = document.getElementById("user_password");
const userConfirmPasswordInput = document.getElementById("user_confirm_password");
const currentUserId = userForm?.dataset.currentUserId || "";
const appDateFormat = document.body?.dataset.dateFormat || "iso-24";
const appTimezone = document.body?.dataset.timezone || "UTC";
const deepLinkedJobId = (() => {
  try {
    const raw = new URLSearchParams(window.location.search).get("job_id");
    const parsed = Number(raw);
    return Number.isInteger(parsed) && parsed > 0 ? parsed : null;
  } catch (error) {
    return null;
  }
})();
let pendingAutoOpenJobId = deepLinkedJobId;
let selectedJobId = null;
let syncJobsLiveRefreshState = null;
let serverStatusAutoCheckTimerId = null;
let serverStatusAutoCheckInFlight = false;
const SERVER_STATUS_AUTO_CHECK_ENABLED_KEY = "serverStatusAutoCheckEnabled";
const SERVER_STATUS_AUTO_CHECK_INTERVAL_KEY = "serverStatusAutoCheckInterval";

function intervalSecondsToServerStatusCron(intervalSeconds) {
  const parsed = Number(intervalSeconds);
  if (!Number.isFinite(parsed)) {
    return "*/1 * * * *";
  }
  const normalized = Math.max(60, Math.trunc(parsed));
  if (normalized % 604800 === 0) {
    return "0 0 * * 0";
  }
  if (normalized % 86400 === 0) {
    return "0 0 * * *";
  }
  if (normalized % 3600 === 0) {
    const hourStep = Math.max(1, Math.trunc(normalized / 3600));
    if (hourStep <= 23) {
      return `0 */${hourStep} * * *`;
    }
  }
  if (normalized % 60 === 0) {
    const minuteStep = Math.max(1, Math.trunc(normalized / 60));
    if (minuteStep <= 59) {
      return `*/${minuteStep} * * * *`;
    }
  }
  return "*/1 * * * *";
}

function normalizeCronWhitespace(rawValue) {
  return String(rawValue || "").trim().replace(/\s+/g, " ");
}

function expandCronToken(token, min, max) {
  const values = new Set();
  const segment = String(token || "").trim();
  if (!segment) {
    return null;
  }

  const [rangePartRaw, stepPartRaw] = segment.split("/");
  if (segment.split("/").length > 2) {
    return null;
  }

  let step = 1;
  if (stepPartRaw != null) {
    step = Number(stepPartRaw);
    if (!Number.isInteger(step) || step < 1) {
      return null;
    }
  }

  let start = min;
  let end = max;
  const rangePart = rangePartRaw == null ? segment : rangePartRaw;

  if (rangePart !== "*") {
    if (rangePart.includes("-")) {
      const [startRaw, endRaw] = rangePart.split("-");
      if (rangePart.split("-").length !== 2) {
        return null;
      }
      start = Number(startRaw);
      end = Number(endRaw);
      if (!Number.isInteger(start) || !Number.isInteger(end) || start > end) {
        return null;
      }
    } else {
      start = Number(rangePart);
      end = start;
      if (!Number.isInteger(start)) {
        return null;
      }
    }
  }

  if (start < min || end > max) {
    return null;
  }

  for (let value = start; value <= end; value += step) {
    values.add(value);
  }
  return values;
}

function parseCronField(fieldValue, min, max) {
  const tokens = String(fieldValue || "").split(",").map((t) => t.trim()).filter(Boolean);
  if (!tokens.length) {
    return null;
  }
  const result = new Set();
  for (const token of tokens) {
    const expanded = expandCronToken(token, min, max);
    if (!expanded) {
      return null;
    }
    for (const value of expanded) {
      result.add(value);
    }
  }
  return result;
}

function parseServerStatusCronExpression(cronExpression) {
  const normalized = normalizeCronWhitespace(cronExpression);
  const parts = normalized.split(" ");
  if (parts.length !== 5) {
    return null;
  }

  const parsed = {
    minute: parseCronField(parts[0], 0, 59),
    hour: parseCronField(parts[1], 0, 23),
    dayOfMonth: parseCronField(parts[2], 1, 31),
    month: parseCronField(parts[3], 1, 12),
    dayOfWeek: parseCronField(parts[4], 0, 6),
  };

  if (!parsed.minute || !parsed.hour || !parsed.dayOfMonth || !parsed.month || !parsed.dayOfWeek) {
    return null;
  }

  return { normalized, parsed };
}

function cronMatchesDate(parsedCron, date) {
  return parsedCron.minute.has(date.getMinutes())
    && parsedCron.hour.has(date.getHours())
    && parsedCron.dayOfMonth.has(date.getDate())
    && parsedCron.month.has(date.getMonth() + 1)
    && parsedCron.dayOfWeek.has(date.getDay());
}

function nextServerStatusCronRun(parsedCron, fromDate = new Date()) {
  const probe = new Date(fromDate.getTime());
  probe.setSeconds(0, 0);
  probe.setMinutes(probe.getMinutes() + 1);

  // Search up to ~2 years of minute slots.
  for (let i = 0; i < 1051200; i += 1) {
    if (cronMatchesDate(parsedCron, probe)) {
      return new Date(probe.getTime());
    }
    probe.setMinutes(probe.getMinutes() + 1);
  }
  return null;
}

function serverStatusCronToIntervalSeconds(cronExpression) {
  const parsed = parseServerStatusCronExpression(cronExpression);
  if (!parsed) {
    return null;
  }
  const firstRun = nextServerStatusCronRun(parsed.parsed, new Date());
  if (!firstRun) {
    return null;
  }
  const secondRun = nextServerStatusCronRun(parsed.parsed, new Date(firstRun.getTime()));
  if (!secondRun) {
    return null;
  }
  return Math.max(60, Math.round((secondRun.getTime() - firstRun.getTime()) / 1000));
}

function normalizeServerStatusAutoCheckIntervalValue(rawValue) {
  if (rawValue == null) {
    return null;
  }
  const raw = String(rawValue).trim();
  if (!raw) {
    return null;
  }
  const asNumber = Number(raw);
  if (Number.isFinite(asNumber)) {
    return intervalSecondsToServerStatusCron(asNumber);
  }
  const parsed = parseServerStatusCronExpression(raw);
  return parsed ? parsed.normalized : null;
}

function getLocalServerStatusPreferences() {
  try {
    return {
      enabled: localStorage.getItem(SERVER_STATUS_AUTO_CHECK_ENABLED_KEY) === "true",
      interval: localStorage.getItem(SERVER_STATUS_AUTO_CHECK_INTERVAL_KEY),
    };
  } catch (error) {
    return { enabled: false, interval: null };
  }
}

function setLocalServerStatusPreferences(enabled, interval) {
  try {
    localStorage.setItem(SERVER_STATUS_AUTO_CHECK_ENABLED_KEY, String(Boolean(enabled)));
    if (interval != null) {
      localStorage.setItem(SERVER_STATUS_AUTO_CHECK_INTERVAL_KEY, String(interval));
    }
  } catch (error) {
    // Ignore storage errors (private mode / restricted storage)
  }
}

async function persistServerStatusPreferences(enabled, interval, { showFeedback = true } = {}) {
  let normalizedInterval = normalizeServerStatusAutoCheckIntervalValue(interval) || "*/1 * * * *";
  if (!enabled && !normalizeServerStatusAutoCheckIntervalValue(interval)) {
    normalizedInterval = "*/1 * * * *";
  }
  const intervalSeconds = serverStatusCronToIntervalSeconds(normalizedInterval);
  if (!intervalSeconds) {
    if (showFeedback) {
      notify("Invalid cron expression. Use 5 fields like */5 * * * *.", "error");
    }
    return;
  }
  setLocalServerStatusPreferences(enabled, normalizedInterval);
  try {
    const response = await fetch(
      `/api/server-status/preferences?enabled=${encodeURIComponent(String(Boolean(enabled)))}&interval_seconds=${encodeURIComponent(String(intervalSeconds))}`,
      { method: "POST" }
    );
    if (!response.ok) {
      throw new Error("Server preference save failed");
    }
    if (showFeedback) {
      notify("Auto-check preference saved.", "success");
    }
  } catch (error) {
    // Keep local fallback if server persistence is temporarily unavailable.
    if (showFeedback) {
      notify("Saved locally. Server sync failed; retrying on next change.", "warning");
    }
  }
}

async function loadServerStatusPreferences() {
  if (!serverStatusAutoCheckToggle || !serverStatusAutoCheckInterval) {
    return;
  }

  const localPrefs = getLocalServerStatusPreferences();
  const normalizedLocalInterval = normalizeServerStatusAutoCheckIntervalValue(localPrefs.interval);
  if (normalizedLocalInterval) {
    serverStatusAutoCheckInterval.value = normalizedLocalInterval;
  }
  serverStatusAutoCheckToggle.checked = Boolean(localPrefs.enabled);

  try {
    const response = await fetch("/api/server-status/preferences");
    if (!response.ok) {
      applyServerStatusAutoCheckState();
      return;
    }
    const data = await response.json();
    const intervalValue = intervalSecondsToServerStatusCron(data.interval_seconds);
    serverStatusAutoCheckInterval.value = intervalValue;
    serverStatusAutoCheckToggle.checked = data.enabled === true;
    setLocalServerStatusPreferences(serverStatusAutoCheckToggle.checked, serverStatusAutoCheckInterval.value);
  } catch (error) {
    // Keep local fallback if preferences endpoint is unreachable.
  }

  applyServerStatusAutoCheckState();
}

function notify(message, type = "info") {
  if (typeof window.showToast === "function") {
    window.showToast(message, type);
    return;
  }
  window.alert(message);
}

function clearScheduleAptExtraSteps() {
  ["full_upgrade", "fix_dpkg", "fix_broken", "autoremove", "clean"].forEach((step) => {
    const el = document.getElementById(`sched_apt_step_${step}`);
    if (el instanceof HTMLInputElement) {
      el.checked = false;
    }
  });
  const schedAlertOnly = document.getElementById("sched_alert_only");
  if (schedAlertOnly instanceof HTMLInputElement) {
    schedAlertOnly.checked = false;
  }
}

function toggleScheduleFailureThreshold() {
  const enabled = Boolean(autoDisableOnFailuresInput?.checked);
  if (failureThresholdGroup) {
    failureThresholdGroup.classList.toggle("hidden", !enabled);
  }
  if (failureThresholdInput) {
    failureThresholdInput.required = enabled;
    if (!enabled && !failureThresholdInput.value) {
      failureThresholdInput.value = "3";
    }
  }
}

if (sidebar && localStorage.getItem("sidebarCollapsed") === "true") {
  sidebar.classList.add("collapsed");
}

sidebarBrand?.addEventListener("click", () => {
  if (!sidebar) {
    return;
  }
  sidebar.classList.toggle("collapsed");
  localStorage.setItem("sidebarCollapsed", String(sidebar.classList.contains("collapsed")));
});

sidebarMobileToggle?.addEventListener("click", () => {
  sidebar?.classList.toggle("mobile-open");
});

function toggleAuthFields() {
  if (!authMethod || !passwordLabel || !keyLabel) {
    return;
  }

  const isPassword = authMethod.value === "password";
  const serverIdInput = serverForm?.querySelector('input[name="server_id"]');
  const isEditingServer = Boolean(serverIdInput?.value);
  const passwordInput = passwordLabel.querySelector('input[name="password"]');
  const keySelect = keyLabel.querySelector('select[name="ssh_key_id"]');

  passwordLabel.classList.toggle("hidden", !isPassword);
  keyLabel.classList.toggle("hidden", isPassword);

  if (passwordInput) {
    passwordInput.required = isPassword && !isEditingServer;
    passwordInput.placeholder = isPassword && isEditingServer ? "Leave blank to keep current password" : "";
    if (!isPassword) {
      passwordInput.value = "";
    }
  }

  if (keySelect) {
    keySelect.disabled = isPassword;
    keySelect.required = !isPassword;
    if (isPassword) {
      keySelect.value = "";
    }
  }
}

authMethod?.addEventListener("change", toggleAuthFields);
if (authMethod && passwordLabel && keyLabel) {
  toggleAuthFields();
}

testConnectionBtn?.addEventListener("click", async () => {
  if (!serverForm) {
    return;
  }

  const formData = new FormData(serverForm);
  const payload = {
    host: (formData.get("host") || "").toString().trim(),
    port: Number(formData.get("port") || 22),
    username: (formData.get("username") || "").toString().trim(),
    auth_method: (formData.get("auth_method") || "key").toString(),
    password: (formData.get("password") || "").toString() || null,
    ssh_key_id: formData.get("ssh_key_id") ? Number(formData.get("ssh_key_id")) : null,
    server_id: formData.get("server_id") ? Number(formData.get("server_id")) : null,
  };

  if (!payload.host || !payload.username) {
    notify("Host and username are required before testing connection.", "error");
    return;
  }

  if (payload.auth_method === "password" && !payload.password && !payload.server_id) {
    notify("Enter an SSH password before testing password authentication.", "error");
    return;
  }

  if (payload.auth_method === "key" && !payload.ssh_key_id) {
    notify("Select an SSH key before testing key authentication.", "error");
    return;
  }

  const originalButtonHtml = testConnectionBtn.innerHTML;
  testConnectionBtn.disabled = true;
  testConnectionBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i><span>Testing...</span>';

  try {
    const response = await fetch("/api/servers/test-connection", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    const responseText = await response.text();
    let data;
    try {
      data = JSON.parse(responseText);
    } catch {
      notify(`Server error (${response.status}): ${response.statusText}`, "error");
      return;
    }

    if (!response.ok) {
      notify(data.detail || "Connection test failed.", "error");
      return;
    }

    notify(data.message || "Connection successful.", "success");
  } catch (error) {
    notify(`Connection test failed: ${error.message}`, "error");
  } finally {
    testConnectionBtn.disabled = false;
    testConnectionBtn.innerHTML = originalButtonHtml;
  }
});

serverForm?.addEventListener("submit", async (event) => {
  event.preventDefault();
  const formData = new FormData(serverForm);
  const serverId = formData.get("server_id");

  const payload = {
    name: formData.get("name"),
    host: formData.get("host"),
    port: Number(formData.get("port")),
    username: formData.get("username"),
    auth_method: formData.get("auth_method"),
    password: formData.get("password") || null,
    ssh_key_id: formData.get("ssh_key_id") ? Number(formData.get("ssh_key_id")) : null,
    sudo_password: formData.get("sudo_password") || null,
    alert_cpu_threshold: Number(formData.get("alert_cpu_threshold")),
    alert_ram_threshold: Number(formData.get("alert_ram_threshold")),
    alert_storage_threshold: Number(formData.get("alert_storage_threshold")),
    alert_load_avg_threshold: Number(formData.get("alert_load_avg_threshold")),
    alert_load_avg_5_threshold: Number(formData.get("alert_load_avg_5_threshold")),
    alert_load_avg_15_threshold: Number(formData.get("alert_load_avg_15_threshold")),
  };

  if (!payload.password) {
    delete payload.password;
  }

  const endpoint = serverId ? `/api/servers/${serverId}` : "/api/servers";
  const method = serverId ? "PUT" : "POST";

  const response = await fetch(endpoint, {
    method,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    const error = await response.json();
    notify(error.detail || "Failed to save server", "error");
    return;
  }

  serverForm.reset();
  const serverIdInput = serverForm.querySelector('input[name="server_id"]');
  if (serverIdInput) {
    serverIdInput.value = "";
  }
  if (saveServerBtn) {
    saveServerBtn.innerHTML = '<i class="fas fa-save"></i><span>Save Server</span>';
  }
  if (typeof window.showToastAfterReload === "function") {
    window.showToastAfterReload(serverId ? "Server updated successfully." : "Server created successfully.", "success");
  }
  window.location.reload();
});

function setServerFormVisibility(showForm) {
  if (!serverFormCard || !serversListCard) {
    return;
  }
  serverFormCard.classList.toggle("hidden", !showForm);
  serversListCard.classList.toggle("hidden", showForm);
}

function resetServerFormToCreateMode() {
  if (!serverForm) {
    return;
  }
  serverForm.reset();
  const serverIdInput = serverForm.querySelector('input[name="server_id"]');
  if (serverIdInput) {
    serverIdInput.value = "";
  }
  if (serverFormTitle) {
    serverFormTitle.textContent = "Add Server";
  }
  if (saveServerBtn) {
    saveServerBtn.innerHTML = '<i class="fas fa-save"></i><span>Save Server</span>';
  }
  const cpuThresholdField = serverForm.querySelector('[name="alert_cpu_threshold"]');
  const ramThresholdField = serverForm.querySelector('[name="alert_ram_threshold"]');
  const storageThresholdField = serverForm.querySelector('[name="alert_storage_threshold"]');
  const loadThresholdField = serverForm.querySelector('[name="alert_load_avg_threshold"]');
  const load5ThresholdField = serverForm.querySelector('[name="alert_load_avg_5_threshold"]');
  const load15ThresholdField = serverForm.querySelector('[name="alert_load_avg_15_threshold"]');
  if (cpuThresholdField) {
    cpuThresholdField.value = "90";
  }
  if (ramThresholdField) {
    ramThresholdField.value = "90";
  }
  if (storageThresholdField) {
    storageThresholdField.value = "90";
  }
  if (loadThresholdField) {
    loadThresholdField.value = "0";
  }
  if (load5ThresholdField) {
    load5ThresholdField.value = "0";
  }
  if (load15ThresholdField) {
    load15ThresholdField.value = "0";
  }
  toggleAuthFields();
}

function showCreateServerForm() {
  resetServerFormToCreateMode();
  setServerFormVisibility(true);
  window.scrollTo({ top: 0, behavior: "smooth" });
}

function hideServerFormAndReset() {
  resetServerFormToCreateMode();
  setServerFormVisibility(false);
}

createServerBtn?.addEventListener("click", showCreateServerForm);
createServerBtnEmpty?.addEventListener("click", showCreateServerForm);
serverFormCloseBtn?.addEventListener("click", hideServerFormAndReset);

document.querySelectorAll("[data-edit-server]").forEach((button) => {
  button.addEventListener("click", () => {
    const row = button.closest("tr");
    if (!row || !serverForm) {
      return;
    }

    const normalizeNumericInputValue = (value, fallback = "0") => {
      const numeric = Number(value);
      if (!Number.isFinite(numeric)) {
        return fallback;
      }
      return Number.isInteger(numeric) ? String(Math.trunc(numeric)) : String(numeric);
    };

    const setField = (name, value) => {
      const field = serverForm.querySelector(`[name="${name}"]`);
      if (field) {
        field.value = value || "";
      }
    };

    setField("server_id", row.dataset.serverId);
    setField("name", row.dataset.serverName);
    setField("host", row.dataset.serverHost);
    setField("port", row.dataset.serverPort);
    setField("username", row.dataset.serverUsername);
    setField("auth_method", row.dataset.serverAuth);
    setField("ssh_key_id", row.dataset.serverSshKeyId || "");
    setField("sudo_password", "");
    setField("password", "");
    setField("alert_cpu_threshold", row.dataset.serverAlertCpuThreshold || "90");
    setField("alert_ram_threshold", row.dataset.serverAlertRamThreshold || "90");
    setField("alert_storage_threshold", row.dataset.serverAlertStorageThreshold || "90");
    setField("alert_load_avg_threshold", normalizeNumericInputValue(row.dataset.serverAlertLoadAvgThreshold, "0"));
    setField("alert_load_avg_5_threshold", normalizeNumericInputValue(row.dataset.serverAlertLoadAvg5Threshold, "0"));
    setField("alert_load_avg_15_threshold", normalizeNumericInputValue(row.dataset.serverAlertLoadAvg15Threshold, "0"));

    toggleAuthFields();

    if (saveServerBtn) {
      saveServerBtn.innerHTML = '<i class="fas fa-pen"></i><span>Update Server</span>';
    }
    if (serverFormTitle) {
      serverFormTitle.textContent = "Edit Server";
    }
    setServerFormVisibility(true);
    serverForm.scrollIntoView({ behavior: "smooth", block: "center" });
  });
});

cancelEditBtn?.addEventListener("click", hideServerFormAndReset);

if (serverForm && serverFormCard && serversListCard) {
  setServerFormVisibility(false);
  serverFormCard.classList.add("visible");
  serversListCard.classList.add("visible");
}

function setUserFormMode(editing) {
  if (!userForm || !userSubmitBtn || !userCancelBtn || !userPasswordInput || !userConfirmPasswordInput || !userFormTitle) {
    return;
  }

  if (editing) {
    userFormTitle.textContent = "Edit User";
    if (userFormIcon) {
      userFormIcon.className = "fas fa-user-edit";
    }
    userSubmitBtn.innerHTML = '<i class="fas fa-save"></i><span>Save Changes</span>';
    userCancelBtn.classList.remove("hidden");
    userPasswordInput.required = false;
    userConfirmPasswordInput.required = false;
    userPasswordInput.placeholder = "Leave blank to keep current password";
    userConfirmPasswordInput.placeholder = "Repeat new password";
  } else {
    userFormTitle.textContent = "Create New User";
    if (userFormIcon) {
      userFormIcon.className = "fas fa-user-plus";
    }
    userSubmitBtn.innerHTML = '<i class="fas fa-user-plus"></i><span>Create User</span>';
    userCancelBtn.classList.add("hidden");
    userPasswordInput.required = true;
    userConfirmPasswordInput.required = true;
    userPasswordInput.placeholder = "";
    userConfirmPasswordInput.placeholder = "";
  }
}

function setUserFormVisibility(showForm) {
  if (!userFormCard || !usersListCard) {
    return;
  }

  userFormCard.classList.toggle("hidden", !showForm);
  usersListCard.classList.toggle("hidden", showForm);
}

function showCreateUserForm() {
  if (!userForm) {
    return;
  }

  userForm.reset();
  userForm.setAttribute("action", "/users/create");
  setUserFormMode(false);
  applySelfDisableGuard(null);
  setUserFormVisibility(true);
  window.scrollTo({ top: 0, behavior: "smooth" });
}

window.showCreateUserForm = showCreateUserForm;

function setUserFieldValue(name, value) {
  if (!userForm) {
    return;
  }
  const field = userForm.querySelector(`[name="${name}"]`);
  if (!field) {
    return;
  }

  if (field instanceof HTMLInputElement && field.type === "checkbox") {
    field.checked = value === true || value === "true";
    return;
  }

  field.value = value || "";
}

function applySelfDisableGuard(editingUserId) {
  if (!userForm) {
    return;
  }

  const enabledField = userForm.querySelector('input[name="enabled"]');
  const enabledSelectField = userForm.querySelector('select[name="enabled"]');
  const targetField = enabledField || enabledSelectField;
  if (!(targetField instanceof HTMLInputElement) && !(targetField instanceof HTMLSelectElement)) {
    return;
  }

  const isSelfEdit = Boolean(currentUserId) && String(editingUserId || "") === String(currentUserId);
  targetField.disabled = isSelfEdit;

  if (isSelfEdit) {
    if (targetField instanceof HTMLInputElement) {
      targetField.checked = true;
    } else {
      targetField.value = "true";
    }
    targetField.title = "You cannot disable your own account.";
  } else {
    targetField.title = "";
  }
}

document.querySelectorAll("[data-edit-user]").forEach((button) => {
  button.addEventListener("click", () => {
    if (!userForm) {
      return;
    }

    const row = button.closest("tr");
    if (!row) {
      return;
    }

    const userId = row.dataset.userId;
    if (!userId) {
      return;
    }

    userForm.setAttribute("action", `/users/${userId}/update`);
    setUserFormMode(true);
    setUserFieldValue("username", row.dataset.userUsername || "");
    setUserFieldValue("first_name", row.dataset.userFirstName || "");
    setUserFieldValue("last_name", row.dataset.userLastName || "");
    setUserFieldValue("email", row.dataset.userEmail || "");
    setUserFieldValue("is_admin", row.dataset.userIsAdmin || "false");
    setUserFieldValue("enabled", row.dataset.userEnabled || "false");
    setUserFieldValue("password", "");
    setUserFieldValue("confirm_password", "");
    applySelfDisableGuard(userId);
    setUserFormVisibility(true);

    userForm.scrollIntoView({ behavior: "smooth", block: "center" });
  });
});

function hideUserFormAndReset() {
  if (!userForm) {
    return;
  }

  userForm.reset();
  userForm.setAttribute("action", "/users/create");
  setUserFormMode(false);
  applySelfDisableGuard(null);
  setUserFormVisibility(false);
}

userCancelBtn?.addEventListener("click", hideUserFormAndReset);
userFormCloseBtn?.addEventListener("click", hideUserFormAndReset);
createUserBtn?.addEventListener("click", showCreateUserForm);

if (userForm) {
  setUserFormMode(false);
  applySelfDisableGuard(null);
  setUserFormVisibility(false);
  userFormCard?.classList.add("visible");
  usersListCard?.classList.add("visible");
}

document.querySelectorAll("[data-test-server]").forEach((button) => {
  button.addEventListener("click", async () => {
    const row = button.closest("tr");
    const serverId = button.getAttribute("data-test-server");
    if (!row || !serverId) {
      return;
    }

    const payload = {
      host: (row.dataset.serverHost || "").trim(),
      port: Number(row.dataset.serverPort || 22),
      username: (row.dataset.serverUsername || "").trim(),
      auth_method: row.dataset.serverAuth || "key",
      ssh_key_id: row.dataset.serverSshKeyId ? Number(row.dataset.serverSshKeyId) : null,
      server_id: Number(serverId),
      password: null,
    };

    if (!payload.host || !payload.username) {
      notify("Server details are incomplete for connection testing.", "error");
      return;
    }

    const originalButtonHtml = button.innerHTML;
    button.disabled = true;
    button.innerHTML = '<i class="fas fa-spinner fa-spin"></i>';

    try {
      const response = await fetch("/api/servers/test-connection", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      const responseText = await response.text();
      let data;
      try {
        data = JSON.parse(responseText);
      } catch {
        notify(`Server error (${response.status}): ${response.statusText}`, "error");
        return;
      }

      if (!response.ok) {
        notify(`${row.dataset.serverName || "Server"}: ${data.detail || "Connection test failed."}`, "error");
        return;
      }

      notify(data.message || `${row.dataset.serverName || "Server"}: connection successful.`, "success");
    } catch (error) {
      notify(`Connection test failed: ${error.message}`, "error");
    } finally {
      button.disabled = false;
      button.innerHTML = originalButtonHtml;
    }
  });
});

async function refreshAllServerStatus({ silent = false } = {}) {
  if (!serverStatusBody) {
    return;
  }

  const originalButtonHtml = refreshAllServerStatusBtn.innerHTML;
  if (!silent) {
    refreshAllServerStatusBtn.disabled = true;
    refreshAllServerStatusBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i><span>Checking...</span>';
  }

  try {
    const response = await fetch("/api/server-status/check-all", { method: "POST" });
    const responseText = await response.text();
    let data;
    try {
      data = JSON.parse(responseText);
    } catch {
      if (!silent) {
        notify(`Server error (${response.status}): ${response.statusText}`, "error");
      }
      return;
    }

    if (!response.ok) {
      if (!silent) {
        notify(data.detail || "Failed to refresh server status.", "error");
      }
      return;
    }

    renderServerStatusTable(Array.isArray(data.items) ? data.items : []);
    setServerStatusLastUpdated(data.checked_at || null);
    if (!silent) {
      notify("Server status checks completed.", "success");
    }
  } catch (error) {
    if (!silent) {
      notify(`Failed to refresh server status: ${error.message}`, "error");
    }
  } finally {
    if (!silent) {
      refreshAllServerStatusBtn.disabled = false;
      refreshAllServerStatusBtn.innerHTML = originalButtonHtml;
    }
  }
}

function stopServerStatusAutoCheck() {
  if (serverStatusAutoCheckTimerId !== null) {
    clearTimeout(serverStatusAutoCheckTimerId);
    serverStatusAutoCheckTimerId = null;
  }
}

function scheduleNextServerStatusAutoCheck() {
  if (!serverStatusAutoCheckInterval || !serverStatusAutoCheckToggle?.checked) {
    return;
  }

  const parsed = parseServerStatusCronExpression(serverStatusAutoCheckInterval.value);
  if (!parsed) {
    notify("Invalid cron expression. Use 5 fields like */5 * * * *.", "error");
    return;
  }

  const nextRun = nextServerStatusCronRun(parsed.parsed, new Date());
  if (!nextRun) {
    notify("Could not calculate next run time for this cron expression.", "error");
    return;
  }

  const delayMs = Math.min(2147483647, Math.max(1000, nextRun.getTime() - Date.now()));
  serverStatusAutoCheckTimerId = setTimeout(async () => {
    if (!serverStatusAutoCheckToggle?.checked || serverStatusAutoCheckInFlight) {
      scheduleNextServerStatusAutoCheck();
      return;
    }
    serverStatusAutoCheckInFlight = true;
    try {
      await refreshAllServerStatus({ silent: true });
    } finally {
      serverStatusAutoCheckInFlight = false;
      scheduleNextServerStatusAutoCheck();
    }
  }, delayMs);
}

function startServerStatusAutoCheck() {
  stopServerStatusAutoCheck();
  if (!serverStatusAutoCheckInterval) {
    return;
  }

  const normalized = normalizeServerStatusAutoCheckIntervalValue(serverStatusAutoCheckInterval.value);
  if (!normalized) {
    notify("Invalid cron expression. Use 5 fields like */5 * * * *.", "error");
    return;
  }
  serverStatusAutoCheckInterval.value = normalized;

  // Run once immediately when enabled so users do not wait for the first interval.
  serverStatusAutoCheckInFlight = true;
  refreshAllServerStatus({ silent: true }).finally(() => {
    serverStatusAutoCheckInFlight = false;
    scheduleNextServerStatusAutoCheck();
  });
}

function applyServerStatusAutoCheckState() {
  if (!serverStatusBody || !serverStatusAutoCheckToggle) {
    return;
  }

  if (serverStatusAutoCheckToggle.checked) {
    startServerStatusAutoCheck();
    return;
  }

  stopServerStatusAutoCheck();
}

refreshAllServerStatusBtn?.addEventListener("click", async () => {
  await refreshAllServerStatus({ silent: false });
});

if (serverStatusAutoCheckToggle && serverStatusAutoCheckInterval) {
  serverStatusAutoCheckToggle.addEventListener("change", () => {
    void persistServerStatusPreferences(serverStatusAutoCheckToggle.checked, serverStatusAutoCheckInterval.value, { showFeedback: true });
    applyServerStatusAutoCheckState();
  });

  serverStatusAutoCheckInterval.addEventListener("change", () => {
    const normalized = normalizeServerStatusAutoCheckIntervalValue(serverStatusAutoCheckInterval.value);
    if (!normalized) {
      notify("Invalid cron expression. Use 5 fields like */5 * * * *.", "error");
      serverStatusAutoCheckInterval.value = "*/1 * * * *";
    } else {
      serverStatusAutoCheckInterval.value = normalized;
    }
    void persistServerStatusPreferences(serverStatusAutoCheckToggle.checked, serverStatusAutoCheckInterval.value, { showFeedback: true });
    applyServerStatusAutoCheckState();
  });

  void loadServerStatusPreferences();
}

window.addEventListener("beforeunload", () => {
  stopServerStatusAutoCheck();
});

serverStatusBody?.addEventListener("click", async (event) => {
  const button = event.target.closest("[data-refresh-server-status]");
  if (!(button instanceof HTMLButtonElement)) {
    return;
  }

  const serverId = button.getAttribute("data-refresh-server-status");
  if (!serverId) {
    return;
  }

  const row = button.closest("tr");
  const originalButtonHtml = button.innerHTML;
  button.disabled = true;
  button.innerHTML = '<i class="fas fa-spinner fa-spin"></i>';

  try {
    const response = await fetch(`/api/server-status/${serverId}/check`, { method: "POST" });
    const responseText = await response.text();
    let data;
    try {
      data = JSON.parse(responseText);
    } catch {
      notify(`Server error (${response.status}): ${response.statusText}`, "error");
      return;
    }

    if (!response.ok) {
      notify(data.detail || "Failed to refresh server status.", "error");
      return;
    }

    if (row) {
      row.outerHTML = renderServerStatusRow(data);
    }
    setServerStatusLastUpdated(data.last_health_check_at || null);
    notify(`${data.name || "Server"}: ${data.last_health_message || "status updated."}`, data.last_health_status === "online" ? "success" : "error");
  } catch (error) {
    notify(`Failed to refresh server status: ${error.message}`, "error");
  } finally {
    button.disabled = false;
    button.innerHTML = originalButtonHtml;
  }
});

document.querySelectorAll("[data-delete-server]").forEach((button) => {
  button.addEventListener("click", async () => {
    const serverId = button.getAttribute("data-delete-server");
    if (!serverId) {
      return;
    }

    if (!window.confirm("Delete this server?")) {
      return;
    }

    const response = await fetch(`/api/servers/${serverId}`, { method: "DELETE" });
    if (!response.ok) {
      notify("Failed to delete server", "error");
      return;
    }

    if (typeof window.showToastAfterReload === "function") {
      window.showToastAfterReload("Server deleted successfully.", "success");
    }

    window.location.reload();
  });
});

// Reboot server handler
document.addEventListener("click", async (event) => {
  const rebootButton = event.target.closest("[data-reboot-server]");
  if (!(rebootButton instanceof HTMLButtonElement)) {
    return;
  }

  const serverId = rebootButton.getAttribute("data-reboot-server");
  const serverName = rebootButton.getAttribute("data-server-name") || "this server";
  if (!serverId) {
    return;
  }

  if (!window.confirm(`Reboot ${serverName}?\n\nThe server will be unavailable while rebooting. Unsaved work on the server will be lost.`)) {
    return;
  }

  const originalButtonHtml = rebootButton.innerHTML;
  rebootButton.disabled = true;
  rebootButton.innerHTML = '<i class="fas fa-spinner fa-spin"></i><span>Rebooting...</span>';

  try {
    const response = await fetch(`/api/server-status/${serverId}/reboot`, { method: "POST" });
    const responseText = await response.text();
    let data;
    try {
      data = JSON.parse(responseText);
    } catch {
      notify(`Server error (${response.status}): ${response.statusText}`, "error");
      return;
    }

    if (!response.ok) {
      notify(data.detail || "Failed to send reboot command.", "error");
      return;
    }

    notify(data.message || `Reboot command sent to ${serverName}.`, "success");
  } catch (error) {
    notify(`Failed to send reboot command: ${error.message}`, "error");
  } finally {
    rebootButton.disabled = false;
    rebootButton.innerHTML = originalButtonHtml;
  }
});

runForm?.addEventListener("submit", async (event) => {
  event.preventDefault();
  const checkedServers = [...document.querySelectorAll("#server-checks input:checked")].map((x) => Number(x.value));

  if (checkedServers.length === 0) {
    notify("Select at least one server", "warning");
    return;
  }

  const packageManager = document.getElementById("package_manager");
  const alertOnlyCheckbox = document.getElementById("alert_only");
  const alertOnly = alertOnlyCheckbox instanceof HTMLInputElement && alertOnlyCheckbox.checked;
  const aptExtraStepCheckboxes = document.querySelectorAll("#apt_extra_steps_group input[type='checkbox']:checked");
  const payload = {
    server_ids: checkedServers,
    package_manager: packageManager ? packageManager.value : "auto",
    apt_extra_steps: alertOnly ? [] : [...aptExtraStepCheckboxes].map((x) => x.value),
    alert_only: alertOnly,
  };

  const response = await fetch("/api/updates/run", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    const error = await response.json();
    notify(error.detail || "Failed to run updates", "error");
    return;
  }

  notify("Manual update started. Jobs are now running.", "success");
  loadJobs();
});

// Toggle apt extra steps visibility and button label when alert-only mode changes
document.getElementById("alert_only")?.addEventListener("change", function () {
  const isAlertOnly = this.checked;
  const aptGroup = document.getElementById("apt_extra_steps_group");
  const submitLabel = document.getElementById("run-submit-label");
  const submitIcon = document.getElementById("run-submit-icon");
  if (aptGroup) {
    aptGroup.style.opacity = isAlertOnly ? "0.4" : "";
    aptGroup.style.pointerEvents = isAlertOnly ? "none" : "";
  }
  if (submitLabel) {
    submitLabel.textContent = isAlertOnly ? "Check for Updates" : "Start Update";
  }
  if (submitIcon) {
    submitIcon.className = isAlertOnly ? "fas fa-bell" : "fas fa-play";
  }
});

function renderStatus(status) {
  return `<span class="status status-${status}">${status}</span>`;
}

function formatDateTimeForUi(value) {
  if (!value) {
    return "-";
  }

  const rawValue = String(value);
  const normalized = rawValue.includes("T") ? rawValue : rawValue.replace(" ", "T");
  const hasTimezoneSuffix = /Z$|[+-]\d{2}:?\d{2}$/.test(normalized);
  const timestamp = new Date(hasTimezoneSuffix ? normalized : `${normalized}Z`);
  if (Number.isNaN(timestamp.getTime())) {
    return String(value);
  }

  const parts = new Intl.DateTimeFormat("en-US", {
    timeZone: appTimezone,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }).formatToParts(timestamp);

  const getPart = (type) => parts.find((part) => part.type === type)?.value || "00";
  const year = getPart("year");
  const month = getPart("month");
  const day = getPart("day");
  const hour = getPart("hour");
  const minute = getPart("minute");
  const second = getPart("second");
  const monthNames = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

  if (appDateFormat === "us-24") {
    return `${month}/${day}/${year} ${hour}:${minute}:${second}`;
  }

  if (appDateFormat === "eu-24") {
    return `${day}/${month}/${year} ${hour}:${minute}:${second}`;
  }

  if (appDateFormat === "month-name") {
    return `${day} ${monthNames[Math.max(0, Number(month) - 1)]} ${year} ${hour}:${minute}:${second}`;
  }

  return `${year}-${month}-${day} ${hour}:${minute}:${second}`;
}

function formatOutputPreview(job) {
  if (job.summary) {
    return escapeHtml(job.summary);
  }

  if (job.status === "pending" || job.status === "running") {
    return "-";
  }

  return "Update completed";
}

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function renderServerHealthStatus(status) {
  if (status === "online") {
    return '<span class="status status-success">online</span>';
  }
  if (status === "offline") {
    return '<span class="status status-failed">offline</span>';
  }
  return '<span class="status status-pending">unknown</span>';
}

function formatPercent(value) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) {
    return "-";
  }
  return `${numeric.toFixed(1)}%`;
}

function renderServerStatusRow(server) {
  return `
    <tr data-server-status-row="${escapeHtml(server.id)}">
      <td><strong>${escapeHtml(server.name)}</strong>${server.needs_reboot ? ' <i class="fas fa-power-off reboot-required-icon" title="Reboot required"></i>' : ''}</td>
      <td>${escapeHtml(server.host)}:${escapeHtml(server.port)}</td>
      <td>${escapeHtml(server.username)}</td>
      <td data-server-status-cell="status">${renderServerHealthStatus(server.last_health_status)}</td>
      <td class="hide-mobile" data-server-status-cell="cpu">${escapeHtml(formatPercent(server.last_cpu_usage))}</td>
      <td class="hide-mobile" data-server-status-cell="ram">${escapeHtml(formatPercent(server.last_ram_usage))}</td>
      <td class="hide-mobile" data-server-status-cell="storage">${escapeHtml(formatPercent(server.last_storage_usage))}</td>
      <td class="hide-mobile" data-server-status-cell="load-avg-1">${server.last_load_avg != null ? escapeHtml(Number(server.last_load_avg).toFixed(2)) : "-"}</td>
      <td class="hide-mobile" data-server-status-cell="load-avg-5">${server.last_load_avg_5 != null ? escapeHtml(Number(server.last_load_avg_5).toFixed(2)) : "-"}</td>
      <td class="hide-mobile" data-server-status-cell="load-avg-15">${server.last_load_avg_15 != null ? escapeHtml(Number(server.last_load_avg_15).toFixed(2)) : "-"}</td>
      <td class="hide-mobile" data-server-status-cell="last-check">${escapeHtml(server.last_health_check_at ? formatDateTimeForUi(server.last_health_check_at) : "Not checked yet")}</td>
      <td class="hide-mobile" data-server-status-cell="message">${server.last_health_status === "online" ? "-" : escapeHtml(server.last_health_message || "No checks recorded yet.")}</td>
      <td>
        <button type="button" class="btn btn-primary btn-sm btn-icon-only" title="Check now" data-refresh-server-status="${escapeHtml(server.id)}">
          <i class="fas fa-rotate-right"></i>
        </button>
      </td>
    </tr>
  `;
}

function renderServerStatusTable(items) {
  if (!serverStatusBody) {
    return;
  }

  if (!items.length) {
    serverStatusBody.innerHTML = `
      <tr>
        <td colspan="13" class="text-center empty-state">
          <div>
            <i class="fas fa-server empty-icon"></i>
            <p>No servers configured yet.</p>
          </div>
        </td>
      </tr>
    `;
    return;
  }

  serverStatusBody.innerHTML = items.map((item) => renderServerStatusRow(item)).join("");
}

function setServerStatusLastUpdated(value) {
  if (!serverStatusLastUpdated) {
    return;
  }

  serverStatusLastUpdated.textContent = value
    ? `Latest stored result: ${formatDateTimeForUi(value)}`
    : "Latest stored result: no checks yet";
}

function renderJobRow(job) {
  const jobTypeLabel = job.job_type === "scheduled" ? "Scheduled" : "Manual";
  const packageManagerLabel = job.package_manager === "auto" ? "Automatically Detect" : job.package_manager;
  const canStop = job.status === "pending" || job.status === "running";
  const canRerun = job.status === "skipped";
  const extraAction = canStop
    ? `<button type="button" class="btn btn-warning btn-sm btn-icon-only" data-stop-job="${job.id}" title="Stop job"><i class="fas fa-stop"></i></button>`
    : (canRerun
      ? `<button type="button" class="btn btn-success btn-sm btn-icon-only" data-rerun-job="${job.id}" title="Re-run job"><i class="fas fa-rotate-right"></i></button>`
      : "");
  const actionsCell = `<div class="flex-gap-8"><button type="button" class="btn btn-primary btn-sm btn-icon-only" data-view-job="${job.id}" title="View output"><i class="fas fa-eye"></i></button>${extraAction}</div>`;
  return `
      <tr data-job-id="${job.id}" class="job-row" title="Click to view output">
        <td>${job.id}</td>
        <td>${escapeHtml(job.server_name || `Server #${job.server_id}`)}</td>
        <td>${escapeHtml(jobTypeLabel)}</td>
        <td>${renderStatus(job.status)}</td>
        <td>${escapeHtml(packageManagerLabel)}</td>
        <td>${escapeHtml(formatDateTimeForUi(job.created_at))}</td>
        <td>${escapeHtml(formatDateTimeForUi(job.started_at))}</td>
        <td>${escapeHtml(formatDateTimeForUi(job.finished_at))}</td>
        <td>${formatOutputPreview(job)}</td>
        <td>${actionsCell}</td>
      </tr>
    `;
}

const SECTION_LABELS = {
  summary: "Summary",
  "apt-extra-steps": "Additional apt Steps",
  steps: "Steps",
  "command-output": "Command Output",
  hint: "Hint",
  error: "Error",
};

function renderJobOutput(raw) {
  if (!raw) return "No output loaded.";
  const sectionPattern = /^\[([a-z-]+)\]\n?/gm;
  const parts = [];
  let lastIndex = 0;
  let match;
  const matches = [];

  while ((match = sectionPattern.exec(raw)) !== null) {
    matches.push({ index: match.index, tag: match[1], end: match.index + match[0].length });
  }

  for (let i = 0; i < matches.length; i++) {
    const { index, tag, end } = matches[i];
    const contentEnd = i + 1 < matches.length ? matches[i + 1].index : raw.length;
    const label = SECTION_LABELS[tag] || tag;
    const content = raw.slice(end, contentEnd).trimEnd();
    parts.push(
      `<span class="output-section-label">${escapeHtml(label)}</span>` +
      `<span class="output-section-body">${escapeHtml(content)}</span>`
    );
    lastIndex = contentEnd;
  }

  if (matches.length === 0) {
    return escapeHtml(raw);
  }

  return parts.join("");
}

function setDisplayedJobOutput(job) {
  // Remove any existing output rows
  document.querySelectorAll("#jobs-body tr.job-output-row").forEach((r) => r.remove());

  // Mark the selected row
  document.querySelectorAll("#jobs-body tr.job-row").forEach((r) => r.classList.remove("selected-job-row"));
  const selectedRow = document.querySelector(`#jobs-body tr[data-job-id="${job.id}"]`);
  if (!selectedRow) return;
  selectedRow.classList.add("selected-job-row");

  // Insert expansion row after the selected row
  const colCount = selectedRow.cells.length;
  const outputTr = document.createElement("tr");
  outputTr.className = "job-output-row";
  const outputTd = document.createElement("td");
  outputTd.colSpan = colCount;
  const pre = document.createElement("pre");
  pre.className = "job-output-pre";
  pre.innerHTML = renderJobOutput(job.output);
  outputTd.appendChild(pre);
  outputTr.appendChild(outputTd);
  selectedRow.insertAdjacentElement("afterend", outputTr);
  syncJobsLiveRefreshState?.();
}

async function viewJobOutput(jobId) {
  // Toggle off if clicking the already-open row
  if (selectedJobId === jobId) {
    document.querySelectorAll("#jobs-body tr.job-output-row").forEach((r) => r.remove());
    document.querySelectorAll("#jobs-body tr.job-row").forEach((r) => r.classList.remove("selected-job-row"));
    selectedJobId = null;
    syncJobsLiveRefreshState?.();
    return;
  }

  const response = await fetch(`/api/updates/${jobId}`);
  if (!response.ok) {
    notify("Failed to load job output", "error");
    return;
  }

  const job = await response.json();
  const jobRowSelector = `#jobs-body tr[data-job-id="${job.id}"]`;
  if (!document.querySelector(jobRowSelector) && jobsBody) {
    jobsBody.querySelectorAll("tr").forEach((row) => {
      if (!row.getAttribute("data-job-id")) {
        row.remove();
      }
    });
    jobsBody.insertAdjacentHTML("afterbegin", renderJobRow(job));
  }

  selectedJobId = Number(job.id);
  setDisplayedJobOutput(job);

  const selectedRow = document.querySelector(jobRowSelector);
  if (selectedRow) {
    selectedRow.scrollIntoView({ behavior: "smooth", block: "center" });
  }
}

async function loadJobs() {
  if (!jobsBody) {
    return;
  }

  const response = await fetch("/api/updates?limit=30");
  if (!response.ok) {
    return;
  }

  const jobs = await response.json();
  if (jobs.length === 0) {
    jobsBody.innerHTML = '<tr><td colspan="10">No jobs yet.</td></tr>';
    selectedJobId = null;
    return;
  }

  jobsBody.innerHTML = jobs.map((job) => renderJobRow(job)).join("");

  const selectedJob = selectedJobId ? jobs.find((job) => job.id === selectedJobId) : null;
  if (selectedJob) {
    setDisplayedJobOutput(selectedJob);
  }

  if (pendingAutoOpenJobId) {
    const autoOpenId = pendingAutoOpenJobId;
    pendingAutoOpenJobId = null;
    await viewJobOutput(autoOpenId);
  }
  // Don't auto-open any row — user clicks to expand
}

jobsBody?.addEventListener("click", async (event) => {
  const target = event.target;
  const element = target instanceof Element ? target : target?.parentElement;
  const viewButton = element?.closest("[data-view-job]");
  if (viewButton) {
    event.preventDefault();
    event.stopPropagation();
    const jobId = Number(viewButton.getAttribute("data-view-job"));
    if (!jobId) {
      return;
    }
    await viewJobOutput(jobId);
    return;
  }

  const stopButton = element?.closest("[data-stop-job]");
  if (stopButton) {
    event.preventDefault();
    event.stopPropagation();
    const jobId = Number(stopButton.getAttribute("data-stop-job"));
    if (!jobId) {
      return;
    }
    if (!window.confirm(`Stop job #${jobId}?`)) {
      return;
    }

    stopButton.setAttribute("disabled", "disabled");
    try {
      const response = await fetch(`/api/updates/${jobId}/stop`, { method: "POST" });
      if (!response.ok) {
        const error = await response.json().catch(() => ({ detail: "Failed to stop job." }));
        notify(error.detail || "Failed to stop job.", "error");
      } else {
        notify("Stop requested. Refreshing jobs...", "success");
        if (window.location.pathname.startsWith("/updates/jobs")) {
          window.location.reload();
        } else {
          await loadJobs();
        }
      }
    } catch (error) {
      notify(`Failed to stop job: ${error.message}`, "error");
    } finally {
      stopButton.removeAttribute("disabled");
    }
    return;
  }

  const rerunButton = element?.closest("[data-rerun-job]");
  if (rerunButton) {
    event.preventDefault();
    event.stopPropagation();
    const jobId = Number(rerunButton.getAttribute("data-rerun-job"));
    if (!jobId) {
      return;
    }
    if (!window.confirm(`Re-run skipped job #${jobId}?`)) {
      return;
    }

    rerunButton.setAttribute("disabled", "disabled");
    try {
      const response = await fetch(`/api/updates/${jobId}/rerun`, { method: "POST" });
      if (!response.ok) {
        const error = await response.json().catch(() => ({ detail: "Failed to re-run job." }));
        notify(error.detail || "Failed to re-run job.", "error");
      } else {
        notify("Job re-run started. Refreshing jobs...", "success");
        if (window.location.pathname.startsWith("/updates/jobs")) {
          window.location.reload();
        } else {
          await loadJobs();
        }
      }
    } catch (error) {
      notify(`Failed to re-run job: ${error.message}`, "error");
    } finally {
      rerunButton.removeAttribute("disabled");
    }
    return;
  }

  const row = element?.closest("tr[data-job-id]");
  if (!row) {
    return;
  }

  if (element?.closest("button, a, input, select, textarea")) {
    return;
  }

  const jobId = Number(row.getAttribute("data-job-id"));
  if (!jobId) {
    return;
  }

  await viewJobOutput(jobId);
});

scheduleForm?.addEventListener("submit", async (event) => {
  event.preventDefault();

  const scheduleServers = [...document.querySelectorAll("#schedule-server-checks input:checked")].map((x) => Number(x.value));
  if (scheduleServers.length === 0) {
    notify("Select at least one server for this schedule", "warning");
    return;
  }

  const payload = {
    name: document.getElementById("schedule_name")?.value,
    cron_expression: document.getElementById("cron_expression")?.value,
    package_manager: document.getElementById("schedule_package_manager")?.value || "auto",
    server_ids: scheduleServers,
    auto_disable_on_failures: Boolean(autoDisableOnFailuresInput?.checked),
    failure_threshold: autoDisableOnFailuresInput?.checked ? Number(failureThresholdInput?.value || 0) : null,
    apt_extra_steps: [...document.querySelectorAll("#sched_apt_step_full_upgrade, #sched_apt_step_fix_dpkg, #sched_apt_step_fix_broken, #sched_apt_step_autoremove, #sched_apt_step_clean")]
      .filter((el) => el instanceof HTMLInputElement && el.checked)
      .map((el) => el.value),
    alert_only: document.getElementById("sched_alert_only") instanceof HTMLInputElement
      ? (document.getElementById("sched_alert_only")).checked
      : false,
  };

  if (payload.auto_disable_on_failures && (!payload.failure_threshold || payload.failure_threshold < 1)) {
    notify("Enter a valid failure threshold of at least 1.", "error");
    return;
  }

  const editingScheduleId = scheduleIdInput?.value ? Number(scheduleIdInput.value) : null;

  const endpoint = editingScheduleId ? `/api/schedules/${editingScheduleId}` : "/api/schedules";
  const method = editingScheduleId ? "PUT" : "POST";
  const response = await fetch(endpoint, {
    method,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    const error = await response.json();
    notify(error.detail || (editingScheduleId ? "Failed to update schedule" : "Failed to create schedule"), "error");
    return;
  }

  if (typeof window.showToastAfterReload === "function") {
    window.showToastAfterReload(
      editingScheduleId ? "Schedule updated successfully." : "Schedule created successfully.",
      "success"
    );
  }
  window.location.reload();
});

function setScheduleFormVisibility(showForm) {
  if (!scheduleFormCard || !scheduledUpdatesCard) {
    return;
  }
  scheduleFormCard.classList.toggle("hidden", !showForm);
  scheduledUpdatesCard.classList.toggle("hidden", showForm);
}

function showCreateScheduleForm() {
  scheduleForm?.reset();
  if (scheduleIdInput) {
    scheduleIdInput.value = "";
  }
  if (scheduleFormTitle) {
    scheduleFormTitle.textContent = "Create Scheduled Update";
  }
  if (scheduleFormIcon) {
    scheduleFormIcon.className = "fas fa-calendar-plus";
  }
  if (saveScheduleBtn) {
    saveScheduleBtn.innerHTML = '<i class="fas fa-calendar-plus"></i><span>Create Schedule</span>';
  }
  if (failureThresholdInput) {
    failureThresholdInput.value = "3";
  }
  clearScheduleAptExtraSteps();
  toggleScheduleFailureThreshold();
  setScheduleFormVisibility(true);
  window.scrollTo({ top: 0, behavior: "smooth" });
}

function hideScheduleFormAndReset() {
  scheduleForm?.reset();
  if (scheduleIdInput) {
    scheduleIdInput.value = "";
  }
  if (scheduleFormTitle) {
    scheduleFormTitle.textContent = "Create Scheduled Update";
  }
  if (scheduleFormIcon) {
    scheduleFormIcon.className = "fas fa-calendar-plus";
  }
  if (saveScheduleBtn) {
    saveScheduleBtn.innerHTML = '<i class="fas fa-calendar-plus"></i><span>Create Schedule</span>';
  }
  if (failureThresholdInput) {
    failureThresholdInput.value = "3";
  }
  clearScheduleAptExtraSteps();
  toggleScheduleFailureThreshold();
  setScheduleFormVisibility(false);
}

createScheduleBtn?.addEventListener("click", showCreateScheduleForm);
createScheduleBtnEmpty?.addEventListener("click", showCreateScheduleForm);
cancelScheduleBtn?.addEventListener("click", hideScheduleFormAndReset);
scheduleFormCloseBtn?.addEventListener("click", hideScheduleFormAndReset);
autoDisableOnFailuresInput?.addEventListener("change", toggleScheduleFailureThreshold);

if (scheduleFormCard && scheduledUpdatesCard) {
  setScheduleFormVisibility(false);
  scheduleFormCard.classList.add("visible");
  scheduledUpdatesCard.classList.add("visible");
}
toggleScheduleFailureThreshold();

document.querySelectorAll("[data-edit-schedule]").forEach((button) => {
  button.addEventListener("click", () => {
    if (!scheduleForm) {
      return;
    }

    const editId = button.getAttribute("data-edit-schedule");
    if (!editId) {
      return;
    }

    scheduleForm.reset();
    if (scheduleIdInput) {
      scheduleIdInput.value = editId;
    }

    const scheduleName = button.getAttribute("data-schedule-name") || "";
    const scheduleCron = button.getAttribute("data-schedule-cron") || "";
    const schedulePackageManager = button.getAttribute("data-schedule-package-manager") || "auto";
    const scheduleServerIdsRaw = button.getAttribute("data-schedule-server-ids") || "";
    const scheduleAutoDisableOnFailures = button.getAttribute("data-schedule-auto-disable-on-failures") === "true";
    const scheduleFailureThreshold = button.getAttribute("data-schedule-failure-threshold") || "3";
    const scheduleAptExtraStepsRaw = button.getAttribute("data-schedule-apt-extra-steps") || "";
    const scheduleAptExtraSteps = scheduleAptExtraStepsRaw.split(",").map((s) => s.trim()).filter((s) => s.length > 0);
    const scheduleAlertOnly = button.getAttribute("data-schedule-alert-only") === "true";
    const scheduleServerIds = scheduleServerIdsRaw
      .split(",")
      .map((value) => value.trim())
      .filter((value) => value.length > 0);

    const nameField = document.getElementById("schedule_name");
    const cronField = document.getElementById("cron_expression");
    const packageManagerField = document.getElementById("schedule_package_manager");

    if (nameField) {
      nameField.value = scheduleName;
    }
    if (cronField) {
      cronField.value = scheduleCron;
    }
    if (packageManagerField) {
      packageManagerField.value = schedulePackageManager;
    }
    if (autoDisableOnFailuresInput) {
      autoDisableOnFailuresInput.checked = scheduleAutoDisableOnFailures;
    }
    if (failureThresholdInput) {
      failureThresholdInput.value = scheduleFailureThreshold;
    }
    toggleScheduleFailureThreshold();

    ["full_upgrade", "fix_dpkg", "fix_broken", "autoremove", "clean"].forEach((step) => {
      const el = document.getElementById(`sched_apt_step_${step}`);
      if (el instanceof HTMLInputElement) {
        el.checked = scheduleAptExtraSteps.includes(step);
      }
    });

    const schedAlertOnlyEl = document.getElementById("sched_alert_only");
    if (schedAlertOnlyEl instanceof HTMLInputElement) {
      schedAlertOnlyEl.checked = scheduleAlertOnly;
    }

    document.querySelectorAll("#schedule-server-checks input[type='checkbox']").forEach((checkbox) => {
      if (checkbox instanceof HTMLInputElement) {
        checkbox.checked = scheduleServerIds.includes(checkbox.value);
      }
    });

    if (scheduleFormTitle) {
      scheduleFormTitle.textContent = "Edit Scheduled Update";
    }
    if (scheduleFormIcon) {
      scheduleFormIcon.className = "fas fa-calendar-check";
    }
    if (saveScheduleBtn) {
      saveScheduleBtn.innerHTML = '<i class="fas fa-save"></i><span>Save Changes</span>';
    }

    setScheduleFormVisibility(true);
    window.scrollTo({ top: 0, behavior: "smooth" });
  });
});

document.querySelectorAll("[data-toggle-schedule]").forEach((button) => {
  button.addEventListener("click", async () => {
    const scheduleId = button.getAttribute("data-toggle-schedule");
    if (!scheduleId) {
      return;
    }

    const response = await fetch(`/api/schedules/${scheduleId}/toggle`, { method: "POST" });
    if (!response.ok) {
      const error = await response.json();
      notify(error.detail || "Failed to toggle schedule", "error");
      return;
    }
    if (typeof window.showToastAfterReload === "function") {
      window.showToastAfterReload("Schedule status updated.", "success");
    }
    window.location.reload();
  });
});

document.querySelectorAll("[data-delete-schedule]").forEach((button) => {
  button.addEventListener("click", async () => {
    const scheduleId = button.getAttribute("data-delete-schedule");
    if (!scheduleId) {
      return;
    }

    if (!window.confirm("Delete this schedule?")) {
      return;
    }

    const response = await fetch(`/api/schedules/${scheduleId}`, { method: "DELETE" });
    if (!response.ok) {
      const error = await response.json();
      notify(error.detail || "Failed to delete schedule", "error");
      return;
    }
    if (typeof window.showToastAfterReload === "function") {
      window.showToastAfterReload("Schedule deleted successfully.", "success");
    }
    window.location.reload();
  });
});

if (jobsBody) {
  const isServerRenderedJobsPage = window.location.pathname.startsWith("/updates/jobs");
  if (isServerRenderedJobsPage) {
    const liveUpdatesToggle = document.getElementById("live_updates_toggle");
    const searchParams = new URLSearchParams(window.location.search);
    const hasActiveFilters = ["q", "status", "job_type", "date_from", "date_to", "job_id"].some((key) => {
      const value = (searchParams.get(key) || "").trim();
      return value.length > 0;
    }) || Number(searchParams.get("page") || "1") > 1;
    let refreshTimerId = null;

    const stopLiveRefresh = () => {
      if (refreshTimerId !== null) {
        clearInterval(refreshTimerId);
        refreshTimerId = null;
      }
    };

    const startLiveRefresh = () => {
      stopLiveRefresh();
      refreshTimerId = setInterval(() => {
        window.location.reload();
      }, 10000);
    };

    const updateLiveRefreshState = () => {
      const hasOpenOutput = selectedJobId !== null || Boolean(document.querySelector("#jobs-body tr.job-output-row"));
      if (liveUpdatesToggle?.checked && !hasActiveFilters && !hasOpenOutput && !window.jobsFilterCardOpen) {
        startLiveRefresh();
        liveUpdatesToggle.title = "Live updates are enabled.";
        return;
      }

      stopLiveRefresh();
      if (liveUpdatesToggle && !hasActiveFilters && hasOpenOutput) {
        liveUpdatesToggle.title = "Live updates pause automatically while job output is open.";
      }
    };

    syncJobsLiveRefreshState = updateLiveRefreshState;
    window.syncJobsLiveRefreshState = updateLiveRefreshState;

    if (liveUpdatesToggle) {
      if (hasActiveFilters) {
        liveUpdatesToggle.checked = false;
        liveUpdatesToggle.disabled = true;
        liveUpdatesToggle.title = "Clear filters and return to page 1 to enable live updates.";
      }

      liveUpdatesToggle.addEventListener("change", () => {
        updateLiveRefreshState();
      });

      updateLiveRefreshState();
    }
  } else {
    setInterval(loadJobs, 5000);
    loadJobs();
  }
}

const auditLiveUpdatesToggle = document.getElementById("audit_live_updates_toggle");
if (auditLiveUpdatesToggle && window.location.pathname.startsWith("/audit-log")) {
  const searchParams = new URLSearchParams(window.location.search);
  const hasActiveFilters = ["q", "action", "actor", "date_from", "date_to"].some((key) => {
    const value = (searchParams.get(key) || "").trim();
    return value.length > 0;
  }) || Number(searchParams.get("page") || "1") > 1;
  let refreshTimerId = null;

  const stopLiveRefresh = () => {
    if (refreshTimerId !== null) {
      clearInterval(refreshTimerId);
      refreshTimerId = null;
    }
  };

  const startLiveRefresh = () => {
    stopLiveRefresh();
    refreshTimerId = setInterval(() => {
      window.location.reload();
    }, 10000);
  };

  if (hasActiveFilters) {
    auditLiveUpdatesToggle.checked = false;
    auditLiveUpdatesToggle.disabled = true;
    auditLiveUpdatesToggle.title = "Clear filters and return to page 1 to enable live updates.";
  }

  auditLiveUpdatesToggle.addEventListener("change", () => {
    if (auditLiveUpdatesToggle.checked && !hasActiveFilters) {
      startLiveRefresh();
      return;
    }
    stopLiveRefresh();
  });

  if (auditLiveUpdatesToggle.checked && !hasActiveFilters) {
    startLiveRefresh();
  }
}
