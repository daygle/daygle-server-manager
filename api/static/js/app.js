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

function notify(message, type = "info") {
  if (typeof window.showToast === "function") {
    window.showToast(message, type);
    return;
  }
  window.alert(message);
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
  if (cancelEditBtn) {
    cancelEditBtn.classList.add("hidden");
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
  if (cancelEditBtn) {
    cancelEditBtn.classList.add("hidden");
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

    toggleAuthFields();

    if (saveServerBtn) {
      saveServerBtn.innerHTML = '<i class="fas fa-pen"></i><span>Update Server</span>';
    }
    if (serverFormTitle) {
      serverFormTitle.textContent = "Edit Server";
    }
    if (cancelEditBtn) {
      cancelEditBtn.classList.remove("hidden");
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
  if (!refreshAllServerStatusBtn) {
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
    clearInterval(serverStatusAutoCheckTimerId);
    serverStatusAutoCheckTimerId = null;
  }
}

function startServerStatusAutoCheck() {
  stopServerStatusAutoCheck();
  if (!serverStatusAutoCheckInterval) {
    return;
  }

  const intervalSeconds = Number(serverStatusAutoCheckInterval.value || 60);
  const intervalMs = Number.isFinite(intervalSeconds) && intervalSeconds > 0 ? intervalSeconds * 1000 : 60000;

  serverStatusAutoCheckTimerId = setInterval(async () => {
    if (serverStatusAutoCheckInFlight) {
      return;
    }
    serverStatusAutoCheckInFlight = true;
    try {
      await refreshAllServerStatus({ silent: true });
    } finally {
      serverStatusAutoCheckInFlight = false;
    }
  }, intervalMs);
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
  const storedEnabled = localStorage.getItem(SERVER_STATUS_AUTO_CHECK_ENABLED_KEY);
  const storedInterval = localStorage.getItem(SERVER_STATUS_AUTO_CHECK_INTERVAL_KEY);

  if (storedInterval && [...serverStatusAutoCheckInterval.options].some((option) => option.value === storedInterval)) {
    serverStatusAutoCheckInterval.value = storedInterval;
  }
  serverStatusAutoCheckToggle.checked = storedEnabled === "true";

  serverStatusAutoCheckToggle.addEventListener("change", () => {
    localStorage.setItem(SERVER_STATUS_AUTO_CHECK_ENABLED_KEY, String(serverStatusAutoCheckToggle.checked));
    applyServerStatusAutoCheckState();
  });

  serverStatusAutoCheckInterval.addEventListener("change", () => {
    localStorage.setItem(SERVER_STATUS_AUTO_CHECK_INTERVAL_KEY, serverStatusAutoCheckInterval.value);
    applyServerStatusAutoCheckState();
  });

  applyServerStatusAutoCheckState();
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
  button.innerHTML = '<i class="fas fa-spinner fa-spin"></i><span>Checking...</span>';

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

runForm?.addEventListener("submit", async (event) => {
  event.preventDefault();
  const checkedServers = [...document.querySelectorAll("#server-checks input:checked")].map((x) => Number(x.value));

  if (checkedServers.length === 0) {
    notify("Select at least one server", "warning");
    return;
  }

  const packageManager = document.getElementById("package_manager");
  const payload = {
    server_ids: checkedServers,
    package_manager: packageManager ? packageManager.value : "auto",
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
      <td><strong>${escapeHtml(server.name)}</strong></td>
      <td>${escapeHtml(server.host)}:${escapeHtml(server.port)}</td>
      <td>${escapeHtml(server.username)}</td>
      <td data-server-status-cell="status">${renderServerHealthStatus(server.last_health_status)}</td>
      <td class="hide-mobile" data-server-status-cell="cpu">${escapeHtml(formatPercent(server.last_cpu_usage))}</td>
      <td class="hide-mobile" data-server-status-cell="ram">${escapeHtml(formatPercent(server.last_ram_usage))}</td>
      <td class="hide-mobile" data-server-status-cell="storage">${escapeHtml(formatPercent(server.last_storage_usage))}</td>
      <td class="hide-mobile" data-server-status-cell="last-check">${escapeHtml(server.last_health_check_at ? formatDateTimeForUi(server.last_health_check_at) : "Not checked yet")}</td>
      <td class="hide-mobile" data-server-status-cell="message">${server.last_health_status === "online" ? "-" : escapeHtml(server.last_health_message || "No checks recorded yet.")}</td>
      <td>
        <button type="button" class="btn btn-primary btn-sm" data-refresh-server-status="${escapeHtml(server.id)}">
          <i class="fas fa-rotate-right"></i>
          <span>Check Now</span>
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
        <td colspan="10" class="text-center empty-state">
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
      </tr>
    `;
}

const SECTION_LABELS = {
  summary: "Summary",
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
    jobsBody.innerHTML = '<tr><td colspan="9">No jobs yet.</td></tr>';
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
      if (liveUpdatesToggle?.checked && !hasActiveFilters && !hasOpenOutput) {
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
