const sidebar = document.getElementById("sidebar");
const sidebarBrand = document.getElementById("sidebarBrand");
const sidebarMobileToggle = document.getElementById("sidebarMobileToggle");

const serverForm = document.getElementById("server-form");
const runForm = document.getElementById("run-form");
const scheduleForm = document.getElementById("schedule-form");
const jobsBody = document.getElementById("jobs-body");
const schedulesBody = document.getElementById("schedules-body");
const latestLog = document.getElementById("latest-log");
const selectedJobLabel = document.getElementById("selected-job-label");
const authMethod = document.getElementById("auth_method");
const passwordLabel = document.getElementById("password_label");
const keyLabel = document.getElementById("key_label");
const cancelEditBtn = document.getElementById("cancel_edit_btn");
const saveServerBtn = document.getElementById("save_server_btn");
const userForm = document.getElementById("user-form");
const userFormTitle = document.getElementById("user-form-title");
const userSubmitBtn = document.getElementById("user_submit_btn");
const userCancelBtn = document.getElementById("user_cancel_btn");
const userPasswordInput = document.getElementById("user_password");
const userConfirmPasswordInput = document.getElementById("user_confirm_password");
let selectedJobId = null;

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
  const passwordInput = passwordLabel.querySelector('input[name="password"]');
  const keySelect = keyLabel.querySelector('select[name="ssh_key_id"]');

  passwordLabel.classList.toggle("hidden", !isPassword);
  keyLabel.classList.toggle("hidden", isPassword);

  if (passwordInput) {
    passwordInput.required = isPassword;
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
    alert(error.detail || "Failed to save server");
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
    saveServerBtn.textContent = "Save Server";
  }
  window.location.reload();
});

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
    const passwordInput = serverForm.querySelector('input[name="password"]');
    if (passwordInput && row.dataset.serverAuth === "password") {
      passwordInput.placeholder = "Leave blank to keep current password";
    }

    if (saveServerBtn) {
      saveServerBtn.textContent = "Update Server";
    }
    if (cancelEditBtn) {
      cancelEditBtn.classList.remove("hidden");
    }
    serverForm.scrollIntoView({ behavior: "smooth", block: "center" });
  });
});

cancelEditBtn?.addEventListener("click", () => {
  if (!serverForm) {
    return;
  }
  serverForm.reset();
  const serverIdInput = serverForm.querySelector('input[name="server_id"]');
  if (serverIdInput) {
    serverIdInput.value = "";
  }
  if (saveServerBtn) {
    saveServerBtn.textContent = "Save Server";
  }
  cancelEditBtn.classList.add("hidden");
  toggleAuthFields();
});

function setUserFormMode(editing) {
  if (!userForm || !userSubmitBtn || !userCancelBtn || !userPasswordInput || !userConfirmPasswordInput || !userFormTitle) {
    return;
  }

  if (editing) {
    userFormTitle.textContent = "Edit User";
    userSubmitBtn.textContent = "Update User";
    userCancelBtn.classList.remove("hidden");
    userPasswordInput.required = false;
    userConfirmPasswordInput.required = false;
    userPasswordInput.placeholder = "Leave blank to keep current password";
    userConfirmPasswordInput.placeholder = "Repeat new password";
  } else {
    userFormTitle.textContent = "Create User";
    userSubmitBtn.textContent = "Create User";
    userCancelBtn.classList.add("hidden");
    userPasswordInput.required = true;
    userConfirmPasswordInput.required = true;
    userPasswordInput.placeholder = "";
    userConfirmPasswordInput.placeholder = "";
  }
}

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

    userForm.scrollIntoView({ behavior: "smooth", block: "center" });
  });
});

userCancelBtn?.addEventListener("click", () => {
  if (!userForm) {
    return;
  }

  userForm.reset();
  userForm.setAttribute("action", "/users/create");
  setUserFormMode(false);
});

if (userForm) {
  setUserFormMode(false);
}

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
      alert("Failed to delete server");
      return;
    }

    window.location.reload();
  });
});

runForm?.addEventListener("submit", async (event) => {
  event.preventDefault();
  const checkedServers = [...document.querySelectorAll("#server-checks input:checked")].map((x) => Number(x.value));

  if (checkedServers.length === 0) {
    alert("Select at least one server");
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
    alert(error.detail || "Failed to run updates");
    return;
  }

  loadJobs();
});

function renderStatus(status) {
  return `<span class="status status-${status}">${status}</span>`;
}

function formatOutputPreview(output) {
  if (!output) {
    return "-";
  }
  return output.replace(/\s+/g, " ").slice(0, 120);
}

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function renderJobRow(job) {
  return `
      <tr data-job-id="${job.id}">
        <td>${job.id}</td>
        <td>${job.server_id}</td>
        <td>${renderStatus(job.status)}</td>
        <td>${escapeHtml(job.package_manager)}</td>
        <td>${escapeHtml(job.created_at)}</td>
        <td>${escapeHtml(job.started_at || "-")}</td>
        <td>${escapeHtml(job.finished_at || "-")}</td>
        <td>${escapeHtml(formatOutputPreview(job.output))}</td>
        <td><button type="button" class="btn-secondary" data-view-job="${job.id}">View output</button></td>
      </tr>
    `;
}

function setDisplayedJobOutput(job) {
  if (!latestLog) {
    return;
  }

  latestLog.textContent = job.output || "No output yet for this job.";
  if (selectedJobLabel) {
    selectedJobLabel.textContent = `job #${job.id}`;
  }
}

async function viewJobOutput(jobId) {
  if (!latestLog) {
    return;
  }

  const response = await fetch(`/api/updates/${jobId}`);
  if (!response.ok) {
    alert("Failed to load job output");
    return;
  }

  const job = await response.json();
  selectedJobId = Number(job.id);
  setDisplayedJobOutput(job);
}

async function loadJobs() {
  if (!jobsBody || !latestLog) {
    return;
  }

  const response = await fetch("/api/updates?limit=30");
  if (!response.ok) {
    return;
  }

  const jobs = await response.json();
  if (jobs.length === 0) {
    jobsBody.innerHTML = '<tr><td colspan="9">No jobs yet.</td></tr>';
    latestLog.textContent = "No output loaded.";
    if (selectedJobLabel) {
      selectedJobLabel.textContent = "latest";
    }
    selectedJobId = null;
    return;
  }

  jobsBody.innerHTML = jobs.map((job) => renderJobRow(job)).join("");

  const selectedJob = selectedJobId ? jobs.find((job) => job.id === selectedJobId) : null;
  if (selectedJob) {
    setDisplayedJobOutput(selectedJob);
  } else {
    selectedJobId = jobs[0].id;
    setDisplayedJobOutput(jobs[0]);
  }
}

jobsBody?.addEventListener("click", async (event) => {
  const target = event.target;
  if (!(target instanceof HTMLElement)) {
    return;
  }

  const button = target.closest("button[data-view-job]");
  if (!button) {
    return;
  }

  const jobId = Number(button.getAttribute("data-view-job"));
  if (!jobId) {
    return;
  }

  await viewJobOutput(jobId);
});

scheduleForm?.addEventListener("submit", async (event) => {
  event.preventDefault();

  const scheduleServers = [...document.querySelectorAll("#schedule-server-checks input:checked")].map((x) => Number(x.value));
  if (scheduleServers.length === 0) {
    alert("Select at least one server for this schedule");
    return;
  }

  const payload = {
    name: document.getElementById("schedule_name")?.value,
    cron_expression: document.getElementById("cron_expression")?.value,
    package_manager: document.getElementById("schedule_package_manager")?.value || "auto",
    server_ids: scheduleServers,
    enabled: true,
  };

  const response = await fetch("/api/schedules", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    const error = await response.json();
    alert(error.detail || "Failed to create schedule");
    return;
  }

  window.location.reload();
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
      alert(error.detail || "Failed to toggle schedule");
      return;
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
      alert(error.detail || "Failed to delete schedule");
      return;
    }
    window.location.reload();
  });
});

if (jobsBody) {
  setInterval(loadJobs, 5000);
  loadJobs();
}
