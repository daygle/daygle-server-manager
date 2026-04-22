const sidebar = document.getElementById("sidebar");
const sidebarBrand = document.getElementById("sidebarBrand");
const sidebarMobileToggle = document.getElementById("sidebarMobileToggle");

const serverForm = document.getElementById("server-form");
const runForm = document.getElementById("run-form");
const jobsBody = document.getElementById("jobs-body");
const latestLog = document.getElementById("latest-log");
const authMethod = document.getElementById("auth_method");
const passwordLabel = document.getElementById("password_label");
const keyLabel = document.getElementById("key_label");

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
  const isPassword = authMethod.value === "password";
  passwordLabel.classList.toggle("hidden", !isPassword);
  keyLabel.classList.toggle("hidden", isPassword);
}

authMethod?.addEventListener("change", toggleAuthFields);
if (authMethod && passwordLabel && keyLabel) {
  toggleAuthFields();
}

serverForm?.addEventListener("submit", async (event) => {
  event.preventDefault();
  const formData = new FormData(serverForm);

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

  const response = await fetch("/api/servers", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    const error = await response.json();
    alert(error.detail || "Failed to add server");
    return;
  }

  window.location.reload();
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

async function loadJobs() {
  if (!jobsBody || !latestLog) {
    return;
  }

  const response = await fetch("/api/updates?limit=30");
  if (!response.ok) {
    return;
  }

  const jobs = await response.json();
  jobsBody.innerHTML = jobs
    .map(
      (job) => `
      <tr data-job-id="${job.id}">
        <td>${job.id}</td>
        <td>${job.server_id}</td>
        <td>${renderStatus(job.status)}</td>
        <td>${job.package_manager}</td>
        <td>${job.created_at}</td>
        <td>${job.started_at || "-"}</td>
        <td>${job.finished_at || "-"}</td>
      </tr>
    `
    )
    .join("");

  if (jobs.length > 0) {
    latestLog.textContent = jobs[0].output || "No output yet for latest job.";
  }
}

if (jobsBody) {
  setInterval(loadJobs, 5000);
  loadJobs();
}
