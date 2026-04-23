(function () {
  if (window.createToast) {
    return;
  }

  function getContainer() {
    let container = document.getElementById("toastContainer");
    if (!container) {
      container = document.createElement("div");
      container.id = "toastContainer";
      container.className = "toast-container";
      document.body.appendChild(container);
    }
    return container;
  }

  function normalizeType(type) {
    const value = String(type || "info").toLowerCase();
    if (["success", "error", "warning", "info"].includes(value)) {
      return value;
    }
    return "info";
  }

  function removeToast(toast) {
    if (!toast || !toast.parentNode) {
      return;
    }
    toast.parentNode.removeChild(toast);
  }

  function _createToast(message, type) {
    const safeType = normalizeType(type);
    const container = getContainer();

    const toast = document.createElement("div");
    toast.className = `toast-notification toast-${safeType}`;
    toast.setAttribute("role", "status");
    toast.setAttribute("aria-live", "polite");

    const body = document.createElement("div");
    body.className = "toast-message";
    body.textContent = String(message || "");

    const closeButton = document.createElement("button");
    closeButton.className = "toast-close";
    closeButton.type = "button";
    closeButton.setAttribute("aria-label", "Close notification");
    closeButton.innerHTML = "<i class=\"fas fa-times\"></i>";
    closeButton.addEventListener("click", function () {
      removeToast(toast);
    });

    toast.appendChild(body);
    toast.appendChild(closeButton);
    container.appendChild(toast);

    window.setTimeout(function () {
      removeToast(toast);
    }, 3000);

    return toast;
  }

  function processQueue() {
    const queue = window._toastQueue || [];
    for (let i = 0; i < queue.length; i += 1) {
      try {
        _createToast(queue[i].message, queue[i].type);
      } catch (error) {
        // Ignore malformed queued items.
      }
    }
    window._toastQueue = [];
  }

  window.createToast = _createToast;
  window.showToast = function (message, type) {
    return window.createToast(message, type);
  };

  if (document.readyState === "complete" || document.readyState === "interactive") {
    processQueue();
  } else {
    document.addEventListener("DOMContentLoaded", processQueue);
  }

  if (window.__initialFlash) {
    try {
      _createToast(window.__initialFlash.message || window.__initialFlash, window.__initialFlash.type || "info");
    } catch (error) {
      // Ignore initial flash render issues.
    }
    window.__initialFlash = null;
  }
})();
