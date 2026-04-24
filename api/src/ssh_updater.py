from __future__ import annotations

import io
import re
from datetime import datetime
from time import monotonic, sleep

import paramiko
from sqlalchemy.orm import Session

from .models import Server, UpdateJob

SSH_CONNECT_TIMEOUT_SECONDS = 30
REMOTE_COMMAND_TIMEOUT_SECONDS = 1800

APT_PROGRESS_PREFIXES = (
    "Reading package lists...",
    "Building dependency tree...",
    "Reading state information...",
    "Calculating upgrade...",
)

REDACTION_PLACEHOLDER = "[REDACTED]"


def redact_secrets(text: str, secrets: list[str | None]) -> str:
    redacted = text
    for secret in secrets:
        if secret:
            redacted = redacted.replace(secret, REDACTION_PLACEHOLDER)
    return redacted


def clean_command_output(package_manager: str, output: str) -> str:
    normalized_output = output.replace("\r", "\n")

    cleaned_lines: list[str] = []
    previous_blank = False

    for raw_line in normalized_output.splitlines():
        line = raw_line.rstrip()
        stripped = line.strip()

        if not stripped:
            if cleaned_lines and not previous_blank:
                cleaned_lines.append("")
            previous_blank = True
            continue

        if should_skip_output_line(package_manager, stripped):
            continue

        cleaned_lines.append(line)
        previous_blank = False

    return "\n".join(cleaned_lines).strip()


def should_skip_output_line(package_manager: str, line: str) -> bool:
    if line == REDACTION_PLACEHOLDER:
        return True

    return False


def is_noisy_apt_line(line: str) -> bool:
    if line == "[stderr]":
        return False

    if re.match(r"^\d+%\s+\[.*\]$", line):
        return True

    if re.match(r"^(Hit|Get|Ign):\d+\s", line):
        return True

    if re.match(r"^Fetched\s+.+\sin\s.+\(.+\/s\)$", line):
        return True

    return any(line.startswith(prefix) for prefix in APT_PROGRESS_PREFIXES)


def detect_package_manager(client: paramiko.SSHClient) -> str:
    detection_command = (
        "if command -v apt-get >/dev/null 2>&1; then echo apt; "
        "elif command -v dnf >/dev/null 2>&1; then echo dnf; "
        "elif command -v yum >/dev/null 2>&1; then echo yum; "
        "else echo unknown; fi"
    )
    _, stdout, _ = client.exec_command(detection_command)
    package_manager = stdout.read().decode("utf-8").strip()
    return package_manager


def load_private_key_for_ssh(private_key_pem: str) -> paramiko.PKey:
    key_loaders = [
        paramiko.Ed25519Key,
        paramiko.RSAKey,
        paramiko.ECDSAKey,
        paramiko.DSSKey,
    ]
    for loader in key_loaders:
        try:
            return loader.from_private_key(io.StringIO(private_key_pem))
        except Exception:
            continue
    raise ValueError("Unsupported private key format")


VALID_APT_EXTRA_STEPS = {"full_upgrade", "fix_dpkg", "fix_broken", "autoremove", "clean"}


def build_update_command(package_manager: str, apt_extra_steps: list[str] | None = None) -> str:
    if package_manager == "apt":
        extra_steps = [s for s in (apt_extra_steps or []) if s in VALID_APT_EXTRA_STEPS]

        # Extra noninteractive and lock-timeout options reduce chances of hanging.
        apt_common = (
            "sudo -S env DEBIAN_FRONTEND=noninteractive "
            "apt-get -o DPkg::Lock::Timeout=120 -o Dpkg::Options::=--force-confdef "
            "-o Dpkg::Options::=--force-confold -y"
        )

        # full_upgrade replaces the standard upgrade step; it can remove packages to resolve deps.
        upgrade_cmd = f"{apt_common} full-upgrade" if "full_upgrade" in extra_steps else f"{apt_common} upgrade"
        parts = [f"{apt_common} update", upgrade_cmd]

        if "fix_dpkg" in extra_steps:
            parts.append("sudo -S dpkg --configure -a")
        if "fix_broken" in extra_steps:
            parts.append(f"{apt_common} --fix-broken install")
        if "autoremove" in extra_steps:
            parts.append(f"{apt_common} autoremove --purge")
        if "clean" in extra_steps:
            parts.append("sudo -S apt-get clean")

        return " && ".join(parts)
    if package_manager == "dnf":
        return "sudo -S dnf -y upgrade --refresh"
    if package_manager == "yum":
        return "sudo -S yum -y update"
    raise ValueError("Unsupported package manager")


def run_remote_command(
    client: paramiko.SSHClient,
    command: str,
    sudo_password: str | None,
    timeout_seconds: int = REMOTE_COMMAND_TIMEOUT_SECONDS,
) -> tuple[int, str, bool]:
    stdin, stdout, stderr = client.exec_command(command, get_pty=True)
    if sudo_password:
        stdin.write(f"{sudo_password}\n")
        stdin.flush()

    stdout_chunks: list[str] = []
    stderr_chunks: list[str] = []
    channel = stdout.channel
    deadline = monotonic() + timeout_seconds

    while True:
        while channel.recv_ready():
            stdout_chunks.append(channel.recv(4096).decode("utf-8", errors="replace"))
        while channel.recv_stderr_ready():
            stderr_chunks.append(channel.recv_stderr(4096).decode("utf-8", errors="replace"))

        if channel.exit_status_ready():
            break

        if monotonic() >= deadline:
            channel.close()
            timeout_message = (
                f"Command timed out after {timeout_seconds}s. "
                "This usually indicates a remote prompt, package manager lock, or network stall."
            )
            combined = "".join(stdout_chunks)
            err = "".join(stderr_chunks)
            if err:
                combined = f"{combined}\n\n[stderr]\n{err}".strip()
            combined = f"{timeout_message}\n\n{combined}".strip()
            return -1, combined, True

        sleep(0.2)

    exit_code = channel.recv_exit_status()
    stdout_text = "".join(stdout_chunks)
    stderr_text = "".join(stderr_chunks)

    combined_output = stdout_text
    if stderr_text:
        combined_output = f"{combined_output}\n\n[stderr]\n{stderr_text}".strip()
    return exit_code, combined_output, False


def summarize_update_result(package_manager: str, output: str, exit_code: int, timed_out: bool) -> str:
    if timed_out:
        return "Timed out waiting for update command"
    if exit_code != 0:
        return "Update failed (see details)"

    lower_output = output.lower()

    # Common no-update phrases across apt/dnf/yum
    no_update_markers = [
        "0 upgraded, 0 newly installed",
        "nothing to do",
        "no packages marked for upgrade",
        "no packages marked for update",
        "no packages needed for security",
        "no packages needed for update",
    ]
    no_updates = any(marker in lower_output for marker in no_update_markers)

    if package_manager == "apt":
        upgraded = 0
        newly_installed = 0

        # Example: "5 upgraded, 0 newly installed, 0 to remove and 0 not upgraded."
        match = re.search(r"(\d+)\s+upgraded,\s+(\d+)\s+newly installed", output, flags=re.IGNORECASE)
        if match:
            upgraded = int(match.group(1))
            newly_installed = int(match.group(2))

        # Packages removed by autoremove
        removed = 0
        removed_match = re.search(r"(\d+)\s+(?:packages?\s+)?(?:were\s+)?removed", lower_output)
        if removed_match:
            removed = int(removed_match.group(1))

        # apt clean doesn't print a count — detect it ran from the command string presence
        cleaned_cache = "apt-get clean" in output or "apt clean" in output

        if no_updates and removed == 0 and not cleaned_cache:
            return "No updates available"

        parts = []
        if upgraded > 0 or newly_installed > 0:
            if newly_installed == 0:
                parts.append(f"{upgraded} update{'s' if upgraded != 1 else ''} applied")
            else:
                parts.append(f"{upgraded} updated, {newly_installed} newly installed")
        elif no_updates:
            parts.append("No updates available")

        if removed > 0:
            parts.append(f"{removed} unused package{'s' if removed != 1 else ''} removed")
        if cleaned_cache:
            parts.append("package cache cleared")

        return "; ".join(parts) if parts else "Update completed"

    # dnf/yum often don't print a simple numeric summary reliably.
    if package_manager in {"dnf", "yum"}:
        if no_updates:
            return "No updates available"
        if "upgraded:" in lower_output or "updated:" in lower_output:
            return "Updates applied"

    return "Update completed"


def run_update_job(db: Session, job_id: int) -> None:
    job = db.query(UpdateJob).filter(UpdateJob.id == job_id).first()
    if not job:
        return

    server = db.query(Server).filter(Server.id == job.server_id).first()
    if not server:
        job.status = "failed"
        job.output = "Server not found"
        job.summary = "Server not found"
        job.finished_at = datetime.utcnow()
        db.commit()
        return

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    step_logs: list[str] = []
    server_password = server.password
    server_sudo_password = server.sudo_password

    try:
        step_logs.append(f"[{datetime.utcnow().isoformat()}] Starting update job")
        job.status = "running"
        job.started_at = datetime.utcnow()
        db.commit()

        connect_kwargs = {
            "hostname": server.host,
            "port": server.port,
            "username": server.username,
            "timeout": SSH_CONNECT_TIMEOUT_SECONDS,
            "banner_timeout": SSH_CONNECT_TIMEOUT_SECONDS,
            "auth_timeout": SSH_CONNECT_TIMEOUT_SECONDS,
        }

        if server.auth_method == "password":
            connect_kwargs["password"] = server.password
        elif server.ssh_key_id and server.ssh_key:
            pkey = load_private_key_for_ssh(server.ssh_key.private_key)
            connect_kwargs["pkey"] = pkey

        step_logs.append(f"[{datetime.utcnow().isoformat()}] Connecting to {server.host}:{server.port} as {server.username}")
        client.connect(**connect_kwargs)
        step_logs.append(f"[{datetime.utcnow().isoformat()}] SSH connection established")

        package_manager = job.package_manager
        if package_manager == "auto":
            step_logs.append(f"[{datetime.utcnow().isoformat()}] Detecting package manager")
            package_manager = detect_package_manager(client)
            if package_manager == "unknown":
                raise RuntimeError("Could not detect supported package manager (apt, dnf, yum)")
            step_logs.append(f"[{datetime.utcnow().isoformat()}] Detected package manager: {package_manager}")

        command = build_update_command(package_manager, job.apt_extra_steps)
        job.command = command
        db.commit()
        if job.apt_extra_steps and package_manager == "apt":
            step_logs.append(f"[{datetime.utcnow().isoformat()}] Extra apt steps requested: {', '.join(job.apt_extra_steps)}")
        step_logs.append(f"[{datetime.utcnow().isoformat()}] Running update command")

        sudo_password = server.sudo_password or server.password
        exit_code, output, timed_out = run_remote_command(client, command, sudo_password)
        output = redact_secrets(output, [server_password, server_sudo_password])
        summary = summarize_update_result(package_manager, output, exit_code, timed_out)
        cleaned_output = clean_command_output(package_manager, output)

        # Common lock wording for apt/dpkg. Keep message concise and actionable.
        lock_hint = ""
        if "Could not get lock" in output or "Unable to acquire the dpkg frontend lock" in output:
            lock_hint = (
                "\n\n[hint]\nPackage manager lock detected. "
                "Another update process may be running on the server."
            )

        apt_extra_steps_section = ""
        if job.apt_extra_steps and package_manager == "apt":
            step_labels = {
                "full_upgrade": "Use full-upgrade instead of upgrade",
                "fix_dpkg": "Fix interrupted installs (dpkg --configure -a)",
                "fix_broken": "Fix broken dependencies (apt --fix-broken install)",
                "autoremove": "Remove unused packages (autoremove --purge)",
                "clean": "Clear package cache (apt clean)",
            }
            steps_detail = "\n".join(
                f"- {step_labels.get(s, s)}" for s in job.apt_extra_steps
            )
            apt_extra_steps_section = f"\n\n[apt-extra-steps]\n{steps_detail}"

        output_with_steps = (
            "[summary]\n"
            + summary
            + apt_extra_steps_section
            + "\n\n[steps]\n"
            + "\n".join(step_logs)
            + "\n\n[command-output]\n"
            + (cleaned_output or "No relevant command output.")
            + lock_hint
        ).strip()

        job.status = "success" if exit_code == 0 and not timed_out else "failed"
        job.output = output_with_steps
        job.summary = summary
        job.finished_at = datetime.utcnow()
        db.commit()
    except Exception as exc:
        # If the first write failed (e.g., DB constraint), clear transaction state first.
        db.rollback()
        job.status = "failed"
        failure_text = f"{type(exc).__name__}: {exc}"
        failure_text = redact_secrets(failure_text, [server_password, server_sudo_password])
        hint_text = ""
        if isinstance(exc, paramiko.AuthenticationException):
            hint_text = (
                "\n\n[hint]\n"
                "SSH authentication failed. Verify the selected username, ensure the matching public key is in "
                "~/.ssh/authorized_keys for that user, and confirm SSH directory/file permissions (700 for ~/.ssh, "
                "600 for authorized_keys). If using root, also check sshd_config allows key-based root login "
                "(PermitRootLogin prohibit-password or yes)."
            )
        step_text = "\n".join(step_logs)
        job.output = f"[summary]\nUpdate failed\n\n[steps]\n{step_text}\n\n[error]\n{failure_text}{hint_text}".strip()
        job.summary = "Update failed"
        job.finished_at = datetime.utcnow()
        db.commit()
    finally:
        client.close()
