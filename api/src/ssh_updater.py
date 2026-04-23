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

    return package_manager == "apt" and is_noisy_apt_line(line)


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


def build_update_command(package_manager: str) -> str:
    if package_manager == "apt":
        # Extra noninteractive and lock-timeout options reduce chances of hanging.
        apt_common = (
            "sudo -S env DEBIAN_FRONTEND=noninteractive "
            "apt-get -o DPkg::Lock::Timeout=120 -o Dpkg::Options::=--force-confdef "
            "-o Dpkg::Options::=--force-confold -y"
        )
        return f"{apt_common} update && {apt_common} upgrade"
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
    if any(marker in lower_output for marker in no_update_markers):
        return "No updates available"

    if package_manager == "apt":
        # Example: "5 upgraded, 0 newly installed, 0 to remove and 0 not upgraded."
        match = re.search(r"(\d+)\s+upgraded,\s+(\d+)\s+newly installed", output, flags=re.IGNORECASE)
        if match:
            upgraded = int(match.group(1))
            newly_installed = int(match.group(2))
            if upgraded == 0 and newly_installed == 0:
                return "No updates available"
            if upgraded > 0 and newly_installed == 0:
                return f"{upgraded} update{'s' if upgraded != 1 else ''} applied"
            return f"{upgraded} updated, {newly_installed} newly installed"

    # dnf/yum often don't print a simple numeric summary reliably.
    if package_manager in {"dnf", "yum"}:
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
            pkey = paramiko.pkey.load_private_key(io.StringIO(server.ssh_key.private_key))
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

        command = build_update_command(package_manager)
        job.command = command
        db.commit()
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

        output_with_steps = (
            "[summary]\n"
            + summary
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
        step_text = "\n".join(step_logs)
        job.output = f"[summary]\nUpdate failed\n\n[steps]\n{step_text}\n\n[error]\n{failure_text}".strip()
        job.summary = "Update failed"
        job.finished_at = datetime.utcnow()
        db.commit()
    finally:
        client.close()
