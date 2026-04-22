from __future__ import annotations

import io
from datetime import datetime

import paramiko
from sqlalchemy.orm import Session

from .models import Server, UpdateJob


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
        return "sudo -S apt-get update && sudo -S DEBIAN_FRONTEND=noninteractive apt-get -y upgrade"
    if package_manager == "dnf":
        return "sudo -S dnf -y upgrade --refresh"
    if package_manager == "yum":
        return "sudo -S yum -y update"
    raise ValueError("Unsupported package manager")


def run_remote_command(client: paramiko.SSHClient, command: str, sudo_password: str | None) -> tuple[int, str]:
    stdin, stdout, stderr = client.exec_command(command, get_pty=True)
    if sudo_password:
        stdin.write(f"{sudo_password}\n")
        stdin.flush()

    stdout_text = stdout.read().decode("utf-8", errors="replace")
    stderr_text = stderr.read().decode("utf-8", errors="replace")
    exit_code = stdout.channel.recv_exit_status()

    combined_output = stdout_text
    if stderr_text:
        combined_output = f"{combined_output}\n\n[stderr]\n{stderr_text}".strip()
    return exit_code, combined_output


def run_update_job(db: Session, job_id: int) -> None:
    job = db.query(UpdateJob).filter(UpdateJob.id == job_id).first()
    if not job:
        return

    server = db.query(Server).filter(Server.id == job.server_id).first()
    if not server:
        job.status = "failed"
        job.output = "Server not found"
        job.finished_at = datetime.utcnow()
        db.commit()
        return

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        job.status = "running"
        job.started_at = datetime.utcnow()
        db.commit()

        connect_kwargs = {
            "hostname": server.host,
            "port": server.port,
            "username": server.username,
            "timeout": 30,
        }

        if server.auth_method == "password":
            connect_kwargs["password"] = server.password
        elif server.ssh_key_id and server.ssh_key:
            pkey = paramiko.pkey.load_private_key(io.StringIO(server.ssh_key.private_key))
            connect_kwargs["pkey"] = pkey

        client.connect(**connect_kwargs)

        package_manager = job.package_manager
        if package_manager == "auto":
            package_manager = detect_package_manager(client)
            if package_manager == "unknown":
                raise RuntimeError("Could not detect supported package manager (apt, dnf, yum)")

        command = build_update_command(package_manager)
        job.command = command
        db.commit()

        sudo_password = server.sudo_password or server.password
        exit_code, output = run_remote_command(client, command, sudo_password)

        job.status = "success" if exit_code == 0 else "failed"
        job.output = output
        job.finished_at = datetime.utcnow()
        db.commit()
    except Exception as exc:
        job.status = "failed"
        job.output = f"{type(exc).__name__}: {exc}"
        job.finished_at = datetime.utcnow()
        db.commit()
    finally:
        client.close()
