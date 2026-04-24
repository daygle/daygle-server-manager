from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    username: Mapped[str] = mapped_column(String(120), nullable=False, unique=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    first_name: Mapped[str | None] = mapped_column(String(120), nullable=True)
    last_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    is_admin: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    date_format: Mapped[str | None] = mapped_column(String(32), nullable=True)
    timezone: Mapped[str | None] = mapped_column(String(64), nullable=True)
    theme_preference: Mapped[str | None] = mapped_column(String(16), nullable=True)
    avatar_color: Mapped[str | None] = mapped_column(String(16), nullable=True)
    page_size: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)
    last_login: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class SSHKey(Base):
    __tablename__ = "ssh_keys"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False, unique=True)
    private_key: Mapped[str] = mapped_column(Text, nullable=False)
    public_key: Mapped[str] = mapped_column(Text, nullable=False)
    key_type: Mapped[str] = mapped_column(String(20), nullable=False, default="ed25519")
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)

    servers: Mapped[list["Server"]] = relationship("Server", back_populates="ssh_key")


class Server(Base):
    __tablename__ = "servers"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False, unique=True)
    host: Mapped[str] = mapped_column(String(255), nullable=False)
    port: Mapped[int] = mapped_column(Integer, nullable=False, default=22)
    username: Mapped[str] = mapped_column(String(120), nullable=False)
    auth_method: Mapped[str] = mapped_column(String(20), nullable=False, default="key")
    password: Mapped[str | None] = mapped_column(String(255), nullable=True)
    ssh_key_id: Mapped[int | None] = mapped_column(ForeignKey("ssh_keys.id"), nullable=True)
    sudo_password: Mapped[str | None] = mapped_column(String(255), nullable=True)
    last_health_status: Mapped[str | None] = mapped_column(String(20), nullable=True)
    last_health_check_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_health_message: Mapped[str | None] = mapped_column(String(255), nullable=True)
    last_cpu_usage: Mapped[float | None] = mapped_column(nullable=True)
    last_ram_usage: Mapped[float | None] = mapped_column(nullable=True)
    last_storage_usage: Mapped[float | None] = mapped_column(nullable=True)
    last_load_avg: Mapped[float | None] = mapped_column(nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)

    ssh_key: Mapped["SSHKey | None"] = relationship("SSHKey", back_populates="servers")
    update_jobs: Mapped[list["UpdateJob"]] = relationship("UpdateJob", back_populates="server")


class UpdateJob(Base):
    __tablename__ = "update_jobs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    server_id: Mapped[int] = mapped_column(ForeignKey("servers.id"), nullable=False)
    schedule_id: Mapped[int | None] = mapped_column(ForeignKey("update_schedules.id"), nullable=True)
    job_type: Mapped[str] = mapped_column(String(20), nullable=False, default="manual")
    package_manager: Mapped[str] = mapped_column(String(20), nullable=False, default="auto")
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="pending")
    command: Mapped[str] = mapped_column(Text, nullable=False)
    output: Mapped[str | None] = mapped_column(Text, nullable=True)
    summary: Mapped[str | None] = mapped_column(String(255), nullable=True)
    apt_extra_steps_raw: Mapped[str] = mapped_column("apt_extra_steps", Text, nullable=False, default="")
    alert_only: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)

    server: Mapped[Server] = relationship("Server", back_populates="update_jobs")

    @property
    def server_name(self) -> str | None:
        return self.server.name if self.server else None

    @property
    def apt_extra_steps(self) -> list[str]:
        return [v for v in self.apt_extra_steps_raw.split(",") if v.strip()]

    @apt_extra_steps.setter
    def apt_extra_steps(self, values: list[str]) -> None:
        self.apt_extra_steps_raw = ",".join(values)


class UpdateSchedule(Base):
    __tablename__ = "update_schedules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False, unique=True)
    server_ids_raw: Mapped[str] = mapped_column("server_ids", Text, nullable=False)
    package_manager: Mapped[str] = mapped_column(String(20), nullable=False, default="auto")
    cron_expression: Mapped[str | None] = mapped_column(String(120), nullable=True)
    timezone: Mapped[str | None] = mapped_column(String(64), nullable=True)
    interval_minutes: Mapped[int] = mapped_column(Integer, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    auto_disable_on_failures: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    failure_threshold: Mapped[int | None] = mapped_column(Integer, nullable=True)
    disabled_server_ids_raw: Mapped[str] = mapped_column("disabled_server_ids", Text, nullable=False, default="")
    apt_extra_steps_raw: Mapped[str] = mapped_column("apt_extra_steps", Text, nullable=False, default="")
    alert_only: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    next_run_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)

    @property
    def server_ids(self) -> list[int]:
        return [int(value) for value in self.server_ids_raw.split(",") if value.strip()]

    @server_ids.setter
    def server_ids(self, values: list[int]) -> None:
        self.server_ids_raw = ",".join(str(value) for value in values)

    @property
    def disabled_server_ids(self) -> list[int]:
        return [int(value) for value in self.disabled_server_ids_raw.split(",") if value.strip()]

    @disabled_server_ids.setter
    def disabled_server_ids(self, values: list[int]) -> None:
        self.disabled_server_ids_raw = ",".join(str(value) for value in values)

    @property
    def apt_extra_steps(self) -> list[str]:
        return [v for v in self.apt_extra_steps_raw.split(",") if v.strip()]

    @apt_extra_steps.setter
    def apt_extra_steps(self, values: list[str]) -> None:
        self.apt_extra_steps_raw = ",".join(values)


class AppSetting(Base):
    __tablename__ = "app_settings"

    key: Mapped[str] = mapped_column(String(120), primary_key=True)
    value: Mapped[str] = mapped_column(Text, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)
    actor_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    actor_username: Mapped[str | None] = mapped_column(String(120), nullable=True)
    action: Mapped[str] = mapped_column(String(120), nullable=False)
    target_type: Mapped[str | None] = mapped_column(String(60), nullable=True)
    target_id: Mapped[str | None] = mapped_column(String(120), nullable=True)
    target_label: Mapped[str | None] = mapped_column(String(255), nullable=True)
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(60), nullable=True)


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    level: Mapped[str] = mapped_column(String(20), nullable=False, default="error")
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    source_type: Mapped[str | None] = mapped_column(String(60), nullable=True)
    source_id: Mapped[str | None] = mapped_column(String(120), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
