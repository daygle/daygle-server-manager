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
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)

    ssh_key: Mapped["SSHKey | None"] = relationship("SSHKey", back_populates="servers")
    update_jobs: Mapped[list["UpdateJob"]] = relationship("UpdateJob", back_populates="server")


class UpdateJob(Base):
    __tablename__ = "update_jobs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    server_id: Mapped[int] = mapped_column(ForeignKey("servers.id"), nullable=False)
    package_manager: Mapped[str] = mapped_column(String(20), nullable=False, default="auto")
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="pending")
    command: Mapped[str] = mapped_column(String(255), nullable=False)
    output: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)

    server: Mapped[Server] = relationship("Server", back_populates="update_jobs")


class UpdateSchedule(Base):
    __tablename__ = "update_schedules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False, unique=True)
    server_ids_raw: Mapped[str] = mapped_column("server_ids", Text, nullable=False)
    package_manager: Mapped[str] = mapped_column(String(20), nullable=False, default="auto")
    interval_minutes: Mapped[int] = mapped_column(Integer, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    next_run_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)

    @property
    def server_ids(self) -> list[int]:
        return [int(value) for value in self.server_ids_raw.split(",") if value.strip()]

    @server_ids.setter
    def server_ids(self, values: list[int]) -> None:
        self.server_ids_raw = ",".join(str(value) for value in values)
