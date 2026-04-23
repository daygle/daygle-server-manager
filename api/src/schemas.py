from datetime import datetime

from pydantic import BaseModel, Field


class SSHKeyCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    private_key: str = Field(min_length=1)


class SSHKeyRead(BaseModel):
    id: int
    name: str
    public_key: str
    key_type: str
    created_at: datetime

    class Config:
        from_attributes = True


class ServerCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    host: str = Field(min_length=1, max_length=255)
    port: int = Field(default=22, ge=1, le=65535)
    username: str = Field(min_length=1, max_length=120)
    auth_method: str = Field(default="key", pattern="^(key|password)$")
    password: str | None = None
    ssh_key_id: int | None = None
    sudo_password: str | None = None


class ServerUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    host: str | None = Field(default=None, min_length=1, max_length=255)
    port: int | None = Field(default=None, ge=1, le=65535)
    username: str | None = Field(default=None, min_length=1, max_length=120)
    auth_method: str | None = Field(default=None, pattern="^(key|password)$")
    password: str | None = None
    ssh_key_id: int | None = None
    sudo_password: str | None = None


class ServerRead(BaseModel):
    id: int
    name: str
    host: str
    port: int
    username: str
    auth_method: str
    ssh_key_id: int | None
    created_at: datetime

    class Config:
        from_attributes = True


class UpdateRequest(BaseModel):
    server_ids: list[int] = Field(min_length=1)
    package_manager: str = Field(default="auto", pattern="^(auto|apt|dnf|yum)$")


class UpdateJobRead(BaseModel):
    id: int
    server_id: int
    server_name: str | None
    package_manager: str
    status: str
    command: str
    output: str | None
    summary: str | None
    started_at: datetime | None
    finished_at: datetime | None
    created_at: datetime

    class Config:
        from_attributes = True


class UpdateScheduleCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    server_ids: list[int] = Field(min_length=1)
    package_manager: str = Field(default="auto", pattern="^(auto|apt|dnf|yum)$")
    cron_expression: str = Field(min_length=5, max_length=120)
    interval_minutes: int | None = Field(default=None, ge=5, le=10080)
    enabled: bool = True


class UpdateScheduleUpdate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    server_ids: list[int] = Field(min_length=1)
    package_manager: str = Field(default="auto", pattern="^(auto|apt|dnf|yum)$")
    cron_expression: str = Field(min_length=5, max_length=120)
    enabled: bool | None = None


class UpdateScheduleRead(BaseModel):
    id: int
    name: str
    server_ids: list[int]
    package_manager: str
    cron_expression: str | None
    timezone: str | None
    interval_minutes: int
    enabled: bool
    next_run_at: datetime
    last_run_at: datetime | None
    created_at: datetime

    class Config:
        from_attributes = True
