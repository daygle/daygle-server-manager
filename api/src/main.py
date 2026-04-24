from __future__ import annotations

import asyncio
import io
import json
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from pathlib import Path
import secrets
import smtplib
from threading import Thread
from time import monotonic, sleep
from urllib.parse import urlencode
from zoneinfo import ZoneInfo, available_timezones

from fastapi import Depends, FastAPI, Form, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from croniter import croniter
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import paramiko
from sqlalchemy import String, func, or_, text
from sqlalchemy.orm import Session
from starlette.middleware.sessions import SessionMiddleware

from .config import get_setting
from .database import Base, SessionLocal, engine, get_db
from .models import Alert, AppSetting, AuditLog, SSHKey, Server, UpdateJob, UpdateSchedule, User
from .schemas import (
    SSHKeyCreate,
    ServerConnectionTestRequest,
    SSHKeyRead,
    ServerCreate,
    ServerRead,
    ServerUpdate,
    UpdateJobRead,
    UpdateRequest,
    UpdateScheduleCreate,
    UpdateScheduleUpdate,
    UpdateScheduleRead,
)
from .security import hash_password, verify_password
from .ssh_updater import run_check_job, run_update_job

BASE_DIR = Path(__file__).resolve().parent.parent

app = FastAPI(title="Daygle Server Manager", version="0.1.0")

app.add_middleware(
    SessionMiddleware,
    secret_key=get_setting("SESSION_SECRET"),
    max_age=60 * 60 * 24 * 30,
)

app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

DATE_FORMAT_SETTING_KEY = "date_format"
TIMEZONE_SETTING_KEY = "timezone"
HISTORY_RETENTION_SETTING_KEY = "history_retention_days"
UPDATE_JOB_RETENTION_SETTING_KEY = "update_job_retention_days"
AUDIT_RETENTION_SETTING_KEY = "audit_retention_days"
LOGIN_TIMEOUT_SETTING_KEY = "login_timeout_minutes"
EMAIL_ALERTS_ENABLED_SETTING_KEY = "email_alerts_enabled"
SMTP_HOST_SETTING_KEY = "smtp_host"
SMTP_PORT_SETTING_KEY = "smtp_port"
SMTP_USERNAME_SETTING_KEY = "smtp_username"
SMTP_PASSWORD_SETTING_KEY = "smtp_password"
SMTP_USE_TLS_SETTING_KEY = "smtp_use_tls"
SMTP_FROM_SETTING_KEY = "smtp_from"
DEFAULT_THEME_SETTING_KEY = "default_theme"
PAGE_SIZE_SETTING_KEY = "page_size"
APT_LOCK_TIMEOUT_SETTING_KEY = "apt_lock_timeout_seconds"
SSH_CONNECT_TIMEOUT_SETTING_KEY = "ssh_connect_timeout_seconds"
REMOTE_COMMAND_TIMEOUT_SETTING_KEY = "remote_command_timeout_seconds"
SMTP_TIMEOUT_SETTING_KEY = "smtp_timeout_seconds"
SCHEDULE_POLL_INTERVAL_SETTING_KEY = "schedule_poll_interval_seconds"
DEFAULT_APT_LOCK_TIMEOUT_SECONDS = 120
MAX_APT_LOCK_TIMEOUT_SECONDS = 3600
DEFAULT_SSH_CONNECT_TIMEOUT_SECONDS = 30
MAX_SSH_CONNECT_TIMEOUT_SECONDS = 300
DEFAULT_REMOTE_COMMAND_TIMEOUT_SECONDS = 1800
MAX_REMOTE_COMMAND_TIMEOUT_SECONDS = 14400
DEFAULT_SMTP_TIMEOUT_SECONDS = 15
MAX_SMTP_TIMEOUT_SECONDS = 120
DEFAULT_SCHEDULE_POLL_INTERVAL_SECONDS = 30
MAX_SCHEDULE_POLL_INTERVAL_SECONDS = 300
SSH_TERMINAL_TOKEN_TTL_SECONDS = 300
DEFAULT_DATE_FORMAT = "iso-24"
DEFAULT_TIMEZONE = "UTC"
DEFAULT_THEME = "system"
DEFAULT_PAGE_SIZE = 50
VALID_PAGE_SIZES = {25, 50, 100, 200}
DEFAULT_HISTORY_RETENTION_DAYS = 90
MAX_HISTORY_RETENTION_DAYS = 3650
DEFAULT_LOGIN_TIMEOUT_MINUTES = 480
MAX_LOGIN_TIMEOUT_MINUTES = 43200
DEFAULT_EMAIL_ALERTS_ENABLED = True
ALERT_LEVELS = {"info", "warning", "error"}
THEME_OPTIONS = {"system", "light", "dark"}
USER_DATE_FORMAT_GLOBAL = "global"
USER_TIMEZONE_GLOBAL = "global"
USER_THEME_GLOBAL = "global"
DEFAULT_AVATAR_COLOR = "#007bff"
AVATAR_COLOR_OPTIONS: list[tuple[str, str]] = [
    ("#007bff", "Blue"),
    ("#28a745", "Green"),
    ("#dc3545", "Red"),
    ("#ffc107", "Yellow"),
    ("#6f42c1", "Purple"),
    ("#e83e8c", "Pink"),
    ("#fd7e14", "Orange"),
    ("#20c997", "Teal"),
    ("#6c757d", "Gray"),
    ("#17a2b8", "Cyan"),
]
AVATAR_COLOR_OPTION_KEYS = {value.lower() for value, _ in AVATAR_COLOR_OPTIONS}
DATE_FORMAT_OPTIONS: list[tuple[str, str, str]] = [
    ("iso-24", "YYYY-MM-DD HH:MM:SS", "%Y-%m-%d %H:%M:%S"),
    ("us-24", "MM/DD/YYYY HH:MM:SS", "%m/%d/%Y %H:%M:%S"),
    ("eu-24", "DD/MM/YYYY HH:MM:SS", "%d/%m/%Y %H:%M:%S"),
    ("month-name", "DD Mon YYYY HH:MM:SS", "%d %b %Y %H:%M:%S"),
]
DATE_FORMAT_MAP = {key: pattern for key, _, pattern in DATE_FORMAT_OPTIONS}
ssh_terminal_tokens: dict[str, tuple[int, datetime]] = {}


def is_country_city_timezone(timezone_name: str) -> bool:
    if timezone_name == DEFAULT_TIMEZONE:
        return True
    if "/" not in timezone_name:
        return False
    excluded_prefixes = ("Etc/", "posix/", "right/", "SystemV/")
    return not timezone_name.startswith(excluded_prefixes)


_ALL_TIMEZONES = sorted(tz for tz in available_timezones() if is_country_city_timezone(tz))
if DEFAULT_TIMEZONE in _ALL_TIMEZONES:
    _ALL_TIMEZONES.remove(DEFAULT_TIMEZONE)
TIMEZONE_OPTIONS: list[tuple[str, str]] = [(DEFAULT_TIMEZONE, DEFAULT_TIMEZONE)] + [
    (timezone_name, timezone_name) for timezone_name in _ALL_TIMEZONES
]
TIMEZONE_OPTION_KEYS = {value for value, _ in TIMEZONE_OPTIONS}


@app.on_event("startup")
def on_startup() -> None:
    Base.metadata.create_all(bind=engine)
    ensure_schema_columns()
    db = SessionLocal()
    try:
        app.state.date_format = get_date_format_setting(db)
        app.state.timezone = get_timezone_setting(db)
        app.state.default_theme = get_default_theme_setting(db)
        app.state.login_timeout_minutes = get_login_timeout_minutes(db)
        app.state.email_alerts_enabled = get_email_alerts_enabled(db)
        app.state.page_size = get_page_size_setting(db)
    finally:
        db.close()
    if not getattr(app.state, "schedule_worker_started", False):
        app.state.schedule_worker_started = True
        thread = Thread(target=run_schedule_loop, daemon=True)
        thread.start()


def ensure_schema_columns() -> None:
    # Add compatibility columns/types on existing databases without requiring migrations.
    statements = [
        "ALTER TABLE servers ADD COLUMN IF NOT EXISTS last_health_status VARCHAR(20)",
        "ALTER TABLE servers ADD COLUMN IF NOT EXISTS last_health_check_at TIMESTAMP",
        "ALTER TABLE servers ADD COLUMN IF NOT EXISTS last_health_message VARCHAR(255)",
        "ALTER TABLE servers ADD COLUMN IF NOT EXISTS last_cpu_usage DOUBLE PRECISION",
        "ALTER TABLE servers ADD COLUMN IF NOT EXISTS last_ram_usage DOUBLE PRECISION",
        "ALTER TABLE servers ADD COLUMN IF NOT EXISTS last_storage_usage DOUBLE PRECISION",
        "ALTER TABLE servers ADD COLUMN IF NOT EXISTS last_load_avg DOUBLE PRECISION",
        "ALTER TABLE servers ADD COLUMN IF NOT EXISTS last_load_avg_5 DOUBLE PRECISION",
        "ALTER TABLE servers ADD COLUMN IF NOT EXISTS last_load_avg_15 DOUBLE PRECISION",
        "ALTER TABLE servers ADD COLUMN IF NOT EXISTS alert_cpu_threshold INTEGER NOT NULL DEFAULT 90",
        "ALTER TABLE servers ADD COLUMN IF NOT EXISTS alert_ram_threshold INTEGER NOT NULL DEFAULT 90",
        "ALTER TABLE servers ADD COLUMN IF NOT EXISTS alert_storage_threshold INTEGER NOT NULL DEFAULT 90",
        "ALTER TABLE servers ADD COLUMN IF NOT EXISTS alert_load_avg_threshold DOUBLE PRECISION NOT NULL DEFAULT 0",
        "ALTER TABLE servers ADD COLUMN IF NOT EXISTS alert_load_avg_5_threshold DOUBLE PRECISION NOT NULL DEFAULT 0",
        "ALTER TABLE servers ADD COLUMN IF NOT EXISTS alert_load_avg_15_threshold DOUBLE PRECISION NOT NULL DEFAULT 0",
        "ALTER TABLE servers ADD COLUMN IF NOT EXISTS needs_reboot BOOLEAN NOT NULL DEFAULT FALSE",
        "ALTER TABLE update_schedules ADD COLUMN IF NOT EXISTS cron_expression VARCHAR(120)",
        "ALTER TABLE update_schedules ADD COLUMN IF NOT EXISTS timezone VARCHAR(64)",
        "ALTER TABLE update_jobs ALTER COLUMN command TYPE TEXT",
        "ALTER TABLE update_jobs ADD COLUMN IF NOT EXISTS summary VARCHAR(255)",
        "ALTER TABLE update_jobs ADD COLUMN IF NOT EXISTS job_type VARCHAR(20) DEFAULT 'manual'",
        "ALTER TABLE update_jobs ADD COLUMN IF NOT EXISTS schedule_id INTEGER",
        "UPDATE update_jobs SET job_type = 'manual' WHERE job_type IS NULL OR job_type = ''",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS date_format VARCHAR(32)",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS timezone VARCHAR(64)",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS theme_preference VARCHAR(16)",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_color VARCHAR(16)",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS page_size INTEGER",
        "ALTER TABLE update_schedules ADD COLUMN IF NOT EXISTS auto_disable_on_failures BOOLEAN NOT NULL DEFAULT FALSE",
        "ALTER TABLE update_schedules ADD COLUMN IF NOT EXISTS failure_threshold INTEGER",
        "ALTER TABLE update_schedules ADD COLUMN IF NOT EXISTS disabled_server_ids TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE update_schedules ADD COLUMN IF NOT EXISTS apt_extra_steps TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE update_jobs ADD COLUMN IF NOT EXISTS apt_extra_steps TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE update_schedules ADD COLUMN IF NOT EXISTS alert_only BOOLEAN NOT NULL DEFAULT FALSE",
        "ALTER TABLE update_jobs ADD COLUMN IF NOT EXISTS alert_only BOOLEAN NOT NULL DEFAULT FALSE",
        (
            "CREATE TABLE IF NOT EXISTS audit_logs ("
            "id SERIAL PRIMARY KEY, "
            "timestamp TIMESTAMP NOT NULL DEFAULT NOW(), "
            "actor_id INTEGER, "
            "actor_username VARCHAR(120), "
            "action VARCHAR(120) NOT NULL, "
            "target_type VARCHAR(60), "
            "target_id VARCHAR(120), "
            "target_label VARCHAR(255), "
            "detail TEXT, "
            "ip_address VARCHAR(60))"
        ),
        (
            "CREATE TABLE IF NOT EXISTS alerts ("
            "id SERIAL PRIMARY KEY, "
            "level VARCHAR(20) NOT NULL DEFAULT 'error', "
            "title VARCHAR(255) NOT NULL, "
            "message TEXT NOT NULL, "
            "source_type VARCHAR(60), "
            "source_id VARCHAR(120), "
            "created_at TIMESTAMP NOT NULL DEFAULT NOW(), "
            "acknowledged_at TIMESTAMP NULL)"
        ),
    ]
    with engine.begin() as conn:
        for statement in statements:
            conn.execute(text(statement))


def log_audit(
    db: Session,
    action: str,
    request: Request | None = None,
    actor: User | None = None,
    target_type: str | None = None,
    target_id: str | int | None = None,
    target_label: str | None = None,
    detail: str | None = None,
) -> None:
    ip = None
    if request:
        forwarded = request.headers.get("x-forwarded-for")
        ip = forwarded.split(",")[0].strip() if forwarded else (request.client.host if request.client else None)
    entry = AuditLog(
        action=action,
        actor_id=actor.id if actor else None,
        actor_username=actor.username if actor else None,
        target_type=target_type,
        target_id=str(target_id) if target_id is not None else None,
        target_label=target_label,
        detail=detail,
        ip_address=ip,
    )
    db.add(entry)
    db.commit()


def get_next_schedule_run(schedule: UpdateSchedule, from_time: datetime | None = None) -> datetime:
    schedule_timezone_name = normalize_timezone(getattr(schedule, "timezone", None)) or get_active_timezone()
    schedule_timezone = ZoneInfo(schedule_timezone_name)

    if from_time is None:
        base_utc = datetime.utcnow().replace(tzinfo=timezone.utc)
    elif from_time.tzinfo is None:
        base_utc = from_time.replace(tzinfo=timezone.utc)
    else:
        base_utc = from_time.astimezone(timezone.utc)

    base_local = base_utc.astimezone(schedule_timezone)
    if schedule.cron_expression:
        next_local = croniter(schedule.cron_expression, base_local).get_next(datetime)
    else:
        next_local = base_local + timedelta(minutes=schedule.interval_minutes)

    if next_local.tzinfo is None:
        next_local = next_local.replace(tzinfo=schedule_timezone)
    return next_local.astimezone(timezone.utc).replace(tzinfo=None)


def normalize_date_format(value: str | None) -> str | None:
    if not value:
        return None
    clean_value = value.strip()
    return clean_value if clean_value in DATE_FORMAT_MAP else None


def normalize_timezone(value: str | None) -> str | None:
    if not value:
        return None
    clean_value = value.strip()
    try:
        ZoneInfo(clean_value)
    except Exception:
        return None
    return clean_value


def normalize_theme(value: str | None) -> str | None:
    if not value:
        return None
    clean_value = value.strip().lower()
    return clean_value if clean_value in THEME_OPTIONS else None


def normalize_avatar_color(value: str | None) -> str | None:
    if not value:
        return None
    clean_value = value.strip().lower()
    return clean_value if clean_value in AVATAR_COLOR_OPTION_KEYS else None


def normalize_history_retention_days(value: str | int | None) -> int | None:
    if value is None:
        return None
    try:
        retention_days = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    if retention_days < 0 or retention_days > MAX_HISTORY_RETENTION_DAYS:
        return None
    return retention_days


def normalize_login_timeout_minutes(value: str | int | None) -> int | None:
    if value is None:
        return None
    try:
        timeout_minutes = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    if timeout_minutes < 1 or timeout_minutes > MAX_LOGIN_TIMEOUT_MINUTES:
        return None
    return timeout_minutes


def get_app_setting(db: Session, key: str, default: str) -> str:
    setting = db.query(AppSetting).filter(AppSetting.key == key).first()
    if not setting:
        return default
    return setting.value


def set_app_setting(db: Session, key: str, value: str) -> None:
    setting = db.query(AppSetting).filter(AppSetting.key == key).first()
    if setting:
        setting.value = value
    else:
        setting = AppSetting(key=key, value=value)
        db.add(setting)
    db.commit()


def get_date_format_setting(db: Session) -> str:
    stored_value = get_app_setting(db, DATE_FORMAT_SETTING_KEY, DEFAULT_DATE_FORMAT)
    normalized = normalize_date_format(stored_value)
    return normalized or DEFAULT_DATE_FORMAT


def get_timezone_setting(db: Session) -> str:
    stored_value = get_app_setting(db, TIMEZONE_SETTING_KEY, DEFAULT_TIMEZONE)
    normalized = normalize_timezone(stored_value)
    if normalized and normalized in TIMEZONE_OPTION_KEYS:
        return normalized
    return DEFAULT_TIMEZONE


def get_default_theme_setting(db: Session) -> str:
    stored_value = get_app_setting(db, DEFAULT_THEME_SETTING_KEY, DEFAULT_THEME)
    normalized = normalize_theme(stored_value)
    return normalized or DEFAULT_THEME


def format_datetime_value(value: datetime | None, date_format: str, timezone_name: str) -> str:
    if value is None:
        return "-"

    if value.tzinfo is None:
        value_utc = value.replace(tzinfo=timezone.utc)
    else:
        value_utc = value.astimezone(timezone.utc)

    local_value = value_utc.astimezone(ZoneInfo(timezone_name))
    pattern = DATE_FORMAT_MAP.get(date_format, DATE_FORMAT_MAP[DEFAULT_DATE_FORMAT])
    return local_value.strftime(pattern)


def get_active_date_format() -> str:
    return getattr(app.state, "date_format", DEFAULT_DATE_FORMAT)


def get_active_timezone() -> str:
    return getattr(app.state, "timezone", DEFAULT_TIMEZONE)


def get_active_default_theme() -> str:
    return getattr(app.state, "default_theme", DEFAULT_THEME)


def get_effective_date_format(current_user: User) -> str:
    user_format = normalize_date_format(current_user.date_format)
    if user_format:
        return user_format
    return get_active_date_format()


def get_effective_timezone(current_user: User) -> str:
    user_timezone = normalize_timezone(current_user.timezone)
    if user_timezone and user_timezone in TIMEZONE_OPTION_KEYS:
        return user_timezone
    return get_active_timezone()


def get_effective_theme(current_user: User) -> str:
    user_theme = normalize_theme(current_user.theme_preference)
    if user_theme and user_theme != DEFAULT_THEME:
        return user_theme
    return get_active_default_theme()


def get_history_retention_days(db: Session) -> int:
    raw = get_app_setting(db, HISTORY_RETENTION_SETTING_KEY, str(DEFAULT_HISTORY_RETENTION_DAYS))
    normalized = normalize_history_retention_days(raw)
    return normalized if normalized is not None else DEFAULT_HISTORY_RETENTION_DAYS


def get_update_job_retention_days(db: Session) -> int:
    legacy_value = get_history_retention_days(db)
    raw = get_app_setting(db, UPDATE_JOB_RETENTION_SETTING_KEY, str(legacy_value))
    normalized = normalize_history_retention_days(raw)
    return normalized if normalized is not None else legacy_value


def get_audit_retention_days(db: Session) -> int:
    legacy_value = get_history_retention_days(db)
    raw = get_app_setting(db, AUDIT_RETENTION_SETTING_KEY, str(legacy_value))
    normalized = normalize_history_retention_days(raw)
    return normalized if normalized is not None else legacy_value


def get_login_timeout_minutes(db: Session) -> int:
    raw = get_app_setting(db, LOGIN_TIMEOUT_SETTING_KEY, str(DEFAULT_LOGIN_TIMEOUT_MINUTES))
    normalized = normalize_login_timeout_minutes(raw)
    return normalized if normalized is not None else DEFAULT_LOGIN_TIMEOUT_MINUTES


def get_active_login_timeout_minutes() -> int:
    return getattr(app.state, "login_timeout_minutes", DEFAULT_LOGIN_TIMEOUT_MINUTES)


def parse_bool_setting(value: str | bool | None, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def normalize_alert_level(value: str | None) -> str:
    if not value:
        return "error"
    clean = value.strip().lower()
    return clean if clean in ALERT_LEVELS else "error"


def get_smtp_setting(db: Session, key: str, config_key: str, fallback: str = "") -> str:
    setting = db.query(AppSetting).filter(AppSetting.key == key).first()
    if setting is not None:
        return setting.value
    return get_setting(config_key, fallback)


def get_email_alerts_enabled(db: Session) -> bool:
    raw = get_app_setting(
        db,
        EMAIL_ALERTS_ENABLED_SETTING_KEY,
        "true" if DEFAULT_EMAIL_ALERTS_ENABLED else "false",
    )
    return parse_bool_setting(raw, DEFAULT_EMAIL_ALERTS_ENABLED)


def get_active_email_alerts_enabled() -> bool:
    return getattr(app.state, "email_alerts_enabled", DEFAULT_EMAIL_ALERTS_ENABLED)


def normalize_page_size(value: str | int | None) -> int | None:
    if value is None:
        return None
    try:
        size = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    return size if size in VALID_PAGE_SIZES else None


def get_page_size_setting(db: Session) -> int:
    raw = get_app_setting(db, PAGE_SIZE_SETTING_KEY, str(DEFAULT_PAGE_SIZE))
    normalized = normalize_page_size(raw)
    return normalized if normalized is not None else DEFAULT_PAGE_SIZE


def get_active_page_size() -> int:
    return getattr(app.state, "page_size", DEFAULT_PAGE_SIZE)


def get_user_page_size(user: User) -> int:
    if user and user.page_size and user.page_size in VALID_PAGE_SIZES:
        return user.page_size
    return DEFAULT_PAGE_SIZE


def get_effective_page_size(user: User | None, db: Session | None = None) -> int:
    if user and user.page_size and user.page_size in VALID_PAGE_SIZES:
        return user.page_size
    if db:
        return get_page_size_setting(db)
    return get_active_page_size()


def normalize_apt_lock_timeout(value: str | int | None) -> int | None:
    """Return 10–3600 seconds. None means invalid."""
    if value is None:
        return None
    try:
        v = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    return v if 10 <= v <= MAX_APT_LOCK_TIMEOUT_SECONDS else None


def get_apt_lock_timeout(db: Session) -> int:
    raw = get_app_setting(db, APT_LOCK_TIMEOUT_SETTING_KEY, str(DEFAULT_APT_LOCK_TIMEOUT_SECONDS))
    normalized = normalize_apt_lock_timeout(raw)
    return normalized if normalized is not None else DEFAULT_APT_LOCK_TIMEOUT_SECONDS


def normalize_ssh_connect_timeout(value: str | int | None) -> int | None:
    if value is None:
        return None
    try:
        v = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    return v if 5 <= v <= MAX_SSH_CONNECT_TIMEOUT_SECONDS else None


def get_ssh_connect_timeout(db: Session) -> int:
    raw = get_app_setting(db, SSH_CONNECT_TIMEOUT_SETTING_KEY, str(DEFAULT_SSH_CONNECT_TIMEOUT_SECONDS))
    normalized = normalize_ssh_connect_timeout(raw)
    return normalized if normalized is not None else DEFAULT_SSH_CONNECT_TIMEOUT_SECONDS


def normalize_remote_command_timeout(value: str | int | None) -> int | None:
    if value is None:
        return None
    try:
        v = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    return v if 30 <= v <= MAX_REMOTE_COMMAND_TIMEOUT_SECONDS else None


def get_remote_command_timeout(db: Session) -> int:
    raw = get_app_setting(db, REMOTE_COMMAND_TIMEOUT_SETTING_KEY, str(DEFAULT_REMOTE_COMMAND_TIMEOUT_SECONDS))
    normalized = normalize_remote_command_timeout(raw)
    return normalized if normalized is not None else DEFAULT_REMOTE_COMMAND_TIMEOUT_SECONDS


def normalize_smtp_timeout(value: str | int | None) -> int | None:
    if value is None:
        return None
    try:
        v = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    return v if 5 <= v <= MAX_SMTP_TIMEOUT_SECONDS else None


def get_smtp_timeout(db: Session) -> int:
    raw = get_app_setting(db, SMTP_TIMEOUT_SETTING_KEY, str(DEFAULT_SMTP_TIMEOUT_SECONDS))
    normalized = normalize_smtp_timeout(raw)
    return normalized if normalized is not None else DEFAULT_SMTP_TIMEOUT_SECONDS


def normalize_schedule_poll_interval(value: str | int | None) -> int | None:
    if value is None:
        return None
    try:
        v = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    return v if 5 <= v <= MAX_SCHEDULE_POLL_INTERVAL_SECONDS else None


def get_schedule_poll_interval(db: Session) -> int:
    raw = get_app_setting(db, SCHEDULE_POLL_INTERVAL_SETTING_KEY, str(DEFAULT_SCHEDULE_POLL_INTERVAL_SECONDS))
    normalized = normalize_schedule_poll_interval(raw)
    return normalized if normalized is not None else DEFAULT_SCHEDULE_POLL_INTERVAL_SECONDS


def send_admin_alert_email(db: Session, alert: Alert) -> None:
    if not get_active_email_alerts_enabled():
        return

    recipients = [
        row[0]
        for row in db.query(User.email)
        .filter(
            User.is_admin.is_(True),
            User.enabled.is_(True),
            User.email.is_not(None),
            User.email != "",
        )
        .all()
    ]
    if not recipients:
        return

    host = get_smtp_setting(db, SMTP_HOST_SETTING_KEY, "SMTP_HOST", "localhost")
    port = int(get_smtp_setting(db, SMTP_PORT_SETTING_KEY, "SMTP_PORT", "25") or "25")
    username = get_smtp_setting(db, SMTP_USERNAME_SETTING_KEY, "SMTP_USERNAME", "")
    password = get_smtp_setting(db, SMTP_PASSWORD_SETTING_KEY, "SMTP_PASSWORD", "")
    use_tls = parse_bool_setting(get_smtp_setting(db, SMTP_USE_TLS_SETTING_KEY, "SMTP_USE_TLS", "false"), False)
    sender = get_smtp_setting(db, SMTP_FROM_SETTING_KEY, "SMTP_FROM", "daygle-server-manager@localhost")
    site_timezone = get_active_timezone()
    site_date_format = get_active_date_format()
    occurred_local = format_datetime_value(alert.created_at, site_date_format, site_timezone)
    severity = (alert.level or "info").upper()
    source_label = f"{alert.source_type or '-'} {alert.source_id or ''}".strip()

    msg = EmailMessage()
    msg["Subject"] = f"[Daygle Alert][{severity}] {alert.title}"
    msg["From"] = sender
    msg["To"] = ", ".join(recipients)
    msg.set_content(
        f"Daygle Server Manager detected a new alert that may require attention.\n\n"
        f"Summary\n"
        f"- Severity: {severity}\n"
        f"- Alert: {alert.title}\n"
        f"- Details: {alert.message}\n"
        f"- Source: {source_label}\n"
        f"- Occurred: {occurred_local} ({site_timezone})\n\n"
        f"You can review and acknowledge this alert in the Alerts page.\n"
    )

    with smtplib.SMTP(host=host, port=port, timeout=get_smtp_timeout(db)) as smtp:
        smtp.ehlo()
        if use_tls:
            smtp.starttls()
            smtp.ehlo()
        if username and password:
            smtp.login(username, password)
        smtp.send_message(msg)


def test_smtp_connection(host: str, port: int, username: str, password: str, use_tls: bool, timeout_seconds: int) -> None:
    with smtplib.SMTP(host=host, port=port, timeout=timeout_seconds) as smtp:
        smtp.ehlo()
        if use_tls:
            smtp.starttls()
            smtp.ehlo()
        if username:
            smtp.login(username, password)


def create_alert(
    db: Session,
    *,
    level: str,
    title: str,
    message: str,
    source_type: str | None = None,
    source_id: str | int | None = None,
    send_email: bool = True,
) -> Alert:
    level = normalize_alert_level(level)
    alert = Alert(
        level=level,
        title=title,
        message=message,
        source_type=source_type,
        source_id=str(source_id) if source_id is not None else None,
    )
    db.add(alert)
    db.commit()
    db.refresh(alert)

    if send_email:
        try:
            send_admin_alert_email(db, alert)
        except Exception as exc:
            print(f"[alert-email] error: {type(exc).__name__}: {exc}")
            delivery_alert = Alert(
                level="warning",
                title="Alert email delivery failed",
                message=f"Could not send alert email: {type(exc).__name__}: {exc}",
                source_type="smtp",
                source_id=None,
            )
            db.add(delivery_alert)
            db.commit()

    return alert


def purge_old_history(db: Session) -> None:
    job_days = get_update_job_retention_days(db)
    if job_days > 0:
        job_cutoff = datetime.utcnow() - timedelta(days=job_days)
        db.query(UpdateJob).filter(UpdateJob.created_at < job_cutoff).delete(synchronize_session=False)
        db.query(Alert).filter(Alert.created_at < job_cutoff).delete(synchronize_session=False)

    audit_days = get_audit_retention_days(db)
    if audit_days > 0:
        audit_cutoff = datetime.utcnow() - timedelta(days=audit_days)
        db.query(AuditLog).filter(AuditLog.timestamp < audit_cutoff).delete(synchronize_session=False)

    db.commit()


def enqueue_update_jobs(db: Session, servers: list[Server], package_manager: str, apt_extra_steps: list[str] | None = None, job_type: str = "manual", alert_only: bool = False) -> list[int]:
    return enqueue_update_jobs_for_schedule(db, servers, package_manager, None, job_type, apt_extra_steps, alert_only=alert_only)


def enqueue_update_jobs_for_schedule(
    db: Session,
    servers: list[Server],
    package_manager: str,
    schedule_id: int | None,
    job_type: str = "manual",
    apt_extra_steps: list[str] | None = None,
    alert_only: bool = False,
) -> list[int]:
    safe_job_type = "scheduled" if job_type == "scheduled" else "manual"
    created_jobs: list[int] = []
    for server in servers:
        job = UpdateJob(
            server_id=server.id,
            schedule_id=schedule_id if safe_job_type == "scheduled" else None,
            job_type=safe_job_type,
            package_manager=package_manager,
            status="pending",
            command="Pending package manager detection...",
        )
        job.apt_extra_steps = [s for s in (apt_extra_steps or []) if s]
        job.alert_only = alert_only
        db.add(job)
        db.commit()
        db.refresh(job)

        created_jobs.append(job.id)
        thread = Thread(target=process_job_async, args=(job.id,), daemon=True)
        thread.start()

    return created_jobs


def run_schedule_loop() -> None:
    next_purge_at = monotonic() + 3600
    while True:
        db = SessionLocal()
        poll_interval_seconds = DEFAULT_SCHEDULE_POLL_INTERVAL_SECONDS
        try:
            poll_interval_seconds = get_schedule_poll_interval(db)
            now = datetime.utcnow()
            due_schedules = (
                db.query(UpdateSchedule)
                .filter(UpdateSchedule.enabled.is_(True), UpdateSchedule.next_run_at <= now)
                .all()
            )

            for schedule in due_schedules:
                active_server_ids = [server_id for server_id in schedule.server_ids if server_id not in schedule.disabled_server_ids]
                servers = db.query(Server).filter(Server.id.in_(active_server_ids)).all()
                if servers:
                    enqueue_update_jobs_for_schedule(db, servers, schedule.package_manager, schedule.id, job_type="scheduled", apt_extra_steps=schedule.apt_extra_steps, alert_only=schedule.alert_only)

                schedule.last_run_at = now
                schedule.next_run_at = get_next_schedule_run(schedule, now)
                db.commit()

            if monotonic() >= next_purge_at:
                purge_old_history(db)
                next_purge_at = monotonic() + 3600
        except Exception as exc:
            print(f"[schedule-worker] error: {type(exc).__name__}: {exc}")
        finally:
            db.close()

        sleep(poll_interval_seconds)


def process_job_async(job_id: int) -> None:
    db = SessionLocal()
    try:
        job = db.query(UpdateJob).filter(UpdateJob.id == job_id).first()
        is_check = job.alert_only if job else False
        lock_timeout = get_apt_lock_timeout(db)
        connect_timeout = get_ssh_connect_timeout(db)
        command_timeout = get_remote_command_timeout(db)

        if is_check:
            run_check_job(
                db,
                job_id,
                create_alert,
                lock_timeout_seconds=lock_timeout,
                connect_timeout_seconds=connect_timeout,
                command_timeout_seconds=command_timeout,
            )
        else:
            run_update_job(
                db,
                job_id,
                create_alert,
                lock_timeout_seconds=lock_timeout,
                connect_timeout_seconds=connect_timeout,
                command_timeout_seconds=command_timeout,
            )

        job = db.query(UpdateJob).filter(UpdateJob.id == job_id).first()
        if job:
            apply_schedule_failure_guard(db, job)

        if not job or job.status != "failed":
            return

        # For alert-only check jobs, alerts are created by run_check_job itself;
        # don't double-alert on a check that succeeded (status may be "success" even with updates found).
        if job.alert_only:
            return

        existing = (
            db.query(Alert)
            .filter(Alert.source_type == "update_job", Alert.source_id == str(job.id))
            .first()
        )
        if existing:
            return

        server_label = job.server_name or f"Server #{job.server_id}"
        create_alert(
            db,
            level="error",
            title=f"Update failed on {server_label}",
            message=job.summary or "Update job failed.",
            source_type="update_job",
            source_id=job.id,
            send_email=True,
        )
    finally:
        db.close()


def count_consecutive_schedule_failures(db: Session, schedule_id: int, server_id: int) -> int:
    recent_jobs = (
        db.query(UpdateJob)
        .filter(
            UpdateJob.schedule_id == schedule_id,
            UpdateJob.server_id == server_id,
            UpdateJob.job_type == "scheduled",
        )
        .order_by(UpdateJob.created_at.desc())
        .limit(100)
        .all()
    )

    consecutive_failures = 0
    for scheduled_job in recent_jobs:
        if scheduled_job.status == "failed":
            consecutive_failures += 1
            continue
        break
    return consecutive_failures


def apply_schedule_failure_guard(db: Session, job: UpdateJob) -> None:
    if job.job_type != "scheduled" or not job.schedule_id:
        return

    schedule = db.query(UpdateSchedule).filter(UpdateSchedule.id == job.schedule_id).first()
    if not schedule:
        return
    if not schedule.auto_disable_on_failures:
        return

    threshold = schedule.failure_threshold or 0
    if threshold <= 0:
        return

    if job.status != "failed":
        return

    consecutive_failures = count_consecutive_schedule_failures(db, schedule.id, job.server_id)
    if consecutive_failures < threshold:
        return

    disabled_server_ids = set(schedule.disabled_server_ids)
    if job.server_id in disabled_server_ids:
        return

    disabled_server_ids.add(job.server_id)
    schedule.disabled_server_ids = sorted(disabled_server_ids)
    db.commit()

    server = db.query(Server).filter(Server.id == job.server_id).first()
    server_label = server.name if server else f"Server #{job.server_id}"
    log_audit(
        db,
        "schedule.auto_disable_server",
        actor=None,
        target_type="schedule",
        target_id=schedule.id,
        target_label=schedule.name,
        detail=(
            f"Auto-disabled {server_label} after {consecutive_failures} consecutive failed "
            f"scheduled update attempts"
        ),
    )
    create_alert(
        db,
        level="warning",
        title=f"Server auto-disabled in schedule {schedule.name}",
        message=(
            f"{server_label} has been excluded from schedule '{schedule.name}' after "
            f"{consecutive_failures} consecutive failed scheduled update attempts."
        ),
        source_type="schedule",
        source_id=schedule.id,
        send_email=False,
    )


def users_exist(db: Session) -> bool:
    return (db.query(func.count(User.id)).scalar() or 0) > 0


def get_session_user(request: Request, db: Session) -> User | None:
    user_id = request.session.get("user_id")
    if not user_id:
        return None

    timeout_minutes = get_active_login_timeout_minutes()
    now_ts = int(datetime.utcnow().timestamp())
    last_seen_raw = request.session.get("last_seen_at")
    try:
        last_seen_ts = int(last_seen_raw) if last_seen_raw is not None else None
    except (TypeError, ValueError):
        last_seen_ts = None

    if last_seen_ts is not None and now_ts - last_seen_ts > timeout_minutes * 60:
        request.session.clear()
        return None

    user = db.query(User).filter(User.id == user_id, User.enabled.is_(True)).first()
    if not user:
        request.session.clear()
        return None

    request.session["last_seen_at"] = now_ts
    return user


def set_flash(request: Request, message: str, category: str = "info") -> None:
    request.session["flash"] = {"message": message, "type": category}


def pop_flash(request: Request) -> dict | None:
    return request.session.pop("flash", None)


def render_app_template(
    request: Request,
    name: str,
    active_page: str,
    current_user: User,
    db: Session,
    **context,
):
    date_format = get_effective_date_format(current_user)
    timezone_name = get_effective_timezone(current_user)
    effective_theme = get_effective_theme(current_user)
    global_theme = get_active_default_theme()
    user_theme_preference = normalize_theme(current_user.theme_preference) or DEFAULT_THEME
    avatar_color = normalize_avatar_color(current_user.avatar_color) or DEFAULT_AVATAR_COLOR
    global_timezone_name = get_active_timezone()

    template_context = {
        "active_page": active_page,
        "current_user": current_user,
        "flash": pop_flash(request),
        "date_format": date_format,
        "timezone": timezone_name,
        "effective_theme": effective_theme,
        "global_theme": global_theme,
        "user_theme_preference": user_theme_preference,
        "avatar_color": avatar_color,
        "global_timezone": global_timezone_name,
        "date_format_options": DATE_FORMAT_OPTIONS,
        "timezone_options": TIMEZONE_OPTIONS,
        "avatar_color_options": AVATAR_COLOR_OPTIONS,
        "format_dt": lambda value: format_datetime_value(value, date_format, timezone_name),
        "unacknowledged_alert_count": (
            db.query(func.count(Alert.id)).filter(Alert.acknowledged_at.is_(None)).scalar() or 0
        )
        if current_user and current_user.is_admin
        else 0,
    }
    template_context.update(context)
    return templates.TemplateResponse(request=request, name=name, context=template_context)


def require_api_user(request: Request, db: Session, admin: bool = False) -> User:
    if not users_exist(db):
        raise HTTPException(status_code=503, detail="Initial setup required")

    user = get_session_user(request, db)
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")

    if admin and not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


def prune_ssh_terminal_tokens() -> None:
    now = datetime.utcnow()
    expired_tokens = [token for token, (_, expires_at) in ssh_terminal_tokens.items() if expires_at <= now]
    for token in expired_tokens:
        ssh_terminal_tokens.pop(token, None)


def issue_ssh_terminal_token(user: User) -> str:
    prune_ssh_terminal_tokens()
    token = secrets.token_urlsafe(32)
    ssh_terminal_tokens[token] = (
        user.id,
        datetime.utcnow() + timedelta(seconds=SSH_TERMINAL_TOKEN_TTL_SECONDS),
    )
    return token


def resolve_ssh_terminal_user(db: Session, token: str) -> User | None:
    prune_ssh_terminal_tokens()
    if not token:
        return None

    token_record = ssh_terminal_tokens.get(token)
    if not token_record:
        return None

    user_id, expires_at = token_record
    if expires_at <= datetime.utcnow():
        ssh_terminal_tokens.pop(token, None)
        return None

    user = db.query(User).filter(User.id == user_id, User.enabled.is_(True)).first()
    if not user:
        ssh_terminal_tokens.pop(token, None)
        return None
    return user


def build_server_connect_kwargs(
    db: Session,
    *,
    host: str,
    port: int,
    username: str,
    auth_method: str,
    password: str | None,
    ssh_key_id: int | None,
    existing_server: Server | None = None,
) -> dict:
    resolved_auth_method = auth_method if auth_method == "password" else "key"
    resolved_password = password or None
    resolved_ssh_key_id = ssh_key_id

    if resolved_auth_method == "password":
        if not resolved_password and existing_server and existing_server.auth_method == "password":
            resolved_password = existing_server.password
        if not resolved_password:
            raise HTTPException(status_code=400, detail="SSH password is required for password auth")
    else:
        if not resolved_ssh_key_id and existing_server and existing_server.auth_method == "key":
            resolved_ssh_key_id = existing_server.ssh_key_id
        if not resolved_ssh_key_id:
            raise HTTPException(status_code=400, detail="SSH key is required for key auth")

    connect_kwargs = {
        "hostname": host,
        "port": port,
        "username": username,
        "timeout": get_ssh_connect_timeout(db),
        "banner_timeout": get_ssh_connect_timeout(db),
        "auth_timeout": get_ssh_connect_timeout(db),
        "allow_agent": False,
        "look_for_keys": False,
    }

    if resolved_auth_method == "password":
        connect_kwargs["password"] = resolved_password
    else:
        ssh_key = db.query(SSHKey).filter(SSHKey.id == resolved_ssh_key_id).first()
        if not ssh_key:
            raise HTTPException(status_code=400, detail="Selected SSH key does not exist")
        connect_kwargs["pkey"] = load_private_key_for_ssh(ssh_key.private_key)

    return connect_kwargs


def run_ssh_connection_check(connect_kwargs: dict) -> tuple[bool, str]:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(**connect_kwargs)
    except paramiko.AuthenticationException:
        return False, "Authentication failed. Check username and credentials."
    except Exception as exc:
        return False, f"Connection failed: {str(exc)}"
    finally:
        client.close()

    return True, f"Connection successful to {connect_kwargs['hostname']}:{connect_kwargs['port']}"


def run_ssh_command(client: paramiko.SSHClient, command: str, timeout: int = 15) -> str:
    _stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
    exit_code = stdout.channel.recv_exit_status()
    output = stdout.read().decode("utf-8", errors="ignore").strip()
    error_text = stderr.read().decode("utf-8", errors="ignore").strip()
    if exit_code != 0:
        raise RuntimeError(error_text or output or "Command execution failed")
    return output


def collect_server_usage_metrics(
    client: paramiko.SSHClient,
) -> tuple[float | None, float | None, float | None, float | None, float | None, float | None]:
    cpu_usage: float | None = None
    ram_usage: float | None = None
    storage_usage: float | None = None
    load_avg_1: float | None = None
    load_avg_5: float | None = None
    load_avg_15: float | None = None

    try:
        cpu_output = run_ssh_command(
            client,
            "sh -c 'read _ u1 n1 s1 i1 ow1 irq1 sirq1 st1 _ < /proc/stat; "
            "t1=$((u1+n1+s1+i1+ow1+irq1+sirq1+st1)); "
            "idle1=$((i1+ow1)); "
            "sleep 1; "
            "read _ u2 n2 s2 i2 ow2 irq2 sirq2 st2 _ < /proc/stat; "
            "t2=$((u2+n2+s2+i2+ow2+irq2+sirq2+st2)); "
            "idle2=$((i2+ow2)); "
            "dt=$((t2-t1)); didle=$((idle2-idle1)); "
            "if [ $dt -le 0 ]; then echo 0; else awk -v dt=$dt -v didle=$didle \"BEGIN{printf \\\"%.1f\\\", ((dt-didle)/dt)*100}\"; fi'",
            timeout=20,
        )
        cpu_usage = max(0.0, min(100.0, float(cpu_output)))
    except Exception:
        cpu_usage = None

    try:
        ram_output = run_ssh_command(
            client,
            "free | awk '/^Mem:/ { if ($2 > 0) printf \"%.1f\", ($3/$2)*100; else print 0 }'",
        )
        ram_usage = max(0.0, min(100.0, float(ram_output)))
    except Exception:
        ram_usage = None

    try:
        storage_output = run_ssh_command(
            client,
            "df -P / | awk 'NR==2 { gsub(/%/, \"\", $5); print $5 }'",
        )
        storage_usage = max(0.0, min(100.0, float(storage_output)))
    except Exception:
        storage_usage = None

    try:
        load_output = run_ssh_command(
            client,
            "awk '{printf \"%.2f %.2f %.2f\", $1, $2, $3}' /proc/loadavg",
        )
        load_avg_parts = load_output.split()
        if len(load_avg_parts) >= 3:
            load_avg_1 = max(0.0, float(load_avg_parts[0]))
            load_avg_5 = max(0.0, float(load_avg_parts[1]))
            load_avg_15 = max(0.0, float(load_avg_parts[2]))
    except Exception:
        load_avg_1 = None
        load_avg_5 = None
        load_avg_15 = None

    return cpu_usage, ram_usage, storage_usage, load_avg_1, load_avg_5, load_avg_15


def serialize_server_health(server: Server) -> dict:
    return {
        "id": server.id,
        "name": server.name,
        "host": server.host,
        "port": server.port,
        "username": server.username,
        "auth_method": server.auth_method,
        "last_health_status": server.last_health_status or "unknown",
        "last_health_check_at": server.last_health_check_at.isoformat() if server.last_health_check_at else None,
        "last_health_message": server.last_health_message,
        "last_cpu_usage": server.last_cpu_usage,
        "last_ram_usage": server.last_ram_usage,
        "last_storage_usage": server.last_storage_usage,
        "last_load_avg": server.last_load_avg,
        "last_load_avg_5": server.last_load_avg_5,
        "last_load_avg_15": server.last_load_avg_15,
        "alert_cpu_threshold": server.alert_cpu_threshold,
        "alert_ram_threshold": server.alert_ram_threshold,
        "alert_storage_threshold": server.alert_storage_threshold,
        "alert_load_avg_threshold": server.alert_load_avg_threshold,
        "alert_load_avg_5_threshold": server.alert_load_avg_5_threshold,
        "alert_load_avg_15_threshold": server.alert_load_avg_15_threshold,
        "needs_reboot": server.needs_reboot,
    }


def run_saved_server_health_check(db: Session, server: Server) -> dict:
    checked_at = datetime.utcnow()

    try:
        connect_kwargs = build_server_connect_kwargs(
            db,
            host=server.host,
            port=server.port,
            username=server.username,
            auth_method=server.auth_method,
            password=server.password,
            ssh_key_id=server.ssh_key_id,
            existing_server=server,
        )
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(**connect_kwargs)
            is_online = True
            message = f"Connection successful to {server.host}:{server.port}"
            cpu_usage, ram_usage, storage_usage, load_avg_1, load_avg_5, load_avg_15 = collect_server_usage_metrics(client)
        except paramiko.AuthenticationException:
            is_online = False
            message = "Authentication failed. Check username and credentials."
            cpu_usage, ram_usage, storage_usage, load_avg_1, load_avg_5, load_avg_15 = None, None, None, None, None, None
        except Exception as exc:
            is_online = False
            message = f"Connection failed: {str(exc)}"
            cpu_usage, ram_usage, storage_usage, load_avg_1, load_avg_5, load_avg_15 = None, None, None, None, None, None
        finally:
            client.close()
    except HTTPException as exc:
        is_online = False
        message = str(exc.detail)
        cpu_usage, ram_usage, storage_usage, load_avg_1, load_avg_5, load_avg_15 = None, None, None, None, None, None

    server.last_health_status = "online" if is_online else "offline"
    server.last_health_check_at = checked_at
    server.last_health_message = message[:255] if message else None
    server.last_cpu_usage = cpu_usage
    server.last_ram_usage = ram_usage
    server.last_storage_usage = storage_usage
    server.last_load_avg = load_avg_1
    server.last_load_avg_5 = load_avg_5
    server.last_load_avg_15 = load_avg_15
    db.add(server)
    db.commit()
    db.refresh(server)

    # Fire threshold alerts when the server is online and a metric is breached.
    if is_online:
        cpu_threshold = server.alert_cpu_threshold
        ram_threshold = server.alert_ram_threshold
        storage_threshold = server.alert_storage_threshold
        load_threshold_1 = server.alert_load_avg_threshold
        load_threshold_5 = server.alert_load_avg_5_threshold
        load_threshold_15 = server.alert_load_avg_15_threshold

        if cpu_threshold > 0 and cpu_usage is not None and cpu_usage >= cpu_threshold:
            create_alert(
                db,
                level="warning",
                title=f"High CPU usage on {server.name}",
                message=f"CPU usage is {cpu_usage:.1f}% (threshold: {cpu_threshold}%) on {server.name} ({server.host}).",
                source_type="server",
                source_id=server.id,
            )
        if ram_threshold > 0 and ram_usage is not None and ram_usage >= ram_threshold:
            create_alert(
                db,
                level="warning",
                title=f"High RAM usage on {server.name}",
                message=f"RAM usage is {ram_usage:.1f}% (threshold: {ram_threshold}%) on {server.name} ({server.host}).",
                source_type="server",
                source_id=server.id,
            )
        if storage_threshold > 0 and storage_usage is not None and storage_usage >= storage_threshold:
            create_alert(
                db,
                level="error",
                title=f"Low disk space on {server.name}",
                message=f"Disk usage is {storage_usage:.1f}% (threshold: {storage_threshold}%) on {server.name} ({server.host}).",
                source_type="server",
                source_id=server.id,
            )
        if load_threshold_1 > 0 and load_avg_1 is not None and load_avg_1 >= load_threshold_1:
            create_alert(
                db,
                level="warning",
                title=f"High 1-minute load average on {server.name}",
                message=f"1-minute load average is {load_avg_1:.2f} (threshold: {load_threshold_1}) on {server.name} ({server.host}).",
                source_type="server",
                source_id=server.id,
            )
        if load_threshold_5 > 0 and load_avg_5 is not None and load_avg_5 >= load_threshold_5:
            create_alert(
                db,
                level="warning",
                title=f"High 5-minute load average on {server.name}",
                message=f"5-minute load average is {load_avg_5:.2f} (threshold: {load_threshold_5}) on {server.name} ({server.host}).",
                source_type="server",
                source_id=server.id,
            )
        if load_threshold_15 > 0 and load_avg_15 is not None and load_avg_15 >= load_threshold_15:
            create_alert(
                db,
                level="warning",
                title=f"High 15-minute load average on {server.name}",
                message=f"15-minute load average is {load_avg_15:.2f} (threshold: {load_threshold_15}) on {server.name} ({server.host}).",
                source_type="server",
                source_id=server.id,
            )

    return serialize_server_health(server)


@app.get("/")
def root(request: Request, db: Session = Depends(get_db)) -> RedirectResponse:
    if not users_exist(db):
        return RedirectResponse(url="/setup", status_code=307)

    if get_session_user(request, db):
        return RedirectResponse(url="/dashboard", status_code=307)

    return RedirectResponse(url="/login", status_code=307)


@app.get("/setup", response_class=HTMLResponse)
def setup_page(request: Request, db: Session = Depends(get_db)):
    if users_exist(db):
        if get_session_user(request, db):
            return RedirectResponse(url="/dashboard", status_code=303)
        return RedirectResponse(url="/login", status_code=303)

    return templates.TemplateResponse(
        request=request,
        name="setup.html",
        context={"flash": pop_flash(request)},
    )


@app.post("/setup")
def setup_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...),
    first_name: str = Form(""),
    last_name: str = Form(""),
    email: str = Form(""),
    db: Session = Depends(get_db),
):
    if users_exist(db):
        return RedirectResponse(url="/login", status_code=303)

    username = username.strip()
    if len(username) < 3:
        set_flash(request, "Username must be at least 3 characters.", "error")
        return RedirectResponse(url="/setup", status_code=303)

    if len(password) < 8:
        set_flash(request, "Password must be at least 8 characters.", "error")
        return RedirectResponse(url="/setup", status_code=303)

    if password != confirm_password:
        set_flash(request, "Passwords do not match.", "error")
        return RedirectResponse(url="/setup", status_code=303)

    user = User(
        username=username,
        password_hash=hash_password(password),
        first_name=first_name.strip() or None,
        last_name=last_name.strip() or None,
        email=email.strip() or None,
        is_admin=True,
        enabled=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    request.session["user_id"] = user.id
    request.session["last_seen_at"] = int(datetime.utcnow().timestamp())
    return RedirectResponse(url="/setup/complete", status_code=303)


@app.get("/setup/complete", response_class=HTMLResponse)
def setup_complete(request: Request, db: Session = Depends(get_db)):
    if not users_exist(db):
        return RedirectResponse(url="/setup", status_code=303)

    current_user = get_session_user(request, db)
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)

    return render_app_template(
        request,
        "setup_complete.html",
        active_page="dashboard",
        current_user=current_user,
        db=db,
    )


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request, db: Session = Depends(get_db)):
    if not users_exist(db):
        return RedirectResponse(url="/setup", status_code=303)

    if get_session_user(request, db):
        return RedirectResponse(url="/dashboard", status_code=303)

    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={"flash": pop_flash(request)},
    )


@app.post("/login")
def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    if not users_exist(db):
        return RedirectResponse(url="/setup", status_code=303)

    user = db.query(User).filter(User.username == username.strip()).first()
    if not user or not user.enabled or not verify_password(password, user.password_hash):
        set_flash(request, "Invalid username or password.", "error")
        return RedirectResponse(url="/login", status_code=303)

    user.last_login = datetime.utcnow()
    db.commit()

    request.session["user_id"] = user.id
    request.session["last_seen_at"] = int(datetime.utcnow().timestamp())
    log_audit(
        db,
        "user.login",
        request=request,
        actor=user,
        target_type="user",
        target_id=user.id,
        target_label=user.username,
        detail="User logged in successfully",
    )
    return RedirectResponse(url="/dashboard", status_code=303)


@app.get("/logout")
def logout(request: Request, db: Session = Depends(get_db)) -> RedirectResponse:
    current_user = get_session_user(request, db)
    if current_user:
        log_audit(
            db,
            "user.logout",
            request=request,
            actor=current_user,
            target_type="user",
            target_id=current_user.id,
            target_label=current_user.username,
            detail="User logged out",
        )
    request.session.clear()
    return RedirectResponse(url="/login", status_code=303)


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, db: Session = Depends(get_db)):
    if not users_exist(db):
        return RedirectResponse(url="/setup", status_code=303)

    current_user = get_session_user(request, db)
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)

    total_servers = db.query(func.count(Server.id)).scalar() or 0
    servers_online = db.query(func.count(Server.id)).filter(Server.last_health_status == "online").scalar() or 0
    running_jobs = db.query(func.count(UpdateJob.id)).filter(UpdateJob.status == "running").scalar() or 0
    failed_jobs = db.query(func.count(UpdateJob.id)).filter(UpdateJob.status == "failed").scalar() or 0
    unacknowledged_alerts = db.query(func.count(Alert.id)).filter(Alert.acknowledged_at.is_(None)).scalar() or 0
    latest_jobs = db.query(UpdateJob).order_by(UpdateJob.created_at.desc()).limit(10).all()
    servers = db.query(Server).order_by(Server.name.asc()).all()

    return render_app_template(
        request,
        "dashboard.html",
        "dashboard",
        current_user,
        db,
        total_servers=total_servers,
        servers_online=servers_online,
        running_jobs=running_jobs,
        failed_jobs=failed_jobs,
        unacknowledged_alerts=unacknowledged_alerts,
        latest_jobs=latest_jobs,
        servers=servers,
    )


@app.get("/servers", response_class=HTMLResponse)
def servers_page(request: Request, db: Session = Depends(get_db)):
    if not users_exist(db):
        return RedirectResponse(url="/setup", status_code=303)

    current_user = get_session_user(request, db)
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)

    servers = db.query(Server).order_by(Server.name.asc()).all()
    return render_app_template(
        request,
        "servers.html",
        "servers",
        current_user,
        db,
        servers=servers,
        ssh_keys=db.query(SSHKey).order_by(SSHKey.name.asc()).all(),
    )


@app.get("/servers/status", response_class=HTMLResponse)
def server_status_page(request: Request, db: Session = Depends(get_db)):
    if not users_exist(db):
        return RedirectResponse(url="/setup", status_code=303)

    current_user = get_session_user(request, db)
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)

    servers = db.query(Server).order_by(Server.name.asc()).all()
    return render_app_template(
        request,
        "server_status.html",
        "server-status",
        current_user,
        db,
        servers=servers,
    )


@app.get("/ssh-terminal", response_class=HTMLResponse)
def ssh_terminal_page(request: Request, db: Session = Depends(get_db)):
    if not users_exist(db):
        return RedirectResponse(url="/setup", status_code=303)

    current_user = get_session_user(request, db)
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)

    if not current_user.is_admin:
        set_flash(request, "Admin access required.", "error")
        return RedirectResponse(url="/dashboard", status_code=303)

    servers = db.query(Server).order_by(Server.name.asc()).all()
    selected_server_id = None
    selected_server_raw = (request.query_params.get("server_id") or "").strip()
    if selected_server_raw:
        try:
            selected_server_id = int(selected_server_raw)
        except ValueError:
            selected_server_id = None

    if selected_server_id is None and servers:
        selected_server_id = servers[0].id

    return render_app_template(
        request,
        "ssh_terminal.html",
        "ssh-terminal",
        current_user,
        db,
        servers=servers,
        selected_server_id=selected_server_id,
        terminal_access_token=issue_ssh_terminal_token(current_user),
        terminal_token_ttl_seconds=SSH_TERMINAL_TOKEN_TTL_SECONDS,
    )


@app.get("/file-explorer", response_class=HTMLResponse)
def file_explorer_page(request: Request, db: Session = Depends(get_db)):
    if not users_exist(db):
        return RedirectResponse(url="/setup", status_code=303)

    current_user = get_session_user(request, db)
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)

    if not current_user.is_admin:
        set_flash(request, "Admin access required.", "error")
        return RedirectResponse(url="/dashboard", status_code=303)

    servers = db.query(Server).order_by(Server.name.asc()).all()
    selected_server_id = None
    selected_server_raw = (request.query_params.get("server_id") or "").strip()
    if selected_server_raw:
        try:
            selected_server_id = int(selected_server_raw)
        except ValueError:
            selected_server_id = None
    if selected_server_id is None and servers:
        selected_server_id = servers[0].id

    return render_app_template(
        request,
        "file_explorer.html",
        "file-explorer",
        current_user,
        db,
        servers=servers,
        selected_server_id=selected_server_id,
    )


async def send_ssh_terminal_meta(websocket: WebSocket, message_type: str, message: str) -> None:
    await websocket.send_text(f"__ssh_meta__:{json.dumps({'type': message_type, 'message': message})}")


@app.websocket("/ws/ssh-terminal")
async def ssh_terminal_socket(websocket: WebSocket):
    await websocket.accept()

    db = SessionLocal()
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    channel = None
    output_task: asyncio.Task | None = None
    current_user: User | None = None
    server: Server | None = None

    try:
        if not users_exist(db):
            await send_ssh_terminal_meta(websocket, "error", "Initial setup required.")
            await websocket.close(code=4403)
            return

        token = (websocket.query_params.get("token") or "").strip()
        current_user = resolve_ssh_terminal_user(db, token)
        if not current_user:
            await send_ssh_terminal_meta(websocket, "error", "SSH terminal session expired. Refresh the page and try again.")
            await websocket.close(code=4401)
            return

        if not current_user.is_admin:
            await send_ssh_terminal_meta(websocket, "error", "Admin access required.")
            await websocket.close(code=4403)
            return

        try:
            server_id = int((websocket.query_params.get("server_id") or "").strip())
        except ValueError:
            await send_ssh_terminal_meta(websocket, "error", "Invalid server selection.")
            await websocket.close(code=4400)
            return

        server = db.query(Server).filter(Server.id == server_id).first()
        if not server:
            await send_ssh_terminal_meta(websocket, "error", "Selected server was not found.")
            await websocket.close(code=4404)
            return

        connect_kwargs = build_server_connect_kwargs(
            db,
            host=server.host,
            port=server.port,
            username=server.username,
            auth_method=server.auth_method,
            password=server.password,
            ssh_key_id=server.ssh_key_id,
            existing_server=server,
        )

        await asyncio.to_thread(client.connect, **connect_kwargs)
        channel = await asyncio.to_thread(client.invoke_shell, term="xterm", width=120, height=32)

        log_audit(
            db,
            "terminal.connect",
            actor=current_user,
            target_type="server",
            target_id=server.id,
            target_label=server.name,
            detail=f"Opened SSH terminal to {server.host}:{server.port}",
        )
        await send_ssh_terminal_meta(websocket, "status", f"Connected to {server.name} ({server.host}:{server.port}).")

        async def pump_output() -> None:
            while channel is not None and not channel.closed:
                if channel.recv_ready():
                    chunk = await asyncio.to_thread(channel.recv, 4096)
                    if not chunk:
                        break
                    await websocket.send_text(chunk.decode("utf-8", errors="replace"))
                    continue
                await asyncio.sleep(0.03)

        output_task = asyncio.create_task(pump_output())

        while True:
            payload = await websocket.receive_json()
            payload_type = (payload.get("type") or "").strip()

            if payload_type == "input":
                data = payload.get("data") or ""
                if data and channel is not None and not channel.closed:
                    await asyncio.to_thread(channel.send, str(data))
            elif payload_type == "resize":
                if channel is not None and not channel.closed:
                    try:
                        columns = max(40, min(int(payload.get("cols", 120)), 240))
                        rows = max(12, min(int(payload.get("rows", 32)), 80))
                    except (TypeError, ValueError):
                        columns = 120
                        rows = 32
                    await asyncio.to_thread(channel.resize_pty, width=columns, height=rows)
            elif payload_type == "disconnect":
                break
    except WebSocketDisconnect:
        pass
    except Exception as exc:
        try:
            await send_ssh_terminal_meta(websocket, "error", f"SSH terminal error: {str(exc)}")
        except Exception:
            pass
    finally:
        if output_task is not None:
            output_task.cancel()
        if channel is not None:
            try:
                channel.close()
            except Exception:
                pass
        try:
            client.close()
        except Exception:
            pass
        db.close()


@app.get("/updates", response_class=HTMLResponse)
def updates_page(request: Request, db: Session = Depends(get_db)):
    if not users_exist(db):
        return RedirectResponse(url="/setup", status_code=303)

    current_user = get_session_user(request, db)
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)

    if current_user.is_admin:
        return RedirectResponse(url="/updates/manual", status_code=303)
    return RedirectResponse(url="/updates/jobs", status_code=303)


@app.get("/updates/manual", response_class=HTMLResponse)
def updates_manual_page(request: Request, db: Session = Depends(get_db)):
    if not users_exist(db):
        return RedirectResponse(url="/setup", status_code=303)

    current_user = get_session_user(request, db)
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)

    if not current_user.is_admin:
        set_flash(request, "Admin access required.", "error")
        return RedirectResponse(url="/dashboard", status_code=303)

    servers = db.query(Server).order_by(Server.name.asc()).all()
    return render_app_template(
        request,
        "updates_manual.html",
        "updates-manual",
        current_user,
        db,
        servers=servers,
    )


@app.get("/updates/scheduled", response_class=HTMLResponse)
def updates_scheduled_page(request: Request, db: Session = Depends(get_db)):
    if not users_exist(db):
        return RedirectResponse(url="/setup", status_code=303)

    current_user = get_session_user(request, db)
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)

    servers = db.query(Server).order_by(Server.name.asc()).all()
    schedules = db.query(UpdateSchedule).order_by(UpdateSchedule.created_at.desc()).all()
    server_name_map = {s.id: s.name for s in servers}
    return render_app_template(
        request,
        "updates_scheduled.html",
        "updates-scheduled",
        current_user,
        db,
        servers=servers,
        schedules=schedules,
        server_name_map=server_name_map,
    )


@app.get("/updates/jobs", response_class=HTMLResponse)
def updates_jobs_page(request: Request, db: Session = Depends(get_db)):
    if not users_exist(db):
        return RedirectResponse(url="/setup", status_code=303)

    current_user = get_session_user(request, db)
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)

    raw_q = (request.query_params.get("q") or "").strip()
    status_filter = (request.query_params.get("status") or "").strip()
    job_type_filter = (request.query_params.get("job_type") or "").strip()
    date_from = (request.query_params.get("date_from") or "").strip()
    date_to = (request.query_params.get("date_to") or "").strip()

    try:
        page = int(request.query_params.get("page", "1"))
    except ValueError:
        page = 1
    if page < 1:
        page = 1

    default_page_size = get_effective_page_size(current_user, db)
    try:
        page_size = int(request.query_params.get("page_size", str(default_page_size)))
    except ValueError:
        page_size = default_page_size
    page_size = max(10, min(page_size, 200))

    query = db.query(UpdateJob)
    if status_filter and status_filter in {"pending", "running", "success", "failed"}:
        query = query.filter(UpdateJob.status == status_filter)
    if job_type_filter and job_type_filter in {"manual", "scheduled"}:
        query = query.filter(UpdateJob.job_type == job_type_filter)

    from_dt = None
    to_dt_exclusive = None
    try:
        if date_from:
            from_dt = datetime.strptime(date_from, "%Y-%m-%d")
    except ValueError:
        date_from = ""
    try:
        if date_to:
            to_dt_exclusive = datetime.strptime(date_to, "%Y-%m-%d") + timedelta(days=1)
    except ValueError:
        date_to = ""

    if from_dt:
        query = query.filter(UpdateJob.created_at >= from_dt)
    if to_dt_exclusive:
        query = query.filter(UpdateJob.created_at < to_dt_exclusive)

    if from_dt and to_dt_exclusive and from_dt >= to_dt_exclusive:
        set_flash(request, "Invalid date range: From date must be before To date.", "error")
        query = query.filter(text("1=0"))

    if raw_q:
        like_term = f"%{raw_q}%"
        query = query.filter(
            or_(
                UpdateJob.server_name.ilike(like_term),
                UpdateJob.summary.ilike(like_term),
                func.cast(UpdateJob.id, String).ilike(like_term),
            )
        )

    total_count = query.count()
    total_pages = max(1, (total_count + page_size - 1) // page_size)
    if page > total_pages:
        page = total_pages

    jobs = (
        query.order_by(UpdateJob.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    if total_count == 0:
        showing_from = 0
        showing_to = 0
    else:
        showing_from = ((page - 1) * page_size) + 1
        showing_to = min(((page - 1) * page_size) + len(jobs), total_count)

    status_options = ["pending", "running", "success", "failed"]
    job_type_options = ["manual", "scheduled"]

    base_query = {
        "q": raw_q,
        "status": status_filter,
        "job_type": job_type_filter,
        "date_from": date_from,
        "date_to": date_to,
        "page_size": page_size,
    }

    def build_page_url(target_page: int) -> str:
        params = {k: v for k, v in base_query.items() if v not in (None, "")}
        params["page"] = target_page
        return f"/updates/jobs?{urlencode(params)}"

    prev_page_url = build_page_url(page - 1) if page > 1 else None
    next_page_url = build_page_url(page + 1) if page < total_pages else None

    return render_app_template(
        request,
        "updates_jobs.html",
        "updates-jobs",
        current_user,
        db,
        jobs=jobs,
        search_q=raw_q,
        selected_status=status_filter,
        selected_job_type=job_type_filter,
        selected_date_from=date_from,
        selected_date_to=date_to,
        page=page,
        page_size=page_size,
        total_count=total_count,
        showing_from=showing_from,
        showing_to=showing_to,
        total_pages=total_pages,
        prev_page_url=prev_page_url,
        next_page_url=next_page_url,
        status_options=status_options,
        job_type_options=job_type_options,
    )


@app.get("/updates/jobs/running", response_class=HTMLResponse)
def updates_jobs_running_page(request: Request):
    return RedirectResponse(url="/updates/jobs?status=running", status_code=303)


@app.get("/updates/jobs/failed", response_class=HTMLResponse)
def updates_jobs_failed_page(request: Request):
    return RedirectResponse(url="/updates/jobs?status=failed", status_code=303)


@app.get("/users", response_class=HTMLResponse)
def users_page(request: Request, db: Session = Depends(get_db)):
    if not users_exist(db):
        return RedirectResponse(url="/setup", status_code=303)

    current_user = get_session_user(request, db)
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)

    if not current_user.is_admin:
        set_flash(request, "Admin access required.", "error")
        return RedirectResponse(url="/dashboard", status_code=303)

    users = db.query(User).order_by(User.created_at.desc()).all()
    return render_app_template(request, "users.html", "users", current_user, db, users=users)


@app.get("/user-settings", response_class=HTMLResponse)
def user_settings_page(request: Request, db: Session = Depends(get_db)):
    if not users_exist(db):
        return RedirectResponse(url="/setup", status_code=303)

    current_user = get_session_user(request, db)
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)

    return render_app_template(
        request,
        "user_settings.html",
        "user-settings",
        current_user,
        db,
        selected_user_date_format=current_user.date_format or USER_DATE_FORMAT_GLOBAL,
        selected_user_timezone=current_user.timezone or USER_TIMEZONE_GLOBAL,
        selected_user_theme=current_user.theme_preference or USER_THEME_GLOBAL,
        selected_user_avatar_color=normalize_avatar_color(current_user.avatar_color) or DEFAULT_AVATAR_COLOR,
        selected_user_page_size=current_user.page_size or None,
    )


@app.post("/user-settings/save-all")
def save_user_settings(
    request: Request,
    date_format: str = Form(...),
    timezone_name: str = Form(...),
    theme: str = Form(USER_THEME_GLOBAL),
    avatar_color: str = Form(DEFAULT_AVATAR_COLOR),
    page_size: str = Form(""),
    db: Session = Depends(get_db),
):
    current_user = get_session_user(request, db)
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)

    changed: list[str] = []

    # Date format
    prev_date_format = current_user.date_format
    if date_format == USER_DATE_FORMAT_GLOBAL:
        current_user.date_format = None
    else:
        normalized_date_format = normalize_date_format(date_format)
        if not normalized_date_format:
            set_flash(request, "Invalid date format selection.", "error")
            return RedirectResponse(url="/user-settings", status_code=303)
        current_user.date_format = normalized_date_format
    if current_user.date_format != prev_date_format:
        changed.append("date format")

    # Timezone
    prev_timezone = current_user.timezone
    if timezone_name == USER_TIMEZONE_GLOBAL:
        current_user.timezone = None
    else:
        normalized_timezone = normalize_timezone(timezone_name)
        if not normalized_timezone or normalized_timezone not in TIMEZONE_OPTION_KEYS:
            set_flash(request, "Invalid timezone selection.", "error")
            return RedirectResponse(url="/user-settings", status_code=303)
        current_user.timezone = normalized_timezone
    if current_user.timezone != prev_timezone:
        changed.append("timezone")

    # Theme
    prev_theme = current_user.theme_preference
    if theme == USER_THEME_GLOBAL:
        current_user.theme_preference = None
    else:
        normalized_theme = normalize_theme(theme)
        if not normalized_theme:
            set_flash(request, "Invalid theme selection.", "error")
            return RedirectResponse(url="/user-settings", status_code=303)
        current_user.theme_preference = normalized_theme
    if current_user.theme_preference != prev_theme:
        changed.append("theme")

    # Avatar color
    prev_avatar_color = normalize_avatar_color(current_user.avatar_color) or DEFAULT_AVATAR_COLOR
    normalized_avatar_color = normalize_avatar_color(avatar_color)
    if not normalized_avatar_color:
        set_flash(request, "Invalid avatar color selection.", "error")
        return RedirectResponse(url="/user-settings", status_code=303)
    current_user.avatar_color = normalized_avatar_color
    if normalized_avatar_color != prev_avatar_color:
        changed.append("avatar color")

    # Page size
    prev_page_size = current_user.page_size
    if page_size and page_size.strip():
        normalized_page_size = normalize_page_size(page_size)
        if not normalized_page_size:
            set_flash(request, "Invalid page size selection.", "error")
            return RedirectResponse(url="/user-settings", status_code=303)
        current_user.page_size = normalized_page_size
    else:
        current_user.page_size = None
    if current_user.page_size != prev_page_size:
        changed.append("page size")

    db.commit()

    if changed:
        set_flash(request, f"Saved your settings: {', '.join(changed)}.", "success")
    else:
        set_flash(request, "No settings changed.", "info")
    return RedirectResponse(url="/user-settings", status_code=303)


@app.get("/my-settings", response_class=HTMLResponse)
def legacy_my_settings_page() -> RedirectResponse:
    return RedirectResponse(url="/user-settings", status_code=307)


@app.post("/my-settings/save-all")
def legacy_save_my_settings() -> RedirectResponse:
    return RedirectResponse(url="/user-settings", status_code=307)


@app.post("/my-settings/date-format")
def update_my_date_format(
    request: Request,
    date_format: str = Form(...),
    db: Session = Depends(get_db),
):
    current_user = get_session_user(request, db)
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)

    if date_format == USER_DATE_FORMAT_GLOBAL:
        current_user.date_format = None
        db.commit()
        set_flash(request, "Your date format now follows the global setting.", "success")
        return RedirectResponse(url="/user-settings", status_code=303)

    normalized = normalize_date_format(date_format)
    if not normalized:
        set_flash(request, "Invalid date format selection.", "error")
        return RedirectResponse(url="/user-settings", status_code=303)

    current_user.date_format = normalized
    db.commit()
    set_flash(request, "Your personal date format was updated.", "success")
    return RedirectResponse(url="/user-settings", status_code=303)


@app.post("/my-settings/timezone")
def update_my_timezone(
    request: Request,
    timezone_name: str = Form(...),
    db: Session = Depends(get_db),
):
    current_user = get_session_user(request, db)
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)

    if timezone_name == USER_TIMEZONE_GLOBAL:
        current_user.timezone = None
        db.commit()
        set_flash(request, "Your timezone now follows the global setting.", "success")
        return RedirectResponse(url="/user-settings", status_code=303)

    normalized = normalize_timezone(timezone_name)
    if not normalized or normalized not in TIMEZONE_OPTION_KEYS:
        set_flash(request, "Invalid timezone selection.", "error")
        return RedirectResponse(url="/user-settings", status_code=303)

    current_user.timezone = normalized
    db.commit()
    set_flash(request, "Your personal timezone was updated.", "success")
    return RedirectResponse(url="/user-settings", status_code=303)


@app.post("/user-settings/date-format")
def update_user_date_format(
    request: Request,
    date_format: str = Form(...),
    db: Session = Depends(get_db),
):
    return update_my_date_format(request=request, date_format=date_format, db=db)


@app.post("/user-settings/timezone")
def update_user_timezone(
    request: Request,
    timezone_name: str = Form(...),
    db: Session = Depends(get_db),
):
    return update_my_timezone(request=request, timezone_name=timezone_name, db=db)


@app.post("/user-settings/theme")
def update_user_theme_preference(
    request: Request,
    theme: str = Form(...),
    db: Session = Depends(get_db),
):
    current_user = get_session_user(request, db)
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)

    normalized_theme = normalize_theme(theme)
    if not normalized_theme:
        set_flash(request, "Invalid theme selection.", "error")
        return RedirectResponse(url=request.headers.get("referer", "/user-settings"), status_code=303)

    previous_theme = normalize_theme(current_user.theme_preference) or DEFAULT_THEME
    current_user.theme_preference = None if normalized_theme == DEFAULT_THEME else normalized_theme
    db.commit()

    if previous_theme != normalized_theme:
        log_audit(
            db,
            "user.theme",
            request=request,
            actor=current_user,
            target_type="user",
            target_id=current_user.id,
            target_label=current_user.username,
            detail=f"Changed theme preference from {previous_theme} to {normalized_theme}",
        )

    return RedirectResponse(url=request.headers.get("referer", "/user-settings"), status_code=303)


@app.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request, db: Session = Depends(get_db)):
    if not users_exist(db):
        return RedirectResponse(url="/setup", status_code=303)

    current_user = get_session_user(request, db)
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)

    if not current_user.is_admin:
        set_flash(request, "Admin access required.", "error")
        return RedirectResponse(url="/dashboard", status_code=303)

    return render_app_template(
        request,
        "settings.html",
        "settings",
        current_user,
        db,
        selected_date_format=get_active_date_format(),
        selected_timezone=get_active_timezone(),
        selected_default_theme=get_active_default_theme(),
        selected_page_size=get_page_size_setting(db),
        selected_job_retention_days=get_update_job_retention_days(db),
        selected_audit_retention_days=get_audit_retention_days(db),
        selected_login_timeout_minutes=get_active_login_timeout_minutes(),
        selected_email_alerts_enabled=get_active_email_alerts_enabled(),
        selected_smtp_host=get_smtp_setting(db, SMTP_HOST_SETTING_KEY, "SMTP_HOST", "localhost"),
        selected_smtp_port=get_smtp_setting(db, SMTP_PORT_SETTING_KEY, "SMTP_PORT", "25"),
        selected_smtp_username=get_smtp_setting(db, SMTP_USERNAME_SETTING_KEY, "SMTP_USERNAME", ""),
        selected_smtp_use_tls=parse_bool_setting(get_smtp_setting(db, SMTP_USE_TLS_SETTING_KEY, "SMTP_USE_TLS", "false"), False),
        selected_smtp_from=get_smtp_setting(db, SMTP_FROM_SETTING_KEY, "SMTP_FROM", "daygle-server-manager@localhost"),
        selected_smtp_timeout=get_smtp_timeout(db),
        smtp_password_set=bool(get_smtp_setting(db, SMTP_PASSWORD_SETTING_KEY, "SMTP_PASSWORD", "")),
        selected_apt_lock_timeout=get_apt_lock_timeout(db),
        selected_ssh_connect_timeout=get_ssh_connect_timeout(db),
        selected_remote_command_timeout=get_remote_command_timeout(db),
        selected_schedule_poll_interval=get_schedule_poll_interval(db),
    )


@app.post("/settings/save-all")
def save_all_settings(
    request: Request,
    date_format: str = Form(...),
    timezone_name: str = Form(...),
    default_theme: str = Form(DEFAULT_THEME),
    page_size: str = Form(...),
    job_retention_days: int = Form(...),
    audit_retention_days: int = Form(...),
    login_timeout_minutes: int = Form(...),
    email_alerts_enabled: str | None = Form(None),
    smtp_host: str = Form(...),
    smtp_port: int = Form(...),
    smtp_username: str = Form(""),
    smtp_password: str = Form(""),
    clear_smtp_password: str | None = Form(None),
    smtp_use_tls: str | None = Form(None),
    smtp_from: str = Form(...),
    smtp_timeout_seconds: int = Form(DEFAULT_SMTP_TIMEOUT_SECONDS),
    apt_lock_timeout_seconds: int = Form(DEFAULT_APT_LOCK_TIMEOUT_SECONDS),
    ssh_connect_timeout_seconds: int = Form(DEFAULT_SSH_CONNECT_TIMEOUT_SECONDS),
    remote_command_timeout_seconds: int = Form(DEFAULT_REMOTE_COMMAND_TIMEOUT_SECONDS),
    schedule_poll_interval_seconds: int = Form(DEFAULT_SCHEDULE_POLL_INTERVAL_SECONDS),
    db: Session = Depends(get_db),
):
    current_user = get_session_user(request, db)
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)

    if not current_user.is_admin:
        set_flash(request, "Admin access required.", "error")
        return RedirectResponse(url="/dashboard", status_code=303)

    normalized_date_format = normalize_date_format(date_format)
    if not normalized_date_format:
        set_flash(request, "Invalid date format selection.", "error")
        return RedirectResponse(url="/settings", status_code=303)

    normalized_timezone = normalize_timezone(timezone_name)
    if not normalized_timezone or normalized_timezone not in TIMEZONE_OPTION_KEYS:
        set_flash(request, "Invalid timezone selection.", "error")
        return RedirectResponse(url="/settings", status_code=303)

    normalized_default_theme = normalize_theme(default_theme)
    if not normalized_default_theme:
        set_flash(request, "Invalid default theme selection.", "error")
        return RedirectResponse(url="/settings", status_code=303)

    normalized_page_size = normalize_page_size(page_size)
    if not normalized_page_size:
        set_flash(request, "Invalid page size selection.", "error")
        return RedirectResponse(url="/settings", status_code=303)

    normalized_job_retention = normalize_history_retention_days(job_retention_days)
    if normalized_job_retention is None:
        set_flash(request, "Invalid jobs retention period.", "error")
        return RedirectResponse(url="/settings", status_code=303)

    normalized_audit_retention = normalize_history_retention_days(audit_retention_days)
    if normalized_audit_retention is None:
        set_flash(request, "Invalid audit retention period.", "error")
        return RedirectResponse(url="/settings", status_code=303)

    normalized_timeout = normalize_login_timeout_minutes(login_timeout_minutes)
    if normalized_timeout is None:
        set_flash(request, "Invalid login timeout. Enter between 1 and 43200 minutes.", "error")
        return RedirectResponse(url="/settings", status_code=303)

    host = smtp_host.strip()
    sender = smtp_from.strip()
    if not host:
        set_flash(request, "SMTP host is required.", "error")
        return RedirectResponse(url="/settings", status_code=303)
    if smtp_port < 1 or smtp_port > 65535:
        set_flash(request, "SMTP port must be between 1 and 65535.", "error")
        return RedirectResponse(url="/settings", status_code=303)
    if not sender or "@" not in sender:
        set_flash(request, "SMTP from address must be a valid email.", "error")
        return RedirectResponse(url="/settings", status_code=303)

    normalized_smtp_timeout = normalize_smtp_timeout(smtp_timeout_seconds)
    if normalized_smtp_timeout is None:
        set_flash(request, f"Invalid SMTP timeout (5–{MAX_SMTP_TIMEOUT_SECONDS} seconds).", "error")
        return RedirectResponse(url="/settings", status_code=303)

    normalized_ssh_connect_timeout = normalize_ssh_connect_timeout(ssh_connect_timeout_seconds)
    if normalized_ssh_connect_timeout is None:
        set_flash(request, f"Invalid SSH connect timeout (5–{MAX_SSH_CONNECT_TIMEOUT_SECONDS} seconds).", "error")
        return RedirectResponse(url="/settings", status_code=303)

    normalized_remote_command_timeout = normalize_remote_command_timeout(remote_command_timeout_seconds)
    if normalized_remote_command_timeout is None:
        set_flash(request, f"Invalid remote command timeout (30–{MAX_REMOTE_COMMAND_TIMEOUT_SECONDS} seconds).", "error")
        return RedirectResponse(url="/settings", status_code=303)

    normalized_schedule_poll_interval = normalize_schedule_poll_interval(schedule_poll_interval_seconds)
    if normalized_schedule_poll_interval is None:
        set_flash(request, f"Invalid schedule polling interval (5–{MAX_SCHEDULE_POLL_INTERVAL_SECONDS} seconds).", "error")
        return RedirectResponse(url="/settings", status_code=303)

    normalized_email_alerts = parse_bool_setting(email_alerts_enabled, False)
    normalized_smtp_tls = parse_bool_setting(smtp_use_tls, False)
    normalized_clear_smtp_password = parse_bool_setting(clear_smtp_password, False)
    smtp_username_clean = smtp_username.strip()

    changed: list[str] = []

    prev_date_format = get_date_format_setting(db)
    if normalized_date_format != prev_date_format:
        set_app_setting(db, DATE_FORMAT_SETTING_KEY, normalized_date_format)
        app.state.date_format = normalized_date_format
        log_audit(
            db,
            "settings.date_format",
            request=request,
            actor=current_user,
            detail=f"Changed from {prev_date_format} to {normalized_date_format}",
        )
        changed.append("date format")

    prev_timezone = get_timezone_setting(db)
    if normalized_timezone != prev_timezone:
        set_app_setting(db, TIMEZONE_SETTING_KEY, normalized_timezone)
        app.state.timezone = normalized_timezone
        log_audit(
            db,
            "settings.timezone",
            request=request,
            actor=current_user,
            detail=f"Changed from {prev_timezone} to {normalized_timezone}",
        )
        changed.append("timezone")

    prev_default_theme = get_default_theme_setting(db)
    if normalized_default_theme != prev_default_theme:
        set_app_setting(db, DEFAULT_THEME_SETTING_KEY, normalized_default_theme)
        app.state.default_theme = normalized_default_theme
        log_audit(
            db,
            "settings.default_theme",
            request=request,
            actor=current_user,
            detail=f"Changed from {prev_default_theme} to {normalized_default_theme}",
        )
        changed.append("default theme")

    prev_page_size = get_page_size_setting(db)
    if normalized_page_size != prev_page_size:
        set_app_setting(db, PAGE_SIZE_SETTING_KEY, str(normalized_page_size))
        app.state.page_size = normalized_page_size
        log_audit(
            db,
            "settings.page_size",
            request=request,
            actor=current_user,
            detail=f"Changed from {prev_page_size} to {normalized_page_size}",
        )
        changed.append("page size")

    prev_job_retention = get_update_job_retention_days(db)
    if normalized_job_retention != prev_job_retention:
        set_app_setting(db, UPDATE_JOB_RETENTION_SETTING_KEY, str(normalized_job_retention))
        old_label = "keep forever" if prev_job_retention == 0 else f"{prev_job_retention} days"
        new_label = "keep forever" if normalized_job_retention == 0 else f"{normalized_job_retention} days"
        log_audit(
            db,
            "settings.job_retention",
            request=request,
            actor=current_user,
            detail=f"Changed from {old_label} to {new_label}",
        )
        changed.append("job retention")

    prev_audit_retention = get_audit_retention_days(db)
    if normalized_audit_retention != prev_audit_retention:
        set_app_setting(db, AUDIT_RETENTION_SETTING_KEY, str(normalized_audit_retention))
        old_label = "keep forever" if prev_audit_retention == 0 else f"{prev_audit_retention} days"
        new_label = "keep forever" if normalized_audit_retention == 0 else f"{normalized_audit_retention} days"
        log_audit(
            db,
            "settings.audit_retention",
            request=request,
            actor=current_user,
            detail=f"Changed from {old_label} to {new_label}",
        )
        changed.append("audit retention")

    prev_timeout = get_login_timeout_minutes(db)
    if normalized_timeout != prev_timeout:
        set_app_setting(db, LOGIN_TIMEOUT_SETTING_KEY, str(normalized_timeout))
        app.state.login_timeout_minutes = normalized_timeout
        log_audit(
            db,
            "settings.login_timeout",
            request=request,
            actor=current_user,
            detail=f"Changed from {prev_timeout} minutes to {normalized_timeout} minutes",
        )
        changed.append("login timeout")

    prev_email_alerts = get_email_alerts_enabled(db)
    if normalized_email_alerts != prev_email_alerts:
        set_app_setting(db, EMAIL_ALERTS_ENABLED_SETTING_KEY, "true" if normalized_email_alerts else "false")
        app.state.email_alerts_enabled = normalized_email_alerts
        log_audit(
            db,
            "settings.email_alerts",
            request=request,
            actor=current_user,
            detail=(
                f"Changed from {'enabled' if prev_email_alerts else 'disabled'} "
                f"to {'enabled' if normalized_email_alerts else 'disabled'}"
            ),
        )
        changed.append("email alerts")

    prev_smtp_host = get_smtp_setting(db, SMTP_HOST_SETTING_KEY, "SMTP_HOST", "localhost")
    prev_smtp_port = get_smtp_setting(db, SMTP_PORT_SETTING_KEY, "SMTP_PORT", "25")
    prev_smtp_username = get_smtp_setting(db, SMTP_USERNAME_SETTING_KEY, "SMTP_USERNAME", "")
    prev_smtp_use_tls = parse_bool_setting(get_smtp_setting(db, SMTP_USE_TLS_SETTING_KEY, "SMTP_USE_TLS", "false"), False)
    prev_smtp_from = get_smtp_setting(db, SMTP_FROM_SETTING_KEY, "SMTP_FROM", "daygle-server-manager@localhost")
    prev_smtp_password = get_smtp_setting(db, SMTP_PASSWORD_SETTING_KEY, "SMTP_PASSWORD", "")
    prev_smtp_timeout = get_smtp_timeout(db)

    new_smtp_password = prev_smtp_password
    password_updated = False
    if normalized_clear_smtp_password:
        new_smtp_password = ""
        password_updated = new_smtp_password != prev_smtp_password
    elif smtp_password:
        new_smtp_password = smtp_password
        password_updated = True

    smtp_changed = any(
        [
            host != prev_smtp_host,
            str(smtp_port) != str(prev_smtp_port),
            smtp_username_clean != prev_smtp_username,
            normalized_smtp_tls != prev_smtp_use_tls,
            sender != prev_smtp_from,
            normalized_smtp_timeout != prev_smtp_timeout,
            password_updated,
        ]
    )

    if smtp_changed:
        set_app_setting(db, SMTP_HOST_SETTING_KEY, host)
        set_app_setting(db, SMTP_PORT_SETTING_KEY, str(smtp_port))
        set_app_setting(db, SMTP_USERNAME_SETTING_KEY, smtp_username_clean)
        set_app_setting(db, SMTP_USE_TLS_SETTING_KEY, "true" if normalized_smtp_tls else "false")
        set_app_setting(db, SMTP_FROM_SETTING_KEY, sender)
        set_app_setting(db, SMTP_TIMEOUT_SETTING_KEY, str(normalized_smtp_timeout))
        if password_updated:
            set_app_setting(db, SMTP_PASSWORD_SETTING_KEY, new_smtp_password)

        log_audit(
            db,
            "settings.smtp",
            request=request,
            actor=current_user,
            detail=(
                f"Updated SMTP host={host}, port={smtp_port}, user={'set' if smtp_username_clean else 'empty'}, "
                f"tls={'enabled' if normalized_smtp_tls else 'disabled'}, from={sender}, timeout={normalized_smtp_timeout}s, "
                f"password={'updated' if password_updated else 'unchanged'}"
            ),
        )
        changed.append("SMTP settings")

    normalized_lock_timeout = normalize_apt_lock_timeout(apt_lock_timeout_seconds)
    if normalized_lock_timeout is None:
        set_flash(request, f"Invalid apt lock timeout (10–{MAX_APT_LOCK_TIMEOUT_SECONDS} seconds).", "error")
        return RedirectResponse(url="/settings", status_code=303)
    prev_lock_timeout = get_apt_lock_timeout(db)
    if normalized_lock_timeout != prev_lock_timeout:
        set_app_setting(db, APT_LOCK_TIMEOUT_SETTING_KEY, str(normalized_lock_timeout))
        log_audit(
            db,
            "settings.apt_lock_timeout",
            request=request,
            actor=current_user,
            detail=f"Changed from {prev_lock_timeout}s to {normalized_lock_timeout}s",
        )
        changed.append("apt lock timeout")

    prev_ssh_connect_timeout = get_ssh_connect_timeout(db)
    if normalized_ssh_connect_timeout != prev_ssh_connect_timeout:
        set_app_setting(db, SSH_CONNECT_TIMEOUT_SETTING_KEY, str(normalized_ssh_connect_timeout))
        log_audit(
            db,
            "settings.ssh_connect_timeout",
            request=request,
            actor=current_user,
            detail=f"Changed from {prev_ssh_connect_timeout}s to {normalized_ssh_connect_timeout}s",
        )
        changed.append("SSH connect timeout")

    prev_remote_command_timeout = get_remote_command_timeout(db)
    if normalized_remote_command_timeout != prev_remote_command_timeout:
        set_app_setting(db, REMOTE_COMMAND_TIMEOUT_SETTING_KEY, str(normalized_remote_command_timeout))
        log_audit(
            db,
            "settings.remote_command_timeout",
            request=request,
            actor=current_user,
            detail=f"Changed from {prev_remote_command_timeout}s to {normalized_remote_command_timeout}s",
        )
        changed.append("remote command timeout")

    prev_schedule_poll_interval = get_schedule_poll_interval(db)
    if normalized_schedule_poll_interval != prev_schedule_poll_interval:
        set_app_setting(db, SCHEDULE_POLL_INTERVAL_SETTING_KEY, str(normalized_schedule_poll_interval))
        log_audit(
            db,
            "settings.schedule_poll_interval",
            request=request,
            actor=current_user,
            detail=f"Changed from {prev_schedule_poll_interval}s to {normalized_schedule_poll_interval}s",
        )
        changed.append("schedule polling interval")

    if changed:
        set_flash(request, f"Saved settings: {', '.join(changed)}.", "success")
    else:
        set_flash(request, "No settings changed.", "info")

    return RedirectResponse(url="/settings", status_code=303)


@app.post("/settings/date-format")
def update_date_format(
    request: Request,
    date_format: str = Form(...),
    db: Session = Depends(get_db),
):
    current_user = get_session_user(request, db)
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)

    if not current_user.is_admin:
        set_flash(request, "Admin access required.", "error")
        return RedirectResponse(url="/dashboard", status_code=303)

    normalized = normalize_date_format(date_format)
    if not normalized:
        set_flash(request, "Invalid date format selection.", "error")
        return RedirectResponse(url="/settings", status_code=303)

    previous_value = get_date_format_setting(db)
    set_app_setting(db, DATE_FORMAT_SETTING_KEY, normalized)
    app.state.date_format = normalized
    log_audit(
        db,
        "settings.date_format",
        request=request,
        actor=current_user,
        detail=f"Changed from {previous_value} to {normalized}",
    )
    set_flash(request, "Global date format updated.", "success")
    return RedirectResponse(url="/settings", status_code=303)


@app.post("/settings/timezone")
def update_timezone(
    request: Request,
    timezone_name: str = Form(...),
    db: Session = Depends(get_db),
):
    current_user = get_session_user(request, db)
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)

    if not current_user.is_admin:
        set_flash(request, "Admin access required.", "error")
        return RedirectResponse(url="/dashboard", status_code=303)

    normalized = normalize_timezone(timezone_name)
    if not normalized or normalized not in TIMEZONE_OPTION_KEYS:
        set_flash(request, "Invalid timezone selection.", "error")
        return RedirectResponse(url="/settings", status_code=303)

    previous_value = get_timezone_setting(db)
    set_app_setting(db, TIMEZONE_SETTING_KEY, normalized)
    app.state.timezone = normalized
    log_audit(
        db,
        "settings.timezone",
        request=request,
        actor=current_user,
        detail=f"Changed from {previous_value} to {normalized}",
    )
    set_flash(request, "Global timezone updated.", "success")
    return RedirectResponse(url="/settings", status_code=303)


@app.post("/settings/history-retention")
def update_history_retention(
    request: Request,
    retention_days: int = Form(...),
    db: Session = Depends(get_db),
):
    current_user = get_session_user(request, db)
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)

    if not current_user.is_admin:
        set_flash(request, "Admin access required.", "error")
        return RedirectResponse(url="/dashboard", status_code=303)

    normalized = normalize_history_retention_days(retention_days)
    if normalized is None:
        set_flash(request, "Invalid retention period.", "error")
        return RedirectResponse(url="/settings", status_code=303)

    previous_job_value = get_update_job_retention_days(db)
    previous_audit_value = get_audit_retention_days(db)
    set_app_setting(db, UPDATE_JOB_RETENTION_SETTING_KEY, str(normalized))
    set_app_setting(db, AUDIT_RETENTION_SETTING_KEY, str(normalized))
    old_label = (
        "keep forever"
        if previous_job_value == 0 and previous_audit_value == 0
        else f"jobs={previous_job_value} days, audit={previous_audit_value} days"
    )
    new_label = "keep forever" if normalized == 0 else f"{normalized} days"
    log_audit(
        db,
        "settings.history_retention",
        request=request,
        actor=current_user,
        detail=f"Changed both job and audit retention from {old_label} to {new_label}",
    )
    set_flash(request, "Job and audit retention periods updated.", "success")
    return RedirectResponse(url="/settings", status_code=303)


@app.post("/settings/login-timeout")
def update_login_timeout(
    request: Request,
    login_timeout_minutes: int = Form(...),
    db: Session = Depends(get_db),
):
    current_user = get_session_user(request, db)
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)

    if not current_user.is_admin:
        set_flash(request, "Admin access required.", "error")
        return RedirectResponse(url="/dashboard", status_code=303)

    normalized = normalize_login_timeout_minutes(login_timeout_minutes)
    if normalized is None:
        set_flash(request, "Invalid login timeout. Enter between 1 and 43200 minutes.", "error")
        return RedirectResponse(url="/settings", status_code=303)

    previous_value = get_login_timeout_minutes(db)
    set_app_setting(db, LOGIN_TIMEOUT_SETTING_KEY, str(normalized))
    app.state.login_timeout_minutes = normalized
    log_audit(
        db,
        "settings.login_timeout",
        request=request,
        actor=current_user,
        detail=f"Changed from {previous_value} minutes to {normalized} minutes",
    )
    set_flash(request, "Login timeout updated.", "success")
    return RedirectResponse(url="/settings", status_code=303)


@app.post("/settings/email-alerts")
def update_email_alerts(
    request: Request,
    email_alerts_enabled: str | None = Form(None),
    db: Session = Depends(get_db),
):
    current_user = get_session_user(request, db)
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)

    if not current_user.is_admin:
        set_flash(request, "Admin access required.", "error")
        return RedirectResponse(url="/dashboard", status_code=303)

    normalized = parse_bool_setting(email_alerts_enabled, False)
    previous_value = get_email_alerts_enabled(db)
    set_app_setting(db, EMAIL_ALERTS_ENABLED_SETTING_KEY, "true" if normalized else "false")
    app.state.email_alerts_enabled = normalized
    log_audit(
        db,
        "settings.email_alerts",
        request=request,
        actor=current_user,
        detail=f"Changed from {'enabled' if previous_value else 'disabled'} to {'enabled' if normalized else 'disabled'}",
    )
    set_flash(request, "Email alert preference updated.", "success")
    return RedirectResponse(url="/settings", status_code=303)


@app.post("/settings/smtp")
def update_smtp_settings(
    request: Request,
    smtp_host: str = Form(...),
    smtp_port: int = Form(...),
    smtp_username: str = Form(""),
    smtp_password: str = Form(""),
    clear_smtp_password: str | None = Form(None),
    smtp_use_tls: str | None = Form(None),
    smtp_from: str = Form(...),
    smtp_timeout_seconds: int = Form(DEFAULT_SMTP_TIMEOUT_SECONDS),
    db: Session = Depends(get_db),
):
    current_user = get_session_user(request, db)
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)

    if not current_user.is_admin:
        set_flash(request, "Admin access required.", "error")
        return RedirectResponse(url="/dashboard", status_code=303)

    host = smtp_host.strip()
    sender = smtp_from.strip()
    if not host:
        set_flash(request, "SMTP host is required.", "error")
        return RedirectResponse(url="/settings", status_code=303)
    if smtp_port < 1 or smtp_port > 65535:
        set_flash(request, "SMTP port must be between 1 and 65535.", "error")
        return RedirectResponse(url="/settings", status_code=303)
    if not sender or "@" not in sender:
        set_flash(request, "SMTP from address must be a valid email.", "error")
        return RedirectResponse(url="/settings", status_code=303)

    normalized_smtp_timeout = normalize_smtp_timeout(smtp_timeout_seconds)
    if normalized_smtp_timeout is None:
        set_flash(request, f"Invalid SMTP timeout (5–{MAX_SMTP_TIMEOUT_SECONDS} seconds).", "error")
        return RedirectResponse(url="/settings", status_code=303)

    set_app_setting(db, SMTP_HOST_SETTING_KEY, host)
    set_app_setting(db, SMTP_PORT_SETTING_KEY, str(smtp_port))
    set_app_setting(db, SMTP_USERNAME_SETTING_KEY, smtp_username.strip())
    set_app_setting(db, SMTP_USE_TLS_SETTING_KEY, "true" if parse_bool_setting(smtp_use_tls, False) else "false")
    set_app_setting(db, SMTP_FROM_SETTING_KEY, sender)
    set_app_setting(db, SMTP_TIMEOUT_SETTING_KEY, str(normalized_smtp_timeout))

    password_updated = False
    if parse_bool_setting(clear_smtp_password, False):
        set_app_setting(db, SMTP_PASSWORD_SETTING_KEY, "")
        password_updated = True
    elif smtp_password:
        set_app_setting(db, SMTP_PASSWORD_SETTING_KEY, smtp_password)
        password_updated = True

    log_audit(
        db,
        "settings.smtp",
        request=request,
        actor=current_user,
        detail=(
            f"Updated SMTP host={host}, port={smtp_port}, user={'set' if smtp_username.strip() else 'empty'}, "
            f"tls={'enabled' if parse_bool_setting(smtp_use_tls, False) else 'disabled'}, from={sender}, timeout={normalized_smtp_timeout}s, "
            f"password={'updated' if password_updated else 'unchanged'}"
        ),
    )
    set_flash(request, "SMTP settings updated.", "success")
    return RedirectResponse(url="/settings", status_code=303)


@app.post("/settings/smtp/test")
def test_smtp_settings(
    request: Request,
    smtp_host: str = Form(...),
    smtp_port: int = Form(...),
    smtp_username: str = Form(""),
    smtp_password: str = Form(""),
    smtp_use_tls: str | None = Form(None),
    smtp_timeout_seconds: int = Form(DEFAULT_SMTP_TIMEOUT_SECONDS),
    db: Session = Depends(get_db),
):
    current_user = get_session_user(request, db)
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)

    if not current_user.is_admin:
        set_flash(request, "Admin access required.", "error")
        return RedirectResponse(url="/dashboard", status_code=303)

    host = smtp_host.strip()
    if not host:
        set_flash(request, "SMTP host is required.", "error")
        return RedirectResponse(url="/settings", status_code=303)
    if smtp_port < 1 or smtp_port > 65535:
        set_flash(request, "SMTP port must be between 1 and 65535.", "error")
        return RedirectResponse(url="/settings", status_code=303)

    normalized_smtp_timeout = normalize_smtp_timeout(smtp_timeout_seconds)
    if normalized_smtp_timeout is None:
        set_flash(request, f"Invalid SMTP timeout (5–{MAX_SMTP_TIMEOUT_SECONDS} seconds).", "error")
        return RedirectResponse(url="/settings", status_code=303)

    username = smtp_username.strip()
    use_tls = parse_bool_setting(smtp_use_tls, False)
    password_to_use = smtp_password or get_smtp_setting(db, SMTP_PASSWORD_SETTING_KEY, "SMTP_PASSWORD", "")

    try:
        test_smtp_connection(host, smtp_port, username, password_to_use, use_tls, normalized_smtp_timeout)
    except Exception as exc:
        log_audit(
            db,
            "settings.smtp_test",
            request=request,
            actor=current_user,
            detail=(
                f"Connection test failed host={host}, port={smtp_port}, "
                f"user={'set' if username else 'empty'}, tls={'enabled' if use_tls else 'disabled'}, "
                f"error={type(exc).__name__}: {exc}"
            ),
        )
        set_flash(request, f"SMTP test failed: {type(exc).__name__}: {exc}", "error")
        return RedirectResponse(url="/settings", status_code=303)

    log_audit(
        db,
        "settings.smtp_test",
        request=request,
        actor=current_user,
        detail=(
            f"Connection test succeeded host={host}, port={smtp_port}, "
            f"user={'set' if username else 'empty'}, tls={'enabled' if use_tls else 'disabled'}"
        ),
    )
    set_flash(request, "SMTP connection test succeeded.", "success")
    return RedirectResponse(url="/settings", status_code=303)


@app.post("/users/create")
def create_user(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...),
    first_name: str = Form(""),
    last_name: str = Form(""),
    email: str = Form(""),
    is_admin: bool = Form(False),
    enabled: bool = Form(True),
    db: Session = Depends(get_db),
):
    current_user = get_session_user(request, db)
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)
    if not current_user.is_admin:
        set_flash(request, "Admin access required.", "error")
        return RedirectResponse(url="/dashboard", status_code=303)

    clean_username = username.strip()
    if len(clean_username) < 3:
        set_flash(request, "Username must be at least 3 characters.", "error")
        return RedirectResponse(url="/users", status_code=303)

    if len(password) < 8:
        set_flash(request, "Password must be at least 8 characters.", "error")
        return RedirectResponse(url="/users", status_code=303)

    if password != confirm_password:
        set_flash(request, "Passwords do not match.", "error")
        return RedirectResponse(url="/users", status_code=303)

    if db.query(User).filter(User.username == clean_username).first():
        set_flash(request, "Username already exists.", "error")
        return RedirectResponse(url="/users", status_code=303)

    user = User(
        username=clean_username,
        password_hash=hash_password(password),
        first_name=first_name.strip() or None,
        last_name=last_name.strip() or None,
        email=email.strip() or None,
        is_admin=is_admin,
        enabled=enabled,
    )
    db.add(user)
    db.commit()

    log_audit(db, "user.create", request=request, actor=current_user,
              target_type="user", target_id=user.id, target_label=clean_username,
              detail=f"Created user role={'admin' if user.is_admin else 'standard'}; enabled={user.enabled}")
    set_flash(request, f"User '{clean_username}' created.", "success")
    return RedirectResponse(url="/users", status_code=303)


@app.post("/users/{user_id}/toggle-enabled")
def toggle_user_enabled(user_id: int, request: Request, db: Session = Depends(get_db)):
    current_user = get_session_user(request, db)
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)
    if not current_user.is_admin:
        set_flash(request, "Admin access required.", "error")
        return RedirectResponse(url="/dashboard", status_code=303)

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        set_flash(request, "User not found.", "error")
        return RedirectResponse(url="/users", status_code=303)

    new_enabled = not user.enabled
    if user.id == current_user.id and not new_enabled:
        set_flash(request, "You cannot disable your own account.", "error")
        return RedirectResponse(url="/users", status_code=303)

    if user.is_admin and user.enabled and not new_enabled:
        enabled_admins = db.query(func.count(User.id)).filter(User.is_admin.is_(True), User.enabled.is_(True)).scalar() or 0
        if enabled_admins <= 1:
            set_flash(request, "At least one enabled admin must remain.", "error")
            return RedirectResponse(url="/users", status_code=303)

    user.enabled = new_enabled
    db.commit()
    log_audit(db, "user.enable" if new_enabled else "user.disable", request=request, actor=current_user,
              target_type="user", target_id=user.id, target_label=user.username,
              detail=f"Set enabled={new_enabled}")
    set_flash(request, f"User '{user.username}' updated.", "success")
    return RedirectResponse(url="/users", status_code=303)


@app.post("/users/{user_id}/update")
def update_user(
    user_id: int,
    request: Request,
    username: str = Form(...),
    password: str = Form(""),
    confirm_password: str = Form(""),
    first_name: str = Form(""),
    last_name: str = Form(""),
    email: str = Form(""),
    is_admin: bool = Form(False),
    enabled: bool = Form(False),
    db: Session = Depends(get_db),
):
    current_user = get_session_user(request, db)
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)
    if not current_user.is_admin:
        set_flash(request, "Admin access required.", "error")
        return RedirectResponse(url="/dashboard", status_code=303)

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        set_flash(request, "User not found.", "error")
        return RedirectResponse(url="/users", status_code=303)

    clean_username = username.strip()
    if len(clean_username) < 3:
        set_flash(request, "Username must be at least 3 characters.", "error")
        return RedirectResponse(url="/users", status_code=303)

    existing = db.query(User).filter(User.username == clean_username, User.id != user.id).first()
    if existing:
        set_flash(request, "Username already exists.", "error")
        return RedirectResponse(url="/users", status_code=303)

    if password:
        if len(password) < 8:
            set_flash(request, "Password must be at least 8 characters.", "error")
            return RedirectResponse(url="/users", status_code=303)
        if password != confirm_password:
            set_flash(request, "Passwords do not match.", "error")
            return RedirectResponse(url="/users", status_code=303)
    elif confirm_password:
        set_flash(request, "Enter a new password to use password confirmation.", "error")
        return RedirectResponse(url="/users", status_code=303)

    if user.id == current_user.id and not enabled:
        set_flash(request, "You cannot disable your own account.", "error")
        return RedirectResponse(url="/users", status_code=303)

    if user.id == current_user.id and not is_admin:
        set_flash(request, "You cannot remove your own admin access.", "error")
        return RedirectResponse(url="/users", status_code=303)

    if user.is_admin and user.enabled and (not is_admin or not enabled):
        enabled_admins = db.query(func.count(User.id)).filter(User.is_admin.is_(True), User.enabled.is_(True)).scalar() or 0
        if enabled_admins <= 1:
            set_flash(request, "At least one enabled admin must remain.", "error")
            return RedirectResponse(url="/users", status_code=303)

    old_username = user.username
    old_is_admin = user.is_admin
    old_enabled = user.enabled
    old_first_name = user.first_name
    old_last_name = user.last_name
    old_email = user.email

    user.username = clean_username
    user.first_name = first_name.strip() or None
    user.last_name = last_name.strip() or None
    user.email = email.strip() or None
    user.is_admin = is_admin
    user.enabled = enabled

    if password:
        user.password_hash = hash_password(password)

    db.commit()
    changes: list[str] = []
    if old_username != user.username:
        changes.append(f"username {old_username}->{user.username}")
    if old_is_admin != user.is_admin:
        changes.append(f"role {'admin' if old_is_admin else 'standard'}->{'admin' if user.is_admin else 'standard'}")
    if old_enabled != user.enabled:
        changes.append(f"enabled {old_enabled}->{user.enabled}")
    if old_first_name != user.first_name:
        changes.append("first_name updated")
    if old_last_name != user.last_name:
        changes.append("last_name updated")
    if old_email != user.email:
        changes.append("email updated")
    if password:
        changes.append("password updated")
    log_audit(db, "user.update", request=request, actor=current_user,
              target_type="user", target_id=user.id, target_label=user.username,
              detail=("; ".join(changes) if changes else "No effective field changes"))
    set_flash(request, f"User '{user.username}' updated.", "success")
    return RedirectResponse(url="/users", status_code=303)


@app.post("/users/{user_id}/delete")
def delete_user(user_id: int, request: Request, db: Session = Depends(get_db)):
    current_user = get_session_user(request, db)
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)
    if not current_user.is_admin:
        set_flash(request, "Admin access required.", "error")
        return RedirectResponse(url="/dashboard", status_code=303)

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        set_flash(request, "User not found.", "error")
        return RedirectResponse(url="/users", status_code=303)

    if user.id == current_user.id:
        set_flash(request, "You cannot delete your own account.", "error")
        return RedirectResponse(url="/users", status_code=303)

    if user.is_admin and user.enabled:
        enabled_admins = db.query(func.count(User.id)).filter(User.is_admin.is_(True), User.enabled.is_(True)).scalar() or 0
        if enabled_admins <= 1:
            set_flash(request, "At least one enabled admin must remain.", "error")
            return RedirectResponse(url="/users", status_code=303)

    db.delete(user)
    db.commit()
    log_audit(db, "user.delete", request=request, actor=current_user,
              target_type="user", target_id=user_id, target_label=user.username,
              detail=f"Deleted user role={'admin' if user.is_admin else 'standard'}; enabled={user.enabled}")
    set_flash(request, "User deleted.", "success")
    return RedirectResponse(url="/users", status_code=303)


@app.get("/ssh-keys", response_class=HTMLResponse)
def ssh_keys_page(request: Request, db: Session = Depends(get_db)):
    if not users_exist(db):
        return RedirectResponse(url="/setup", status_code=303)

    current_user = get_session_user(request, db)
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)

    if not current_user.is_admin:
        set_flash(request, "Admin access required.", "error")
        return RedirectResponse(url="/dashboard", status_code=303)

    ssh_keys = db.query(SSHKey).order_by(SSHKey.name.asc()).all()
    return render_app_template(request, "ssh_keys.html", "ssh-keys", current_user, db, ssh_keys=ssh_keys)


@app.get("/help", response_class=HTMLResponse)
def help_page(request: Request, db: Session = Depends(get_db)):
    if not users_exist(db):
        return RedirectResponse(url="/setup", status_code=303)

    current_user = get_session_user(request, db)
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)

    return render_app_template(request, "help.html", "help", current_user, db)


@app.get("/about", response_class=HTMLResponse)
def about_page(request: Request, db: Session = Depends(get_db)):
    if not users_exist(db):
        return RedirectResponse(url="/setup", status_code=303)

    current_user = get_session_user(request, db)
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)

    return render_app_template(request, "about.html", "about", current_user, db)


@app.get("/donate", response_class=HTMLResponse)
def donate_page(request: Request, db: Session = Depends(get_db)):
    if not users_exist(db):
        return RedirectResponse(url="/setup", status_code=303)

    current_user = get_session_user(request, db)
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)

    return render_app_template(request, "donate.html", "donate", current_user, db)


@app.get("/audit-log", response_class=HTMLResponse)
def audit_log_page(request: Request, db: Session = Depends(get_db)):
    if not users_exist(db):
        return RedirectResponse(url="/setup", status_code=303)

    current_user = get_session_user(request, db)
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)

    if not current_user.is_admin:
        set_flash(request, "Admin access required.", "error")
        return RedirectResponse(url="/dashboard", status_code=303)

    raw_q = (request.query_params.get("q") or "").strip()
    action_filter = (request.query_params.get("action") or "").strip()
    actor_filter = (request.query_params.get("actor") or "").strip()
    date_from = (request.query_params.get("date_from") or "").strip()
    date_to = (request.query_params.get("date_to") or "").strip()

    try:
        page = int(request.query_params.get("page", "1"))
    except ValueError:
        page = 1
    if page < 1:
        page = 1

    default_page_size = get_effective_page_size(current_user, db)
    try:
        page_size = int(request.query_params.get("page_size", str(default_page_size)))
    except ValueError:
        page_size = default_page_size
    page_size = max(10, min(page_size, 200))

    query = db.query(AuditLog)
    if action_filter:
        query = query.filter(AuditLog.action == action_filter)
    if actor_filter:
        query = query.filter(AuditLog.actor_username == actor_filter)

    from_dt = None
    to_dt_exclusive = None
    try:
        if date_from:
            from_dt = datetime.strptime(date_from, "%Y-%m-%d")
    except ValueError:
        date_from = ""
    try:
        if date_to:
            to_dt_exclusive = datetime.strptime(date_to, "%Y-%m-%d") + timedelta(days=1)
    except ValueError:
        date_to = ""

    if from_dt:
        query = query.filter(AuditLog.timestamp >= from_dt)
    if to_dt_exclusive:
        query = query.filter(AuditLog.timestamp < to_dt_exclusive)

    if from_dt and to_dt_exclusive and from_dt >= to_dt_exclusive:
        set_flash(request, "Invalid date range: From date must be before To date.", "error")
        query = query.filter(text("1=0"))

    if raw_q:
        like_term = f"%{raw_q}%"
        query = query.filter(
            or_(
                AuditLog.action.ilike(like_term),
                AuditLog.actor_username.ilike(like_term),
                AuditLog.target_type.ilike(like_term),
                AuditLog.target_id.ilike(like_term),
                AuditLog.target_label.ilike(like_term),
                AuditLog.detail.ilike(like_term),
                AuditLog.ip_address.ilike(like_term),
            )
        )

    total_count = query.count()
    total_pages = max(1, (total_count + page_size - 1) // page_size)
    if page > total_pages:
        page = total_pages

    entries = (
        query.order_by(AuditLog.timestamp.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    if total_count == 0:
        showing_from = 0
        showing_to = 0
    else:
        showing_from = ((page - 1) * page_size) + 1
        showing_to = min(((page - 1) * page_size) + len(entries), total_count)

    action_options = [
        row[0]
        for row in db.query(AuditLog.action)
        .filter(AuditLog.action.is_not(None))
        .distinct()
        .order_by(AuditLog.action.asc())
        .all()
    ]
    actor_options = [
        row[0]
        for row in db.query(AuditLog.actor_username)
        .filter(AuditLog.actor_username.is_not(None))
        .distinct()
        .order_by(AuditLog.actor_username.asc())
        .all()
    ]

    base_query = {
        "q": raw_q,
        "action": action_filter,
        "actor": actor_filter,
        "date_from": date_from,
        "date_to": date_to,
        "page_size": page_size,
    }

    def build_page_url(target_page: int) -> str:
        params = {k: v for k, v in base_query.items() if v not in (None, "")}
        params["page"] = target_page
        return f"/audit-log?{urlencode(params)}"

    prev_page_url = build_page_url(page - 1) if page > 1 else None
    next_page_url = build_page_url(page + 1) if page < total_pages else None

    return render_app_template(
        request,
        "audit_log.html",
        "audit-log",
        current_user,
        db,
        entries=entries,
        search_q=raw_q,
        selected_action=action_filter,
        selected_actor=actor_filter,
        selected_date_from=date_from,
        selected_date_to=date_to,
        page=page,
        page_size=page_size,
        total_count=total_count,
        showing_from=showing_from,
        showing_to=showing_to,
        total_pages=total_pages,
        prev_page_url=prev_page_url,
        next_page_url=next_page_url,
        action_options=action_options,
        actor_options=actor_options,
    )


@app.get("/alerts", response_class=HTMLResponse)
def alerts_page(request: Request, db: Session = Depends(get_db)):
    if not users_exist(db):
        return RedirectResponse(url="/setup", status_code=303)

    current_user = get_session_user(request, db)
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)

    if not current_user.is_admin:
        set_flash(request, "Admin access required.", "error")
        return RedirectResponse(url="/dashboard", status_code=303)

    q = (request.query_params.get("q") or "").strip()
    level_filter = normalize_alert_level(request.query_params.get("level", "")) if request.query_params.get("level") else ""
    state_filter = (request.query_params.get("state") or "open").strip().lower()
    if state_filter not in {"open", "ack", "all"}:
        state_filter = "open"

    try:
        page = int(request.query_params.get("page", "1"))
    except ValueError:
        page = 1
    page = max(1, page)

    default_page_size = get_effective_page_size(current_user, db)
    try:
        page_size = int(request.query_params.get("page_size", str(default_page_size)))
    except ValueError:
        page_size = default_page_size
    page_size = max(10, min(page_size, 200))

    query = db.query(Alert)
    if level_filter:
        query = query.filter(Alert.level == level_filter)
    if state_filter == "open":
        query = query.filter(Alert.acknowledged_at.is_(None))
    elif state_filter == "ack":
        query = query.filter(Alert.acknowledged_at.is_not(None))
    if q:
        like = f"%{q}%"
        query = query.filter(
            or_(
                Alert.title.ilike(like),
                Alert.message.ilike(like),
                Alert.source_type.ilike(like),
                Alert.source_id.ilike(like),
            )
        )

    total_count = query.count()
    total_pages = max(1, (total_count + page_size - 1) // page_size)
    if page > total_pages:
        page = total_pages

    unacknowledged_count = db.query(func.count(Alert.id)).filter(Alert.acknowledged_at.is_(None)).scalar() or 0

    alerts = query.order_by(Alert.created_at.desc()).offset((page - 1) * page_size).limit(page_size).all()

    base_query = {
        "q": q,
        "level": level_filter,
        "state": state_filter,
        "page_size": page_size,
    }

    def build_page_url(target_page: int) -> str:
        params = {k: v for k, v in base_query.items() if v not in (None, "")}
        params["page"] = target_page
        return f"/alerts?{urlencode(params)}"

    prev_page_url = build_page_url(page - 1) if page > 1 else None
    next_page_url = build_page_url(page + 1) if page < total_pages else None

    return render_app_template(
        request,
        "alerts.html",
        "alerts",
        current_user,
        db,
        alerts=alerts,
        page=page,
        page_size=page_size,
        total_count=total_count,
        total_pages=total_pages,
        prev_page_url=prev_page_url,
        next_page_url=next_page_url,
        search_q=q,
        selected_level=level_filter,
        selected_state=state_filter,
        unacknowledged_count=unacknowledged_count,
    )


@app.post("/alerts/{alert_id}/ack")
def acknowledge_alert(alert_id: int, request: Request, db: Session = Depends(get_db)):
    current_user = get_session_user(request, db)
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)
    if not current_user.is_admin:
        set_flash(request, "Admin access required.", "error")
        return RedirectResponse(url="/dashboard", status_code=303)

    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        set_flash(request, "Alert not found.", "error")
        return RedirectResponse(url="/alerts", status_code=303)

    if alert.acknowledged_at is None:
        alert.acknowledged_at = datetime.utcnow()
        db.commit()
        log_audit(
            db,
            "alert.acknowledge",
            request=request,
            actor=current_user,
            target_type="alert",
            target_id=alert.id,
            target_label=alert.title,
            detail=f"Acknowledged alert level={alert.level}",
        )

    return RedirectResponse(url=request.headers.get("referer", "/alerts"), status_code=303)


@app.post("/alerts/{alert_id}/dismiss")
def dismiss_alert(alert_id: int, request: Request, db: Session = Depends(get_db)):
    current_user = get_session_user(request, db)
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)
    if not current_user.is_admin:
        set_flash(request, "Admin access required.", "error")
        return RedirectResponse(url="/dashboard", status_code=303)

    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        set_flash(request, "Alert not found.", "error")
        return RedirectResponse(url="/alerts", status_code=303)

    alert_title = alert.title
    db.delete(alert)
    db.commit()
    log_audit(
        db,
        "alert.dismiss",
        request=request,
        actor=current_user,
        target_type="alert",
        target_id=alert_id,
        target_label=alert_title,
        detail=f"Dismissed alert level={alert.level}",
    )
    return RedirectResponse(url=request.headers.get("referer", "/alerts"), status_code=303)


@app.post("/api/ssh-keys", response_model=SSHKeyRead)
def create_ssh_key(payload: SSHKeyCreate, request: Request, db: Session = Depends(get_db)):
    require_api_user(request, db, admin=True)

    if db.query(SSHKey).filter(SSHKey.name == payload.name).first():
        raise HTTPException(status_code=400, detail="SSH key name already exists")

    # Derive the public key and type from the supplied private key
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448
    import base64
    
    try:
        # Try to load the private key
        private_key = serialization.load_pem_private_key(
            payload.private_key.encode(),
            password=None,
            backend=default_backend()
        )
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid private key: {exc}")

    # Determine key type and format public key
    public_key_obj = private_key.public_key()
    
    # Serialize public key using OpenSSH wire format for all supported types
    try:
        public_key = public_key_obj.public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH,
        ).decode().strip()
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Could not serialize public key: {exc}")

    # Derive key_type from the first token of the OpenSSH public key line
    if isinstance(private_key, ed25519.Ed25519PrivateKey):
        key_type = "ssh-ed25519"
    elif isinstance(private_key, ed448.Ed448PrivateKey):
        key_type = "ssh-ed448"
    elif isinstance(private_key, rsa.RSAPrivateKey):
        key_type = "ssh-rsa"
    elif isinstance(private_key, ec.EllipticCurvePrivateKey):
        key_type = f"ecdsa-sha2-nistp{private_key.curve.key_size}"
    else:
        raise HTTPException(status_code=400, detail=f"Unsupported key type: {type(private_key)}")

    ssh_key = SSHKey(
        name=payload.name,
        private_key=payload.private_key.strip(),
        public_key=public_key,
        key_type=key_type,
    )
    db.add(ssh_key)
    db.commit()
    db.refresh(ssh_key)
    actor = get_session_user(request, db)
    log_audit(db, "ssh_key.create", request=request, actor=actor,
              target_type="ssh_key", target_id=ssh_key.id, target_label=ssh_key.name,
              detail=f"Imported SSH key type={ssh_key.key_type}")
    return ssh_key


@app.post("/api/ssh-keys/generate", response_model=SSHKeyRead)
def generate_ssh_key(
    request: Request,
    name: str = Query(...),
    db: Session = Depends(get_db),
):
    require_api_user(request, db, admin=True)

    if db.query(SSHKey).filter(SSHKey.name == name).first():
        raise HTTPException(status_code=400, detail="SSH key name already exists")

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
        PublicFormat,
    )
    import base64

    raw_private = Ed25519PrivateKey.generate()
    pem_bytes = raw_private.private_bytes(Encoding.PEM, PrivateFormat.OpenSSH, NoEncryption())
    private_key_pem = pem_bytes.decode()

    # Get public key in OpenSSH wire format (includes key-type blob prefix)
    raw_public = raw_private.public_key()
    public_key = raw_public.public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH).decode().strip()

    ssh_key = SSHKey(
        name=name,
        private_key=private_key_pem.strip(),
        public_key=public_key,
        key_type="ssh-ed25519",
    )
    db.add(ssh_key)
    db.commit()
    db.refresh(ssh_key)
    actor = get_session_user(request, db)
    log_audit(db, "ssh_key.generate", request=request, actor=actor,
              target_type="ssh_key", target_id=ssh_key.id, target_label=ssh_key.name,
              detail="Generated new Ed25519 SSH key")
    return ssh_key


@app.get("/api/ssh-keys", response_model=list[SSHKeyRead])
def list_ssh_keys(request: Request, db: Session = Depends(get_db)):
    require_api_user(request, db)
    return db.query(SSHKey).order_by(SSHKey.name.asc()).all()


@app.delete("/api/ssh-keys/{key_id}")
def delete_ssh_key(key_id: int, request: Request, db: Session = Depends(get_db)):
    require_api_user(request, db, admin=True)

    ssh_key = db.query(SSHKey).filter(SSHKey.id == key_id).first()
    if not ssh_key:
        raise HTTPException(status_code=404, detail="SSH key not found")

    if ssh_key.servers:
        raise HTTPException(
            status_code=400,
            detail=f"Key is assigned to {len(ssh_key.servers)} server(s). Remove them first.",
        )

    db.delete(ssh_key)
    db.commit()
    actor = get_session_user(request, db)
    log_audit(db, "ssh_key.delete", request=request, actor=actor,
              target_type="ssh_key", target_id=key_id, target_label=ssh_key.name,
              detail=f"Deleted SSH key type={ssh_key.key_type}")
    return {"message": "SSH key deleted"}


def load_private_key_for_ssh(private_key_pem: str) -> paramiko.PKey:
    key_loaders = [
        paramiko.Ed25519Key,
        paramiko.RSAKey,
        paramiko.ECDSAKey,
        paramiko.DSSKey,
    ]
    last_error: Exception | None = None
    for loader in key_loaders:
        try:
            return loader.from_private_key(io.StringIO(private_key_pem))
        except Exception as exc:  # pragma: no cover - fallback probing
            last_error = exc
    raise HTTPException(status_code=400, detail="Stored SSH private key format is not supported") from last_error


@app.post("/api/servers/test-connection")
def test_server_connection(payload: ServerConnectionTestRequest, request: Request, db: Session = Depends(get_db)):
    require_api_user(request, db, admin=True)

    host = payload.host.strip()
    username = payload.username.strip()
    if not host:
        raise HTTPException(status_code=400, detail="Host is required")
    if not username:
        raise HTTPException(status_code=400, detail="Username is required")

    auth_method = payload.auth_method
    password = payload.password or None
    ssh_key_id = payload.ssh_key_id

    existing_server: Server | None = None
    if payload.server_id:
        existing_server = db.query(Server).filter(Server.id == payload.server_id).first()

    connect_kwargs = build_server_connect_kwargs(
        db,
        host=host,
        port=payload.port,
        username=username,
        auth_method=auth_method,
        password=password,
        ssh_key_id=ssh_key_id,
        existing_server=existing_server,
    )
    ok, message = run_ssh_connection_check(connect_kwargs)
    if not ok:
        if existing_server:
            existing_server.last_health_status = "offline"
            existing_server.last_health_check_at = datetime.utcnow()
            existing_server.last_health_message = message[:255]
            db.add(existing_server)
            db.commit()
        raise HTTPException(status_code=400, detail=message)

    if existing_server:
        existing_server.last_health_status = "online"
        existing_server.last_health_check_at = datetime.utcnow()
        existing_server.last_health_message = message[:255]
        db.add(existing_server)
        db.commit()

    return {"ok": True, "message": message}


@app.post("/api/server-status/{server_id}/check")
def check_server_status(server_id: int, request: Request, db: Session = Depends(get_db)):
    require_api_user(request, db)

    server = db.query(Server).filter(Server.id == server_id).first()
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")

    return run_saved_server_health_check(db, server)


@app.post("/api/server-status/check-all")
def check_all_server_statuses(request: Request, db: Session = Depends(get_db)):
    require_api_user(request, db)

    servers = db.query(Server).order_by(Server.name.asc()).all()
    return {
        "items": [run_saved_server_health_check(db, server) for server in servers],
        "checked_at": datetime.utcnow().isoformat(),
    }


@app.post("/api/server-status/{server_id}/reboot")
def reboot_server(server_id: int, request: Request, db: Session = Depends(get_db)):
    actor = require_api_user(request, db, admin=True)

    server = db.query(Server).filter(Server.id == server_id).first()
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")

    connect_kwargs = build_server_connect_kwargs(
        db,
        host=server.host,
        port=server.port,
        username=server.username,
        auth_method=server.auth_method,
        password=server.password,
        ssh_key_id=server.ssh_key_id,
        existing_server=server,
    )

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(**connect_kwargs)
        # Use nohup so the command survives the SSH session being terminated by the reboot.
        _, stdout, stderr = client.exec_command("nohup sh -c 'sleep 2 && reboot' >/dev/null 2>&1 &")
        stdout.channel.recv_exit_status()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Reboot command failed: {exc}") from exc
    finally:
        client.close()

    log_audit(
        db,
        "server.reboot",
        request=request,
        actor=actor,
        target_type="server",
        target_id=server.id,
        target_label=server.name,
        detail=f"Reboot initiated on {server.host}:{server.port} by {actor.username}",
    )

    create_alert(
        db,
        level="info",
        title=f"Reboot initiated: {server.name}",
        message=f"A reboot was initiated on {server.name} ({server.host}) by {actor.username}.",
        source_type="server",
        source_id=server.id,
        send_email=False,
    )

    return {"ok": True, "message": f"Reboot command sent to {server.name}."}


# ---------------------------------------------------------------------------
# File Explorer API
# ---------------------------------------------------------------------------

FILE_EXPLORER_MAX_READ_BYTES = 2 * 1024 * 1024  # 2 MB read/edit limit
FILE_EXPLORER_BINARY_SNIFF_BYTES = 8192


def _resolve_sftp_path(raw_path: str) -> str:
    """Normalise a raw path string.  Returns an absolute POSIX path."""
    p = raw_path.strip()
    if not p:
        p = "/"
    # Resolve any .. segments so we always end up with a clean absolute path.
    from posixpath import normpath as posix_normpath
    resolved = posix_normpath("/" + p.lstrip("/"))
    return resolved


def _sftp_for_server(server: Server, db: Session) -> tuple[paramiko.SSHClient, paramiko.SFTPClient]:
    connect_kwargs = build_server_connect_kwargs(
        db,
        host=server.host,
        port=server.port,
        username=server.username,
        auth_method=server.auth_method,
        password=server.password,
        ssh_key_id=server.ssh_key_id,
        existing_server=server,
    )
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(**connect_kwargs)
    sftp = client.open_sftp()
    return client, sftp


def _sftp_entry_to_dict(attr: paramiko.SFTPAttributes, name: str) -> dict:
    import stat as stat_mod
    is_dir = stat_mod.S_ISDIR(attr.st_mode or 0)
    is_link = stat_mod.S_ISLNK(attr.st_mode or 0)
    mode_bits = stat_mod.filemode(attr.st_mode or 0)
    return {
        "name": name,
        "is_dir": is_dir,
        "is_link": is_link,
        "size": attr.st_size if not is_dir else None,
        "mode": mode_bits,
        "mode_octal": oct(stat_mod.S_IMODE(attr.st_mode or 0)),
        "mtime": attr.st_mtime,
        "uid": attr.st_uid,
        "gid": attr.st_gid,
    }


@app.get("/api/file-explorer/{server_id}/list")
def file_explorer_list(server_id: int, path: str = Query(default="/"), request: Request = None, db: Session = Depends(get_db)):
    require_api_user(request, db, admin=True)
    server = db.query(Server).filter(Server.id == server_id).first()
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")

    resolved = _resolve_sftp_path(path)
    client = None
    try:
        client, sftp = _sftp_for_server(server, db)
        try:
            attrs = sftp.listdir_attr(resolved)
        except FileNotFoundError:
            raise HTTPException(status_code=404, detail="Path not found")
        except PermissionError:
            raise HTTPException(status_code=403, detail="Permission denied")
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc

        entries = sorted(
            [_sftp_entry_to_dict(a, a.filename) for a in attrs],
            key=lambda e: (not e["is_dir"], e["name"].lower()),
        )
        # Also stat the current directory itself so the UI has its permissions.
        try:
            self_attr = sftp.stat(resolved)
            self_info = _sftp_entry_to_dict(self_attr, resolved.split("/")[-1] or "/")
        except Exception:
            self_info = None
        sftp.close()
        return {"path": resolved, "entries": entries, "self": self_info}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"SFTP error: {exc}") from exc
    finally:
        if client:
            client.close()


@app.get("/api/file-explorer/{server_id}/read")
def file_explorer_read(server_id: int, path: str = Query(...), request: Request = None, db: Session = Depends(get_db)):
    require_api_user(request, db, admin=True)
    server = db.query(Server).filter(Server.id == server_id).first()
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")

    resolved = _resolve_sftp_path(path)
    client = None
    try:
        client, sftp = _sftp_for_server(server, db)
        try:
            attr = sftp.stat(resolved)
        except FileNotFoundError:
            raise HTTPException(status_code=404, detail="File not found")

        import stat as stat_mod
        if stat_mod.S_ISDIR(attr.st_mode or 0):
            raise HTTPException(status_code=400, detail="Path is a directory")

        if (attr.st_size or 0) > FILE_EXPLORER_MAX_READ_BYTES:
            raise HTTPException(status_code=413, detail=f"File too large to edit (max {FILE_EXPLORER_MAX_READ_BYTES // 1024 // 1024} MB)")

        with sftp.open(resolved, "rb") as fh:
            raw = fh.read(FILE_EXPLORER_BINARY_SNIFF_BYTES)
            if b"\x00" in raw:  # binary sniff
                sftp.close()
                return {"path": resolved, "binary": True, "content": None, "size": attr.st_size}
            rest = fh.read()  # read remainder
        content = (raw + rest).decode("utf-8", errors="replace")
        sftp.close()
        return {"path": resolved, "binary": False, "content": content, "size": attr.st_size}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"SFTP read error: {exc}") from exc
    finally:
        if client:
            client.close()


@app.post("/api/file-explorer/{server_id}/write")
async def file_explorer_write(server_id: int, request: Request, path: str = Query(...), db: Session = Depends(get_db)):
    actor = require_api_user(request, db, admin=True)
    server = db.query(Server).filter(Server.id == server_id).first()
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")

    resolved = _resolve_sftp_path(path)
    body = await request.body()
    if len(body) > FILE_EXPLORER_MAX_READ_BYTES:
        raise HTTPException(status_code=413, detail="Content too large")

    client = None
    try:
        client, sftp = _sftp_for_server(server, db)
        with sftp.open(resolved, "wb") as fh:
            fh.write(body)
        sftp.close()
        log_audit(db, "file.write", request=request, actor=actor,
                  target_type="server", target_id=server.id, target_label=server.name,
                  detail=f"Wrote file {resolved} on {server.host}")
        return {"ok": True, "path": resolved}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"SFTP write error: {exc}") from exc
    finally:
        if client:
            client.close()


@app.post("/api/file-explorer/{server_id}/chmod")
def file_explorer_chmod(server_id: int, path: str = Query(...), mode: str = Query(...), request: Request = None, db: Session = Depends(get_db)):
    actor = require_api_user(request, db, admin=True)
    server = db.query(Server).filter(Server.id == server_id).first()
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")

    resolved = _resolve_sftp_path(path)
    try:
        mode_int = int(mode, 8)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid mode; expected octal string e.g. 644")
    if not (0o000 <= mode_int <= 0o7777):
        raise HTTPException(status_code=400, detail="Mode out of range")

    client = None
    try:
        client, sftp = _sftp_for_server(server, db)
        sftp.chmod(resolved, mode_int)
        sftp.close()
        log_audit(db, "file.chmod", request=request, actor=actor,
                  target_type="server", target_id=server.id, target_label=server.name,
                  detail=f"chmod {mode} {resolved} on {server.host}")
        return {"ok": True, "path": resolved, "mode": mode}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"SFTP chmod error: {exc}") from exc
    finally:
        if client:
            client.close()


@app.post("/api/file-explorer/{server_id}/mkdir")
def file_explorer_mkdir(server_id: int, path: str = Query(...), request: Request = None, db: Session = Depends(get_db)):
    actor = require_api_user(request, db, admin=True)
    server = db.query(Server).filter(Server.id == server_id).first()
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")

    resolved = _resolve_sftp_path(path)
    client = None
    try:
        client, sftp = _sftp_for_server(server, db)
        sftp.mkdir(resolved)
        sftp.close()
        log_audit(db, "file.mkdir", request=request, actor=actor,
                  target_type="server", target_id=server.id, target_label=server.name,
                  detail=f"mkdir {resolved} on {server.host}")
        return {"ok": True, "path": resolved}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"SFTP mkdir error: {exc}") from exc
    finally:
        if client:
            client.close()


@app.post("/api/file-explorer/{server_id}/rename")
def file_explorer_rename(server_id: int, path: str = Query(...), new_path: str = Query(...), request: Request = None, db: Session = Depends(get_db)):
    actor = require_api_user(request, db, admin=True)
    server = db.query(Server).filter(Server.id == server_id).first()
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")

    resolved_src = _resolve_sftp_path(path)
    resolved_dst = _resolve_sftp_path(new_path)
    client = None
    try:
        client, sftp = _sftp_for_server(server, db)
        sftp.rename(resolved_src, resolved_dst)
        sftp.close()
        log_audit(db, "file.rename", request=request, actor=actor,
                  target_type="server", target_id=server.id, target_label=server.name,
                  detail=f"rename {resolved_src} -> {resolved_dst} on {server.host}")
        return {"ok": True, "from": resolved_src, "to": resolved_dst}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"SFTP rename error: {exc}") from exc
    finally:
        if client:
            client.close()


@app.delete("/api/file-explorer/{server_id}/delete")
def file_explorer_delete(server_id: int, path: str = Query(...), request: Request = None, db: Session = Depends(get_db)):
    actor = require_api_user(request, db, admin=True)
    server = db.query(Server).filter(Server.id == server_id).first()
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")

    resolved = _resolve_sftp_path(path)
    if resolved == "/":
        raise HTTPException(status_code=400, detail="Cannot delete the root directory")

    client = None
    try:
        client, sftp = _sftp_for_server(server, db)
        import stat as stat_mod
        attr = sftp.stat(resolved)
        if stat_mod.S_ISDIR(attr.st_mode or 0):
            sftp.rmdir(resolved)
        else:
            sftp.remove(resolved)
        sftp.close()
        log_audit(db, "file.delete", request=request, actor=actor,
                  target_type="server", target_id=server.id, target_label=server.name,
                  detail=f"delete {resolved} on {server.host}")
        return {"ok": True, "path": resolved}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"SFTP delete error: {exc}") from exc
    finally:
        if client:
            client.close()


@app.get("/api/file-explorer/{server_id}/download")
def file_explorer_download(server_id: int, path: str = Query(...), request: Request = None, db: Session = Depends(get_db)):
    require_api_user(request, db, admin=True)
    server = db.query(Server).filter(Server.id == server_id).first()
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")

    resolved = _resolve_sftp_path(path)
    filename = resolved.split("/")[-1] or "download"

    # We must keep the SSH client open while streaming; close it in a generator.
    try:
        client, sftp = _sftp_for_server(server, db)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"SFTP connection failed: {exc}") from exc

    def _stream():
        try:
            with sftp.open(resolved, "rb") as fh:
                while True:
                    chunk = fh.read(65536)
                    if not chunk:
                        break
                    yield chunk
        finally:
            sftp.close()
            client.close()

    import urllib.parse
    safe_filename = urllib.parse.quote(filename)
    return StreamingResponse(
        _stream(),
        media_type="application/octet-stream",
        headers={"Content-Disposition": f"attachment; filename*=UTF-8''{safe_filename}"},
    )


@app.post("/api/file-explorer/{server_id}/upload")
async def file_explorer_upload(server_id: int, request: Request, path: str = Query(...), db: Session = Depends(get_db)):
    """Upload a single file. The raw request body is written to the given remote path."""
    actor = require_api_user(request, db, admin=True)
    server = db.query(Server).filter(Server.id == server_id).first()
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")

    resolved = _resolve_sftp_path(path)
    body = await request.body()
    if len(body) > FILE_EXPLORER_MAX_READ_BYTES:
        raise HTTPException(status_code=413, detail="Upload too large (max 2 MB via browser)")

    client = None
    try:
        client, sftp = _sftp_for_server(server, db)
        with sftp.open(resolved, "wb") as fh:
            fh.write(body)
        sftp.close()
        log_audit(db, "file.upload", request=request, actor=actor,
                  target_type="server", target_id=server.id, target_label=server.name,
                  detail=f"Uploaded file to {resolved} on {server.host}")
        return {"ok": True, "path": resolved}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"SFTP upload error: {exc}") from exc
    finally:
        if client:
            client.close()


@app.post("/api/servers", response_model=ServerRead)
def create_server(server_data: ServerCreate, request: Request, db: Session = Depends(get_db)):
    require_api_user(request, db, admin=True)

    existing = db.query(Server).filter(Server.name == server_data.name).first()
    if existing:
        raise HTTPException(status_code=400, detail="Server name already exists")

    server = Server(**server_data.model_dump())
    db.add(server)
    db.commit()
    db.refresh(server)
    actor = get_session_user(request, db)
    log_audit(db, "server.create", request=request, actor=actor,
              target_type="server", target_id=server.id, target_label=server.name,
              detail=f"host={server.host}:{server.port}; user={server.username}; auth={server.auth_method}")
    return server


@app.put("/api/servers/{server_id}", response_model=ServerRead)
def update_server(server_id: int, payload: ServerUpdate, request: Request, db: Session = Depends(get_db)):
    require_api_user(request, db, admin=True)

    server = db.query(Server).filter(Server.id == server_id).first()
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")

    updates = payload.model_dump(exclude_unset=True)

    if "name" in updates:
        clean_name = (updates.get("name") or "").strip()
        if not clean_name:
            raise HTTPException(status_code=400, detail="Server name cannot be empty")
        existing = db.query(Server).filter(Server.name == clean_name, Server.id != server_id).first()
        if existing:
            raise HTTPException(status_code=400, detail="Server name already exists")
        server.name = clean_name

    if "host" in updates:
        server.host = (updates.get("host") or "").strip()
    if "port" in updates and updates.get("port") is not None:
        server.port = updates["port"]
    if "username" in updates:
        server.username = (updates.get("username") or "").strip()

    auth_method = updates.get("auth_method", server.auth_method)
    if auth_method == "password":
        password = updates.get("password")
        if password:
            server.password = password
        if not server.password:
            raise HTTPException(status_code=400, detail="SSH password is required for password auth")
        server.auth_method = "password"
        server.ssh_key_id = None
    elif auth_method == "key":
        ssh_key_id = updates.get("ssh_key_id", server.ssh_key_id)
        if not ssh_key_id:
            raise HTTPException(status_code=400, detail="SSH key is required for key auth")
        if not db.query(SSHKey).filter(SSHKey.id == ssh_key_id).first():
            raise HTTPException(status_code=400, detail="Selected SSH key does not exist")
        server.auth_method = "key"
        server.ssh_key_id = ssh_key_id
        server.password = None

    if "sudo_password" in updates:
        server.sudo_password = updates.get("sudo_password") or None
    if "alert_cpu_threshold" in updates and updates.get("alert_cpu_threshold") is not None:
        server.alert_cpu_threshold = int(updates["alert_cpu_threshold"])
    if "alert_ram_threshold" in updates and updates.get("alert_ram_threshold") is not None:
        server.alert_ram_threshold = int(updates["alert_ram_threshold"])
    if "alert_storage_threshold" in updates and updates.get("alert_storage_threshold") is not None:
        server.alert_storage_threshold = int(updates["alert_storage_threshold"])
    if "alert_load_avg_threshold" in updates and updates.get("alert_load_avg_threshold") is not None:
        server.alert_load_avg_threshold = float(updates["alert_load_avg_threshold"])
    if "alert_load_avg_5_threshold" in updates and updates.get("alert_load_avg_5_threshold") is not None:
        server.alert_load_avg_5_threshold = float(updates["alert_load_avg_5_threshold"])
    if "alert_load_avg_15_threshold" in updates and updates.get("alert_load_avg_15_threshold") is not None:
        server.alert_load_avg_15_threshold = float(updates["alert_load_avg_15_threshold"])

    changed_fields = sorted(updates.keys())
    db.commit()
    db.refresh(server)
    actor = get_session_user(request, db)
    log_audit(db, "server.update", request=request, actor=actor,
              target_type="server", target_id=server.id, target_label=server.name,
              detail=(
                  f"fields={', '.join(changed_fields) if changed_fields else 'none'}; "
                  f"host={server.host}:{server.port}; user={server.username}; auth={server.auth_method}"
              ))
    return server


@app.get("/api/servers", response_model=list[ServerRead])
def list_servers(request: Request, db: Session = Depends(get_db)):
    require_api_user(request, db)
    return db.query(Server).order_by(Server.name.asc()).all()


@app.delete("/api/servers/{server_id}")
def delete_server(server_id: int, request: Request, db: Session = Depends(get_db)):
    require_api_user(request, db, admin=True)

    server = db.query(Server).filter(Server.id == server_id).first()
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")

    # Remove dependent update jobs first to avoid setting non-null server_id to NULL.
    db.query(UpdateJob).filter(UpdateJob.server_id == server_id).delete(synchronize_session=False)

    # Remove this server from all schedules; delete schedules that would become empty.
    schedules = db.query(UpdateSchedule).all()
    for schedule in schedules:
        ids = schedule.server_ids
        if server_id not in ids:
            continue
        remaining_ids = [sid for sid in ids if sid != server_id]
        if not remaining_ids:
            db.delete(schedule)
        else:
            schedule.server_ids = remaining_ids

    db.delete(server)
    db.commit()
    actor = get_session_user(request, db)
    log_audit(db, "server.delete", request=request, actor=actor,
              target_type="server", target_id=server_id, target_label=server.name,
              detail=f"Deleted server host={server.host}:{server.port}; user={server.username}")
    return {"message": "Server deleted"}


@app.post("/api/updates/run")
def run_updates(payload: UpdateRequest, request: Request, db: Session = Depends(get_db)):
    require_api_user(request, db, admin=True)

    servers = db.query(Server).filter(Server.id.in_(payload.server_ids)).all()
    if not servers:
        raise HTTPException(status_code=404, detail="No matching servers found")

    created_jobs = enqueue_update_jobs(db, servers, payload.package_manager, apt_extra_steps=payload.apt_extra_steps, job_type="manual", alert_only=payload.alert_only)
    actor = get_session_user(request, db)
    server_names = ", ".join(s.name for s in servers)
    log_audit(db, "update.run", request=request, actor=actor,
              detail=f"Servers: {server_names}; package_manager: {payload.package_manager}; apt_extra_steps: {','.join(payload.apt_extra_steps) or 'none'}; alert_only: {payload.alert_only}")
    return {"job_ids": created_jobs}


@app.post("/api/schedules", response_model=UpdateScheduleRead)
def create_schedule(payload: UpdateScheduleCreate, request: Request, db: Session = Depends(get_db)):
    current_user = require_api_user(request, db, admin=True)

    if db.query(UpdateSchedule).filter(UpdateSchedule.name == payload.name).first():
        raise HTTPException(status_code=400, detail="Schedule name already exists")

    servers = db.query(Server).filter(Server.id.in_(payload.server_ids)).all()
    if len(servers) != len(set(payload.server_ids)):
        raise HTTPException(status_code=400, detail="One or more servers in the schedule do not exist")

    cron_expr = payload.cron_expression.strip()
    if not croniter.is_valid(cron_expr):
        raise HTTPException(status_code=400, detail="Invalid cron expression")

    if payload.auto_disable_on_failures and not payload.failure_threshold:
        raise HTTPException(status_code=400, detail="Failure threshold is required when automatic disable is enabled")

    schedule = UpdateSchedule(
        name=payload.name.strip(),
        package_manager=payload.package_manager,
        cron_expression=cron_expr,
        timezone=get_effective_timezone(current_user),
        interval_minutes=payload.interval_minutes or 60,
        enabled=payload.enabled,
        auto_disable_on_failures=payload.auto_disable_on_failures,
        failure_threshold=payload.failure_threshold if payload.auto_disable_on_failures else None,
        next_run_at=datetime.utcnow(),
    )
    schedule.server_ids = sorted(set(payload.server_ids))
    schedule.disabled_server_ids = []
    schedule.apt_extra_steps = [s for s in payload.apt_extra_steps if s]
    schedule.alert_only = payload.alert_only
    schedule.next_run_at = get_next_schedule_run(schedule, datetime.utcnow())

    db.add(schedule)
    db.commit()
    db.refresh(schedule)
    server_names = ", ".join(server.name for server in servers)
    log_audit(db, "schedule.create", request=request, actor=current_user,
              target_type="schedule", target_id=schedule.id, target_label=schedule.name,
              detail=(
                  f"Servers: {server_names}; cron: {schedule.cron_expression}; package_manager: {schedule.package_manager}; "
                  f"apt_extra_steps: {','.join(payload.apt_extra_steps) or 'none'}; "
                  f"alert_only: {schedule.alert_only}; "
                  f"auto_disable_on_failures={schedule.auto_disable_on_failures}; failure_threshold={schedule.failure_threshold or 'off'}"
              ))
    return schedule


@app.put("/api/schedules/{schedule_id}", response_model=UpdateScheduleRead)
def update_schedule(schedule_id: int, payload: UpdateScheduleUpdate, request: Request, db: Session = Depends(get_db)):
    current_user = require_api_user(request, db, admin=True)

    schedule = db.query(UpdateSchedule).filter(UpdateSchedule.id == schedule_id).first()
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")

    clean_name = payload.name.strip()
    duplicate = (
        db.query(UpdateSchedule)
        .filter(UpdateSchedule.name == clean_name, UpdateSchedule.id != schedule_id)
        .first()
    )
    if duplicate:
        raise HTTPException(status_code=400, detail="Schedule name already exists")

    servers = db.query(Server).filter(Server.id.in_(payload.server_ids)).all()
    if len(servers) != len(set(payload.server_ids)):
        raise HTTPException(status_code=400, detail="One or more servers in the schedule do not exist")

    cron_expr = payload.cron_expression.strip()
    if not croniter.is_valid(cron_expr):
        raise HTTPException(status_code=400, detail="Invalid cron expression")

    if payload.auto_disable_on_failures and not payload.failure_threshold:
        raise HTTPException(status_code=400, detail="Failure threshold is required when automatic disable is enabled")

    schedule.name = clean_name
    schedule.package_manager = payload.package_manager
    schedule.cron_expression = cron_expr
    schedule.server_ids = sorted(set(payload.server_ids))
    schedule.auto_disable_on_failures = payload.auto_disable_on_failures
    schedule.failure_threshold = payload.failure_threshold if payload.auto_disable_on_failures else None
    schedule.disabled_server_ids = []
    schedule.apt_extra_steps = [s for s in payload.apt_extra_steps if s]
    schedule.alert_only = payload.alert_only
    if payload.enabled is not None:
        schedule.enabled = payload.enabled

    if schedule.enabled:
        schedule.next_run_at = get_next_schedule_run(schedule, datetime.utcnow())

    db.commit()
    db.refresh(schedule)
    server_names = ", ".join(server.name for server in servers)
    log_audit(db, "schedule.update", request=request, actor=current_user,
              target_type="schedule", target_id=schedule.id, target_label=schedule.name,
              detail=(
                  f"Servers: {server_names}; cron: {schedule.cron_expression}; package_manager: {schedule.package_manager}; "
                  f"apt_extra_steps: {','.join(schedule.apt_extra_steps) or 'none'}; "
                  f"alert_only: {schedule.alert_only}; "
                  f"enabled: {schedule.enabled}; auto_disable_on_failures={schedule.auto_disable_on_failures}; "
                  f"failure_threshold={schedule.failure_threshold or 'off'}; disabled servers reset"
              ))
    return schedule


@app.get("/api/schedules", response_model=list[UpdateScheduleRead])
def list_schedules(request: Request, db: Session = Depends(get_db)):
    require_api_user(request, db)
    return db.query(UpdateSchedule).order_by(UpdateSchedule.created_at.desc()).all()


@app.post("/api/schedules/{schedule_id}/toggle", response_model=UpdateScheduleRead)
def toggle_schedule(schedule_id: int, request: Request, db: Session = Depends(get_db)):
    require_api_user(request, db, admin=True)

    schedule = db.query(UpdateSchedule).filter(UpdateSchedule.id == schedule_id).first()
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")

    schedule.enabled = not schedule.enabled
    if schedule.enabled:
        schedule.next_run_at = get_next_schedule_run(schedule, datetime.utcnow())
    db.commit()
    db.refresh(schedule)
    actor = get_session_user(request, db)
    log_audit(db, "schedule.enable" if schedule.enabled else "schedule.disable", request=request, actor=actor,
              target_type="schedule", target_id=schedule.id, target_label=schedule.name,
              detail=f"enabled={schedule.enabled}; next_run_at={schedule.next_run_at}")
    return schedule


@app.delete("/api/schedules/{schedule_id}")
def delete_schedule(schedule_id: int, request: Request, db: Session = Depends(get_db)):
    require_api_user(request, db, admin=True)

    schedule = db.query(UpdateSchedule).filter(UpdateSchedule.id == schedule_id).first()
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")

    db.delete(schedule)
    db.commit()
    actor = get_session_user(request, db)
    log_audit(db, "schedule.delete", request=request, actor=actor,
              target_type="schedule", target_id=schedule_id, target_label=schedule.name,
              detail=f"Deleted schedule cron={schedule.cron_expression}; package_manager={schedule.package_manager}")
    return {"message": "Schedule deleted"}


@app.get("/api/updates", response_model=list[UpdateJobRead])
def list_update_jobs(request: Request, limit: int = 50, db: Session = Depends(get_db)):
    require_api_user(request, db)

    safe_limit = max(1, min(limit, 200))
    jobs = db.query(UpdateJob).order_by(UpdateJob.created_at.desc()).limit(safe_limit).all()
    return jobs


@app.get("/api/updates/{job_id}", response_model=UpdateJobRead)
def get_update_job(job_id: int, request: Request, db: Session = Depends(get_db)):
    current_user = require_api_user(request, db)

    job = db.query(UpdateJob).filter(UpdateJob.id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Update job not found")
    log_audit(
        db,
        "update.check.output",
        request=request,
        actor=current_user,
        target_type="update_job",
        target_id=job.id,
        target_label=f"Job #{job.id}",
        detail=f"Viewed job output status={job.status}; server_id={job.server_id}",
    )
    return job
