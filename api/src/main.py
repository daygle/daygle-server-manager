from __future__ import annotations

from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from pathlib import Path
import smtplib
from threading import Thread
from time import sleep
from urllib.parse import urlencode
from zoneinfo import ZoneInfo, available_timezones

from fastapi import Depends, FastAPI, Form, HTTPException, Request
from croniter import croniter
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, or_, text
from sqlalchemy.orm import Session
from starlette.middleware.sessions import SessionMiddleware

from .config import get_setting
from .database import Base, SessionLocal, engine, get_db
from .models import Alert, AppSetting, AuditLog, SSHKey, Server, UpdateJob, UpdateSchedule, User
from .schemas import (
    SSHKeyCreate,
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
from .ssh_updater import run_update_job

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
LOGIN_TIMEOUT_SETTING_KEY = "login_timeout_minutes"
EMAIL_ALERTS_ENABLED_SETTING_KEY = "email_alerts_enabled"
SMTP_HOST_SETTING_KEY = "smtp_host"
SMTP_PORT_SETTING_KEY = "smtp_port"
SMTP_USERNAME_SETTING_KEY = "smtp_username"
SMTP_PASSWORD_SETTING_KEY = "smtp_password"
SMTP_USE_TLS_SETTING_KEY = "smtp_use_tls"
SMTP_FROM_SETTING_KEY = "smtp_from"
DEFAULT_THEME_SETTING_KEY = "default_theme"
DEFAULT_DATE_FORMAT = "iso-24"
DEFAULT_TIMEZONE = "UTC"
DEFAULT_THEME = "system"
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
DATE_FORMAT_OPTIONS: list[tuple[str, str, str]] = [
    ("iso-24", "YYYY-MM-DD HH:MM:SS", "%Y-%m-%d %H:%M:%S"),
    ("us-24", "MM/DD/YYYY HH:MM:SS", "%m/%d/%Y %H:%M:%S"),
    ("eu-24", "DD/MM/YYYY HH:MM:SS", "%d/%m/%Y %H:%M:%S"),
    ("month-name", "DD Mon YYYY HH:MM:SS", "%d %b %Y %H:%M:%S"),
]
DATE_FORMAT_MAP = {key: pattern for key, _, pattern in DATE_FORMAT_OPTIONS}


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
    finally:
        db.close()
    if not getattr(app.state, "schedule_worker_started", False):
        app.state.schedule_worker_started = True
        thread = Thread(target=run_schedule_loop, daemon=True)
        thread.start()


def ensure_schema_columns() -> None:
    # Add compatibility columns/types on existing databases without requiring migrations.
    statements = [
        "ALTER TABLE update_schedules ADD COLUMN IF NOT EXISTS cron_expression VARCHAR(120)",
        "ALTER TABLE update_schedules ADD COLUMN IF NOT EXISTS timezone VARCHAR(64)",
        "ALTER TABLE update_jobs ALTER COLUMN command TYPE TEXT",
        "ALTER TABLE update_jobs ADD COLUMN IF NOT EXISTS summary VARCHAR(255)",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS date_format VARCHAR(32)",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS timezone VARCHAR(64)",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS theme_preference VARCHAR(16)",
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

    msg = EmailMessage()
    msg["Subject"] = f"[Daygle Alert] {alert.title}"
    msg["From"] = sender
    msg["To"] = ", ".join(recipients)
    msg.set_content(
        f"A server alert was generated.\n\n"
        f"Level: {alert.level}\n"
        f"Title: {alert.title}\n"
        f"Message: {alert.message}\n"
        f"Source: {alert.source_type or '-'} {alert.source_id or ''}\n"
        f"Time (UTC): {alert.created_at.isoformat()}\n"
    )

    with smtplib.SMTP(host=host, port=port, timeout=15) as smtp:
        smtp.ehlo()
        if use_tls:
            smtp.starttls()
            smtp.ehlo()
        if username and password:
            smtp.login(username, password)
        smtp.send_message(msg)


def test_smtp_connection(host: str, port: int, username: str, password: str, use_tls: bool) -> None:
    with smtplib.SMTP(host=host, port=port, timeout=15) as smtp:
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
    days = get_history_retention_days(db)
    if days <= 0:
        return
    cutoff = datetime.utcnow() - timedelta(days=days)
    db.query(UpdateJob).filter(UpdateJob.created_at < cutoff).delete(synchronize_session=False)
    db.query(AuditLog).filter(AuditLog.timestamp < cutoff).delete(synchronize_session=False)
    db.query(Alert).filter(Alert.created_at < cutoff).delete(synchronize_session=False)
    db.commit()


def enqueue_update_jobs(db: Session, servers: list[Server], package_manager: str) -> list[int]:
    created_jobs: list[int] = []
    for server in servers:
        job = UpdateJob(
            server_id=server.id,
            package_manager=package_manager,
            status="pending",
            command="Pending package manager detection...",
        )
        db.add(job)
        db.commit()
        db.refresh(job)

        created_jobs.append(job.id)
        thread = Thread(target=process_job_async, args=(job.id,), daemon=True)
        thread.start()

    return created_jobs


def run_schedule_loop() -> None:
    tick = 0
    while True:
        db = SessionLocal()
        try:
            now = datetime.utcnow()
            due_schedules = (
                db.query(UpdateSchedule)
                .filter(UpdateSchedule.enabled.is_(True), UpdateSchedule.next_run_at <= now)
                .all()
            )

            for schedule in due_schedules:
                servers = db.query(Server).filter(Server.id.in_(schedule.server_ids)).all()
                if servers:
                    enqueue_update_jobs(db, servers, schedule.package_manager)

                schedule.last_run_at = now
                schedule.next_run_at = get_next_schedule_run(schedule, now)
                db.commit()

            # Purge old history once per hour (every 120 × 30-second ticks)
            tick += 1
            if tick >= 120:
                tick = 0
                purge_old_history(db)
        except Exception as exc:
            print(f"[schedule-worker] error: {type(exc).__name__}: {exc}")
        finally:
            db.close()

        sleep(30)


def process_job_async(job_id: int) -> None:
    db = SessionLocal()
    try:
        run_update_job(db, job_id)

        job = db.query(UpdateJob).filter(UpdateJob.id == job_id).first()
        if not job or job.status != "failed":
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
        "global_timezone": global_timezone_name,
        "date_format_options": DATE_FORMAT_OPTIONS,
        "timezone_options": TIMEZONE_OPTIONS,
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
    log_audit(db, "user.login", request=request, actor=user)
    set_flash(request, f"Welcome back, {user.username}.", "success")
    return RedirectResponse(url="/dashboard", status_code=303)


@app.get("/logout")
def logout(request: Request, db: Session = Depends(get_db)) -> RedirectResponse:
    current_user = get_session_user(request, db)
    if current_user:
        log_audit(db, "user.logout", request=request, actor=current_user)
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
    running_jobs = db.query(func.count(UpdateJob.id)).filter(UpdateJob.status == "running").scalar() or 0
    failed_jobs = db.query(func.count(UpdateJob.id)).filter(UpdateJob.status == "failed").scalar() or 0
    latest_jobs = db.query(UpdateJob).order_by(UpdateJob.created_at.desc()).limit(10).all()

    return render_app_template(
        request,
        "dashboard.html",
        "dashboard",
        current_user,
        db,
        total_servers=total_servers,
        running_jobs=running_jobs,
        failed_jobs=failed_jobs,
        latest_jobs=latest_jobs,
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


@app.get("/updates", response_class=HTMLResponse)
def updates_page(request: Request, db: Session = Depends(get_db)):
    return RedirectResponse(url="/updates/manual", status_code=303)


@app.get("/updates/manual", response_class=HTMLResponse)
def updates_manual_page(request: Request, db: Session = Depends(get_db)):
    if not users_exist(db):
        return RedirectResponse(url="/setup", status_code=303)

    current_user = get_session_user(request, db)
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)

    log_audit(db, "update.check", request=request, actor=current_user, detail="Opened manual updates page")

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

    log_audit(db, "update.check", request=request, actor=current_user, detail="Opened scheduled updates page")

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

    log_audit(db, "update.check", request=request, actor=current_user, detail="Opened update jobs page")

    jobs = db.query(UpdateJob).order_by(UpdateJob.created_at.desc()).limit(30).all()
    return render_app_template(
        request,
        "updates_jobs.html",
        "updates-jobs",
        current_user,
        db,
        jobs=jobs,
    )


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
    )


@app.post("/user-settings/save-all")
def save_user_settings(
    request: Request,
    date_format: str = Form(...),
    timezone_name: str = Form(...),
    theme: str = Form(USER_THEME_GLOBAL),
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
        selected_retention_days=get_history_retention_days(db),
        selected_login_timeout_minutes=get_active_login_timeout_minutes(),
        selected_email_alerts_enabled=get_active_email_alerts_enabled(),
        selected_smtp_host=get_smtp_setting(db, SMTP_HOST_SETTING_KEY, "SMTP_HOST", "localhost"),
        selected_smtp_port=get_smtp_setting(db, SMTP_PORT_SETTING_KEY, "SMTP_PORT", "25"),
        selected_smtp_username=get_smtp_setting(db, SMTP_USERNAME_SETTING_KEY, "SMTP_USERNAME", ""),
        selected_smtp_use_tls=parse_bool_setting(get_smtp_setting(db, SMTP_USE_TLS_SETTING_KEY, "SMTP_USE_TLS", "false"), False),
        selected_smtp_from=get_smtp_setting(db, SMTP_FROM_SETTING_KEY, "SMTP_FROM", "daygle-server-manager@localhost"),
        smtp_password_set=bool(get_smtp_setting(db, SMTP_PASSWORD_SETTING_KEY, "SMTP_PASSWORD", "")),
    )


@app.post("/settings/save-all")
def save_all_settings(
    request: Request,
    date_format: str = Form(...),
    timezone_name: str = Form(...),
    default_theme: str = Form(DEFAULT_THEME),
    retention_days: int = Form(...),
    login_timeout_minutes: int = Form(...),
    email_alerts_enabled: str | None = Form(None),
    smtp_host: str = Form(...),
    smtp_port: int = Form(...),
    smtp_username: str = Form(""),
    smtp_password: str = Form(""),
    clear_smtp_password: str | None = Form(None),
    smtp_use_tls: str | None = Form(None),
    smtp_from: str = Form(...),
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

    normalized_retention = normalize_history_retention_days(retention_days)
    if normalized_retention is None:
        set_flash(request, "Invalid retention period.", "error")
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

    prev_retention = get_history_retention_days(db)
    if normalized_retention != prev_retention:
        set_app_setting(db, HISTORY_RETENTION_SETTING_KEY, str(normalized_retention))
        old_label = "keep forever" if prev_retention == 0 else f"{prev_retention} days"
        new_label = "keep forever" if normalized_retention == 0 else f"{normalized_retention} days"
        log_audit(
            db,
            "settings.history_retention",
            request=request,
            actor=current_user,
            detail=f"Changed from {old_label} to {new_label}",
        )
        changed.append("history retention")

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
            password_updated,
        ]
    )

    if smtp_changed:
        set_app_setting(db, SMTP_HOST_SETTING_KEY, host)
        set_app_setting(db, SMTP_PORT_SETTING_KEY, str(smtp_port))
        set_app_setting(db, SMTP_USERNAME_SETTING_KEY, smtp_username_clean)
        set_app_setting(db, SMTP_USE_TLS_SETTING_KEY, "true" if normalized_smtp_tls else "false")
        set_app_setting(db, SMTP_FROM_SETTING_KEY, sender)
        if password_updated:
            set_app_setting(db, SMTP_PASSWORD_SETTING_KEY, new_smtp_password)

        log_audit(
            db,
            "settings.smtp",
            request=request,
            actor=current_user,
            detail=(
                f"Updated SMTP host={host}, port={smtp_port}, user={'set' if smtp_username_clean else 'empty'}, "
                f"tls={'enabled' if normalized_smtp_tls else 'disabled'}, from={sender}, "
                f"password={'updated' if password_updated else 'unchanged'}"
            ),
        )
        changed.append("SMTP settings")

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

    previous_value = get_history_retention_days(db)
    set_app_setting(db, HISTORY_RETENTION_SETTING_KEY, str(normalized))
    old_label = "keep forever" if previous_value == 0 else f"{previous_value} days"
    new_label = "keep forever" if normalized == 0 else f"{normalized} days"
    log_audit(
        db,
        "settings.history_retention",
        request=request,
        actor=current_user,
        detail=f"Changed from {old_label} to {new_label}",
    )
    set_flash(request, "History retention period updated.", "success")
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

    set_app_setting(db, SMTP_HOST_SETTING_KEY, host)
    set_app_setting(db, SMTP_PORT_SETTING_KEY, str(smtp_port))
    set_app_setting(db, SMTP_USERNAME_SETTING_KEY, smtp_username.strip())
    set_app_setting(db, SMTP_USE_TLS_SETTING_KEY, "true" if parse_bool_setting(smtp_use_tls, False) else "false")
    set_app_setting(db, SMTP_FROM_SETTING_KEY, sender)

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
            f"tls={'enabled' if parse_bool_setting(smtp_use_tls, False) else 'disabled'}, from={sender}, "
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

    username = smtp_username.strip()
    use_tls = parse_bool_setting(smtp_use_tls, False)
    password_to_use = smtp_password or get_smtp_setting(db, SMTP_PASSWORD_SETTING_KEY, "SMTP_PASSWORD", "")

    try:
        test_smtp_connection(host, smtp_port, username, password_to_use, use_tls)
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
              target_type="user", target_id=user.id, target_label=clean_username)
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
              target_type="user", target_id=user.id, target_label=user.username)
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

    user.username = clean_username
    user.first_name = first_name.strip() or None
    user.last_name = last_name.strip() or None
    user.email = email.strip() or None
    user.is_admin = is_admin
    user.enabled = enabled

    if password:
        user.password_hash = hash_password(password)

    db.commit()
    log_audit(db, "user.update", request=request, actor=current_user,
              target_type="user", target_id=user.id, target_label=user.username)
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
              target_type="user", target_id=user_id, target_label=user.username)
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

    try:
        page_size = int(request.query_params.get("page_size", "50"))
    except ValueError:
        page_size = 50
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

    try:
        page_size = int(request.query_params.get("page_size", "50"))
    except ValueError:
        page_size = 50
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
    )
    return RedirectResponse(url=request.headers.get("referer", "/alerts"), status_code=303)


@app.post("/api/ssh-keys", response_model=SSHKeyRead)
def create_ssh_key(payload: SSHKeyCreate, request: Request, db: Session = Depends(get_db)):
    require_api_user(request, db, admin=True)

    if db.query(SSHKey).filter(SSHKey.name == payload.name).first():
        raise HTTPException(status_code=400, detail="SSH key name already exists")

    # Derive the public key and type from the supplied private key
    import io as _io
    import paramiko as _paramiko
    try:
        pkey = _paramiko.pkey.load_private_key(_io.StringIO(payload.private_key))
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid private key: {exc}")

    key_type = pkey.get_name()  # e.g. "ssh-ed25519", "ssh-rsa"
    pub_buf = _io.StringIO()
    pkey.write_public_key(pub_buf)
    public_key = pub_buf.getvalue().strip()

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
              target_type="ssh_key", target_id=ssh_key.id, target_label=ssh_key.name)
    return ssh_key


@app.post("/api/ssh-keys/generate", response_model=SSHKeyRead)
def generate_ssh_key(
    request: Request,
    name: str,
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
    import io as _io
    import paramiko as _paramiko

    raw_private = Ed25519PrivateKey.generate()
    pem_bytes = raw_private.private_bytes(Encoding.PEM, PrivateFormat.OpenSSH, NoEncryption())
    private_key_pem = pem_bytes.decode()

    pkey = _paramiko.pkey.load_private_key(_io.StringIO(private_key_pem))
    key_type = pkey.get_name()
    pub_buf = _io.StringIO()
    pkey.write_public_key(pub_buf)
    public_key = pub_buf.getvalue().strip()

    ssh_key = SSHKey(
        name=name,
        private_key=private_key_pem.strip(),
        public_key=public_key,
        key_type=key_type,
    )
    db.add(ssh_key)
    db.commit()
    db.refresh(ssh_key)
    actor = get_session_user(request, db)
    log_audit(db, "ssh_key.generate", request=request, actor=actor,
              target_type="ssh_key", target_id=ssh_key.id, target_label=ssh_key.name)
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
              target_type="ssh_key", target_id=key_id, target_label=ssh_key.name)
    return {"message": "SSH key deleted"}


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
              target_type="server", target_id=server.id, target_label=server.name)
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

    db.commit()
    db.refresh(server)
    actor = get_session_user(request, db)
    log_audit(db, "server.update", request=request, actor=actor,
              target_type="server", target_id=server.id, target_label=server.name)
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
              target_type="server", target_id=server_id, target_label=server.name)
    return {"message": "Server deleted"}


@app.post("/api/updates/run")
def run_updates(payload: UpdateRequest, request: Request, db: Session = Depends(get_db)):
    require_api_user(request, db, admin=True)

    servers = db.query(Server).filter(Server.id.in_(payload.server_ids)).all()
    if not servers:
        raise HTTPException(status_code=404, detail="No matching servers found")

    created_jobs = enqueue_update_jobs(db, servers, payload.package_manager)
    actor = get_session_user(request, db)
    server_names = ", ".join(s.name for s in servers)
    log_audit(db, "update.run", request=request, actor=actor,
              detail=f"Servers: {server_names}; package_manager: {payload.package_manager}")
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

    schedule = UpdateSchedule(
        name=payload.name.strip(),
        package_manager=payload.package_manager,
        cron_expression=cron_expr,
        timezone=get_effective_timezone(current_user),
        interval_minutes=payload.interval_minutes or 60,
        enabled=payload.enabled,
        next_run_at=datetime.utcnow(),
    )
    schedule.server_ids = sorted(set(payload.server_ids))
    schedule.next_run_at = get_next_schedule_run(schedule, datetime.utcnow())

    db.add(schedule)
    db.commit()
    db.refresh(schedule)
    log_audit(db, "schedule.create", request=request, actor=current_user,
              target_type="schedule", target_id=schedule.id, target_label=schedule.name)
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

    schedule.name = clean_name
    schedule.package_manager = payload.package_manager
    schedule.cron_expression = cron_expr
    schedule.server_ids = sorted(set(payload.server_ids))
    if payload.enabled is not None:
        schedule.enabled = payload.enabled

    if schedule.enabled:
        schedule.next_run_at = get_next_schedule_run(schedule, datetime.utcnow())

    db.commit()
    db.refresh(schedule)
    log_audit(db, "schedule.update", request=request, actor=current_user,
              target_type="schedule", target_id=schedule.id, target_label=schedule.name)
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
              target_type="schedule", target_id=schedule.id, target_label=schedule.name)
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
              target_type="schedule", target_id=schedule_id, target_label=schedule.name)
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
    )
    return job
