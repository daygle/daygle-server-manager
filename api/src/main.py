from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Thread
from time import sleep
from zoneinfo import ZoneInfo, available_timezones

from fastapi import Depends, FastAPI, Form, HTTPException, Request
from croniter import croniter
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, text
from sqlalchemy.orm import Session
from starlette.middleware.sessions import SessionMiddleware

from .config import get_setting
from .database import Base, SessionLocal, engine, get_db
from .models import AppSetting, AuditLog, SSHKey, Server, UpdateJob, UpdateSchedule, User
from .schemas import (
    SSHKeyCreate,
    SSHKeyRead,
    ServerCreate,
    ServerRead,
    ServerUpdate,
    UpdateJobRead,
    UpdateRequest,
    UpdateScheduleCreate,
    UpdateScheduleRead,
)
from .security import hash_password, verify_password
from .ssh_updater import run_update_job

BASE_DIR = Path(__file__).resolve().parent.parent

app = FastAPI(title="Daygle Server Manager", version="0.1.0")

app.add_middleware(
    SessionMiddleware,
    secret_key=get_setting("SESSION_SECRET"),
    max_age=60 * 60 * 8,
)

app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

DATE_FORMAT_SETTING_KEY = "date_format"
TIMEZONE_SETTING_KEY = "timezone"
HISTORY_RETENTION_SETTING_KEY = "history_retention_days"
DEFAULT_DATE_FORMAT = "iso-24"
DEFAULT_TIMEZONE = "UTC"
DEFAULT_HISTORY_RETENTION_DAYS = 90
MAX_HISTORY_RETENTION_DAYS = 3650
USER_DATE_FORMAT_GLOBAL = "global"
USER_TIMEZONE_GLOBAL = "global"
DATE_FORMAT_OPTIONS: list[tuple[str, str, str]] = [
    ("iso-24", "YYYY-MM-DD HH:MM:SS", "%Y-%m-%d %H:%M:%S"),
    ("us-24", "MM/DD/YYYY HH:MM:SS", "%m/%d/%Y %H:%M:%S"),
    ("eu-24", "DD/MM/YYYY HH:MM:SS", "%d/%m/%Y %H:%M:%S"),
    ("month-name", "DD Mon YYYY HH:MM:SS", "%d %b %Y %H:%M:%S"),
]
DATE_FORMAT_MAP = {key: pattern for key, _, pattern in DATE_FORMAT_OPTIONS}
_ALL_TIMEZONES = sorted(available_timezones())
if DEFAULT_TIMEZONE in _ALL_TIMEZONES:
    _ALL_TIMEZONES.remove(DEFAULT_TIMEZONE)
TIMEZONE_OPTIONS: list[tuple[str, str]] = [(DEFAULT_TIMEZONE, DEFAULT_TIMEZONE)] + [
    (timezone_name, timezone_name) for timezone_name in _ALL_TIMEZONES
]


@app.on_event("startup")
def on_startup() -> None:
    Base.metadata.create_all(bind=engine)
    ensure_schema_columns()
    db = SessionLocal()
    try:
        app.state.date_format = get_date_format_setting(db)
        app.state.timezone = get_timezone_setting(db)
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
    return normalized or DEFAULT_TIMEZONE


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


def get_effective_date_format(current_user: User) -> str:
    user_format = normalize_date_format(current_user.date_format)
    if user_format:
        return user_format
    return get_active_date_format()


def get_effective_timezone(current_user: User) -> str:
    user_timezone = normalize_timezone(current_user.timezone)
    if user_timezone:
        return user_timezone
    return get_active_timezone()


def get_history_retention_days(db: Session) -> int:
    raw = get_app_setting(db, HISTORY_RETENTION_SETTING_KEY, str(DEFAULT_HISTORY_RETENTION_DAYS))
    normalized = normalize_history_retention_days(raw)
    return normalized if normalized is not None else DEFAULT_HISTORY_RETENTION_DAYS


def purge_old_history(db: Session) -> None:
    days = get_history_retention_days(db)
    if days <= 0:
        return
    cutoff = datetime.utcnow() - timedelta(days=days)
    db.query(UpdateJob).filter(UpdateJob.created_at < cutoff).delete(synchronize_session=False)
    db.query(AuditLog).filter(AuditLog.timestamp < cutoff).delete(synchronize_session=False)
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
    finally:
        db.close()


def users_exist(db: Session) -> bool:
    return (db.query(func.count(User.id)).scalar() or 0) > 0


def get_session_user(request: Request, db: Session) -> User | None:
    user_id = request.session.get("user_id")
    if not user_id:
        return None

    user = db.query(User).filter(User.id == user_id, User.enabled.is_(True)).first()
    if not user:
        request.session.clear()
        return None
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
    global_timezone_name = get_active_timezone()

    template_context = {
        "active_page": active_page,
        "current_user": current_user,
        "flash": pop_flash(request),
        "date_format": date_format,
        "timezone": timezone_name,
        "global_timezone": global_timezone_name,
        "date_format_options": DATE_FORMAT_OPTIONS,
        "timezone_options": TIMEZONE_OPTIONS,
        "format_dt": lambda value: format_datetime_value(value, date_format, timezone_name),
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
    if not users_exist(db):
        return RedirectResponse(url="/setup", status_code=303)

    current_user = get_session_user(request, db)
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)

    servers = db.query(Server).order_by(Server.name.asc()).all()
    jobs = db.query(UpdateJob).order_by(UpdateJob.created_at.desc()).limit(30).all()
    schedules = db.query(UpdateSchedule).order_by(UpdateSchedule.created_at.desc()).all()
    server_name_map = {s.id: s.name for s in servers}
    return render_app_template(
        request,
        "updates.html",
        "updates",
        current_user,
        db,
        servers=servers,
        jobs=jobs,
        schedules=schedules,
        server_name_map=server_name_map,
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


@app.get("/my-settings", response_class=HTMLResponse)
def my_settings_page(request: Request, db: Session = Depends(get_db)):
    if not users_exist(db):
        return RedirectResponse(url="/setup", status_code=303)

    current_user = get_session_user(request, db)
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)

    return render_app_template(
        request,
        "my_settings.html",
        "my-settings",
        current_user,
        db,
        selected_user_date_format=current_user.date_format or USER_DATE_FORMAT_GLOBAL,
        selected_user_timezone=current_user.timezone or USER_TIMEZONE_GLOBAL,
    )


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
        return RedirectResponse(url="/my-settings", status_code=303)

    normalized = normalize_date_format(date_format)
    if not normalized:
        set_flash(request, "Invalid date format selection.", "error")
        return RedirectResponse(url="/my-settings", status_code=303)

    current_user.date_format = normalized
    db.commit()
    set_flash(request, "Your personal date format was updated.", "success")
    return RedirectResponse(url="/my-settings", status_code=303)


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
        return RedirectResponse(url="/my-settings", status_code=303)

    normalized = normalize_timezone(timezone_name)
    if not normalized:
        set_flash(request, "Invalid timezone selection.", "error")
        return RedirectResponse(url="/my-settings", status_code=303)

    current_user.timezone = normalized
    db.commit()
    set_flash(request, "Your personal timezone was updated.", "success")
    return RedirectResponse(url="/my-settings", status_code=303)


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
        selected_retention_days=get_history_retention_days(db),
    )


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
    if not normalized:
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

    entries = db.query(AuditLog).order_by(AuditLog.timestamp.desc()).limit(500).all()
    return render_app_template(request, "audit_log.html", "audit-log", current_user, db, entries=entries)


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
    require_api_user(request, db)

    job = db.query(UpdateJob).filter(UpdateJob.id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Update job not found")
    return job
