from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path
from threading import Thread
from time import sleep

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
from .models import SSHKey, Server, UpdateJob, UpdateSchedule, User
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


@app.on_event("startup")
def on_startup() -> None:
    Base.metadata.create_all(bind=engine)
    ensure_schedule_columns()
    if not getattr(app.state, "schedule_worker_started", False):
        app.state.schedule_worker_started = True
        thread = Thread(target=run_schedule_loop, daemon=True)
        thread.start()


def ensure_schedule_columns() -> None:
    # Add new schedule fields on existing databases without requiring migrations.
    statements = [
        "ALTER TABLE update_schedules ADD COLUMN IF NOT EXISTS cron_expression VARCHAR(120)",
    ]
    with engine.begin() as conn:
        for statement in statements:
            conn.execute(text(statement))


def get_next_schedule_run(schedule: UpdateSchedule, from_time: datetime | None = None) -> datetime:
    base_time = from_time or datetime.utcnow()
    if schedule.cron_expression:
        return croniter(schedule.cron_expression, base_time).get_next(datetime)
    return base_time + timedelta(minutes=schedule.interval_minutes)


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
    **context,
):
    template_context = {
        "active_page": active_page,
        "current_user": current_user,
        "flash": pop_flash(request),
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
    set_flash(request, f"Welcome back, {user.username}.", "success")
    return RedirectResponse(url="/dashboard", status_code=303)


@app.get("/logout")
def logout(request: Request) -> RedirectResponse:
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
    return render_app_template(
        request,
        "updates.html",
        "updates",
        current_user,
        servers=servers,
        jobs=jobs,
        schedules=schedules,
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
    return render_app_template(request, "users.html", "users", current_user, users=users)


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
    return render_app_template(request, "ssh_keys.html", "ssh-keys", current_user, ssh_keys=ssh_keys)


@app.get("/help", response_class=HTMLResponse)
def help_page(request: Request, db: Session = Depends(get_db)):
    if not users_exist(db):
        return RedirectResponse(url="/setup", status_code=303)

    current_user = get_session_user(request, db)
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)

    return render_app_template(request, "help.html", "help", current_user)


@app.get("/about", response_class=HTMLResponse)
def about_page(request: Request, db: Session = Depends(get_db)):
    if not users_exist(db):
        return RedirectResponse(url="/setup", status_code=303)

    current_user = get_session_user(request, db)
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)

    return render_app_template(request, "about.html", "about", current_user)


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

    db.delete(server)
    db.commit()
    return {"message": "Server deleted"}


@app.post("/api/updates/run")
def run_updates(payload: UpdateRequest, request: Request, db: Session = Depends(get_db)):
    require_api_user(request, db, admin=True)

    servers = db.query(Server).filter(Server.id.in_(payload.server_ids)).all()
    if not servers:
        raise HTTPException(status_code=404, detail="No matching servers found")

    created_jobs = enqueue_update_jobs(db, servers, payload.package_manager)

    return {"job_ids": created_jobs}


@app.post("/api/schedules", response_model=UpdateScheduleRead)
def create_schedule(payload: UpdateScheduleCreate, request: Request, db: Session = Depends(get_db)):
    require_api_user(request, db, admin=True)

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
        interval_minutes=payload.interval_minutes or 60,
        enabled=payload.enabled,
        next_run_at=croniter(cron_expr, datetime.utcnow()).get_next(datetime),
    )
    schedule.server_ids = sorted(set(payload.server_ids))

    db.add(schedule)
    db.commit()
    db.refresh(schedule)
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
    return schedule


@app.delete("/api/schedules/{schedule_id}")
def delete_schedule(schedule_id: int, request: Request, db: Session = Depends(get_db)):
    require_api_user(request, db, admin=True)

    schedule = db.query(UpdateSchedule).filter(UpdateSchedule.id == schedule_id).first()
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")

    db.delete(schedule)
    db.commit()
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
