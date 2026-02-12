from __future__ import annotations

import secrets
import time
from collections import defaultdict, deque
from datetime import datetime
from pathlib import Path
from typing import Iterable

from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template,
    request,
    send_from_directory,
    url_for,
    jsonify,
)
from flask_login import (
    LoginManager,
    UserMixin,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from flask_wtf import FlaskForm
from sqlalchemy import ForeignKey, create_engine, select
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    mapped_column,
    relationship,
    sessionmaker,
)
from wtforms import BooleanField, FloatField, PasswordField, SelectField, StringField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Email, EqualTo, Length, NumberRange, Optional
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

from config import Config

# --- App setup --------------------------------------------------------------
app = Flask(__name__)
app.config.from_object(Config)

Path(app.instance_path).mkdir(parents=True, exist_ok=True)
Path(app.config["UPLOAD_FOLDER"]).mkdir(parents=True, exist_ok=True)

_sqlite_kwargs = {"check_same_thread": False} if app.config["SQLALCHEMY_DATABASE_URI"].startswith("sqlite") else {}
engine = create_engine(
    app.config["SQLALCHEMY_DATABASE_URI"],
    echo=False,
    future=True,
    connect_args=_sqlite_kwargs,
)
SessionLocal = sessionmaker(bind=engine, future=True, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


# --- Models ----------------------------------------------------------------
class User(UserMixin, Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(unique=True, index=True)
    name: Mapped[str]
    password_hash: Mapped[str]
    created_at: Mapped[datetime] = mapped_column(default=datetime.utcnow)
    videos: Mapped[list["Video"]] = relationship(
        back_populates="owner",
        cascade="all, delete-orphan",
    )

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)


class Video(Base):
    __tablename__ = "videos"

    id: Mapped[int] = mapped_column(primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    filename: Mapped[str]
    title: Mapped[str] = mapped_column(index=True)
    description: Mapped[str] = mapped_column(default="")
    subject: Mapped[str] = mapped_column(default="Geral")
    level: Mapped[str] = mapped_column(default="Ensino Médio")
    is_published: Mapped[bool] = mapped_column(default=False)
    created_at: Mapped[datetime] = mapped_column(default=datetime.utcnow, index=True)
    start_time: Mapped[float] = mapped_column(default=0.0)
    end_time: Mapped[float] = mapped_column(default=-1.0)

    owner: Mapped[User] = relationship(back_populates="videos")


Base.metadata.create_all(engine)


# --- Login manager ---------------------------------------------------------
login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message_category = "warning"


@login_manager.user_loader
def load_user(user_id: str) -> User | None:
    if not user_id:
        return None
    with SessionLocal() as db:
        return db.get(User, int(user_id))


# --- Forms -----------------------------------------------------------------
SUBJECT_CHOICES: Iterable[tuple[str, str]] = [
    ("Matemática", "Matemática"),
    ("Física", "Física"),
    ("Química", "Química"),
    ("Biologia", "Biologia"),
    ("História", "História"),
    ("Geografia", "Geografia"),
    ("Português", "Português"),
    ("Inglês", "Inglês"),
    ("Geral", "Geral"),
]
LEVEL_CHOICES: Iterable[tuple[str, str]] = [
    ("Fundamental II", "Fundamental II"),
    ("Ensino Médio", "Ensino Médio"),
    ("Pré-vestibular", "Pré-vestibular"),
]


class RegisterForm(FlaskForm):
    name = StringField("Nome", validators=[DataRequired(), Length(max=80)])
    email = StringField("Email", validators=[DataRequired(), Email(), Length(max=120)])
    password = PasswordField("Senha", validators=[DataRequired(), Length(min=6, max=128)])
    confirm = PasswordField("Confirmar Senha", validators=[DataRequired(), EqualTo("password")])
    submit = SubmitField("Criar conta")


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email(), Length(max=120)])
    password = PasswordField("Senha", validators=[DataRequired()])
    submit = SubmitField("Entrar")


class UploadForm(FlaskForm):
    title = StringField("Título", validators=[DataRequired(), Length(max=120)])
    description = TextAreaField("Descrição", validators=[Optional(), Length(max=1000)])
    subject = SelectField("Matéria", choices=list(SUBJECT_CHOICES), validators=[DataRequired()])
    level = SelectField("Nível", choices=list(LEVEL_CHOICES), validators=[DataRequired()])
    submit = SubmitField("Enviar")


class EditVideoForm(FlaskForm):
    title = StringField("Título", validators=[DataRequired(), Length(max=120)])
    description = TextAreaField("Descrição", validators=[Optional(), Length(max=1000)])
    subject = SelectField("Matéria", choices=list(SUBJECT_CHOICES), validators=[DataRequired()])
    level = SelectField("Nível", choices=list(LEVEL_CHOICES), validators=[DataRequired()])
    start_time = FloatField("Início (s)", validators=[Optional(), NumberRange(min=0)])
    end_time = FloatField("Fim (s) (-1 = até o fim)", validators=[Optional()])
    is_published = BooleanField("Publicado?")
    submit = SubmitField("Salvar alterações")




@app.context_processor
def inject_globals():
    return {
        "config": app.config,
        "subject_options": [item[0] for item in SUBJECT_CHOICES],
        "level_options": [item[0] for item in LEVEL_CHOICES],
    }

# --- Helpers ---------------------------------------------------------------
_rate_buckets: defaultdict[str, deque[float]] = defaultdict(deque)


def _allowed_file(filename: str) -> bool:
    if "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[1].lower()
    return ext in app.config["ALLOWED_EXTENSIONS"]


def _rate_limited() -> bool:
    endpoint = request.endpoint or "global"
    if endpoint.startswith("static"):
        return False
    limit = app.config.get("RATE_LIMIT_REQUESTS", 100)
    window = app.config.get("RATE_LIMIT_WINDOW_SECONDS", 60)
    key = f"{request.method}:{endpoint}:{request.remote_addr}"
    now = time.monotonic()
    bucket = _rate_buckets[key]
    while bucket and now - bucket[0] > window:
        bucket.popleft()
    if len(bucket) >= limit:
        return True
    bucket.append(now)
    return False


@app.before_request
def apply_rate_limit() -> None:
    if request.method in {"POST", "PUT", "DELETE"}:
        if _rate_limited():
            abort(429)


@app.after_request
def add_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    return response


# --- Routes ----------------------------------------------------------------
@app.route("/")
def index():
    search = request.args.get("q", "").strip()
    subject = request.args.get("subject", "")
    level = request.args.get("level", "")
    with SessionLocal() as db:
        stmt = select(Video).where(Video.is_published.is_(True)).order_by(Video.created_at.desc())
        if search:
            stmt = stmt.where(Video.title.ilike(f"%{search}%"))
        if subject:
            stmt = stmt.where(Video.subject == subject)
        if level:
            stmt = stmt.where(Video.level == level)
        videos = list(db.scalars(stmt))
    return render_template(
        "index.html",
        videos=videos,
        q=search,
        subject=subject,
        level=level,
        subjects=[choice[0] for choice in SUBJECT_CHOICES],
        levels=[choice[0] for choice in LEVEL_CHOICES],
    )


@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    form = RegisterForm()
    if form.validate_on_submit():
        with SessionLocal() as db:
            existing = db.scalar(select(User).where(User.email == form.email.data.lower()))
            if existing:
                flash("Email já cadastrado.", "warning")
            else:
                user = User(
                    email=form.email.data.lower(),
                    name=form.name.data.strip(),
                )
                user.set_password(form.password.data)
                db.add(user)
                db.commit()
                flash("Conta criada! Faça login.", "success")
                return redirect(url_for("login"))
    return render_template("auth_register.html", form=form)


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    form = LoginForm()
    if form.validate_on_submit():
        with SessionLocal() as db:
            user = db.scalar(select(User).where(User.email == form.email.data.lower()))
            if user and user.check_password(form.password.data):
                login_user(user, remember=True)
                flash(f"Bem-vindo(a), {user.name.split(' ')[0]}!", "success")
                return redirect(url_for("index"))
            flash("Credenciais inválidas.", "danger")
    return render_template("auth_login.html", form=form)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Sessão encerrada.", "info")
    return redirect(url_for("index"))


@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    form = UploadForm()
    if form.validate_on_submit():
        upload_file = request.files.get("file")
        if not upload_file or not upload_file.filename:
            flash("Selecione um arquivo de vídeo.", "warning")
            return render_template("upload.html", form=form)
        if not _allowed_file(upload_file.filename):
            flash("Formato não permitido. Envie arquivos mp4, webm ou mov.", "danger")
            return render_template("upload.html", form=form)
        filename = secure_filename(upload_file.filename)
        token = secrets.token_hex(8)
        stored_name = f"{token}_{filename}"
        save_path = Path(app.config["UPLOAD_FOLDER"]) / stored_name
        upload_file.save(save_path)
        with SessionLocal() as db:
            video = Video(
                owner_id=current_user.id,
                filename=stored_name,
                title=form.title.data.strip(),
                description=form.description.data.strip() if form.description.data else "",
                subject=form.subject.data,
                level=form.level.data,
                is_published=False,
            )
            db.add(video)
            db.commit()
            flash("Upload concluído! Agora personalize e publique quando quiser.", "success")
            return redirect(url_for("video_edit", video_id=video.id))
    return render_template("upload.html", form=form)


@app.route("/videos/<int:video_id>")
def video_detail(video_id: int):
    with SessionLocal() as db:
        video = db.get(Video, video_id)
        if not video:
            abort(404)
        if not video.is_published and (not current_user.is_authenticated or video.owner_id != current_user.id):
            abort(403)
    return render_template("video_detail.html", video=video)


@app.route("/videos/<int:video_id>/edit", methods=["GET", "POST"])
@login_required
def video_edit(video_id: int):
    with SessionLocal() as db:
        video = db.get(Video, video_id)
        if not video:
            abort(404)
        if video.owner_id != current_user.id:
            abort(403)
        form = EditVideoForm(obj=video)
        if form.validate_on_submit():
            start = form.start_time.data if form.start_time.data is not None else 0.0
            end = form.end_time.data if form.end_time.data is not None else -1.0
            if end not in (-1.0, -1) and end <= start:
                flash("O tempo final deve ser maior que o inicial ou -1.", "warning")
                return render_template("video_edit.html", form=form, video=video)
            video.title = form.title.data.strip()
            video.description = form.description.data.strip() if form.description.data else ""
            video.subject = form.subject.data
            video.level = form.level.data
            video.start_time = start
            video.end_time = float(end)
            video.is_published = bool(form.is_published.data)
            db.add(video)
            db.commit()
            flash("Vídeo atualizado.", "success")
            return redirect(url_for("video_detail", video_id=video.id))
    return render_template("video_edit.html", form=form, video=video)




@app.route("/api/videos/<int:video_id>/clip")
def video_clip(video_id: int):
    with SessionLocal() as db:
        video = db.get(Video, video_id)
        if not video:
            abort(404)
        if not video.is_published and (not current_user.is_authenticated or video.owner_id != current_user.id):
            abort(403)
        data = {
            "id": video.id,
            "title": video.title,
            "start_time": video.start_time,
            "end_time": video.end_time,
            "video_url": url_for("uploaded_file", filename=video.filename),
            "is_published": video.is_published,
        }
    return jsonify(data)

@app.route("/uploads/<path:filename>")
def uploaded_file(filename: str):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)


# --- Error handlers --------------------------------------------------------
@app.errorhandler(403)
def forbidden(_):
    return render_template("error.html", code=403, message="Você não pode acessar este conteúdo ainda."), 403


@app.errorhandler(404)
def not_found(_):
    return render_template("error.html", code=404, message="Opa! Esse conteúdo não existe."), 404


@app.errorhandler(429)
def too_many_requests(_):
    return render_template("error.html", code=429, message="Calma aí! Muitas requisições."), 429


@app.errorhandler(413)
def too_large(_):
    return render_template("error.html", code=413, message="Arquivo muito grande."), 413


# --- CLI -------------------------------------------------------------------
@app.cli.command("init-db")
def init_db_command() -> None:
    """Create database tables."""
    Base.metadata.create_all(engine)
    print("Banco de dados pronto.")


if __name__ == "__main__":
    app.run(debug=True, host='127.0.0.1', port=8080)