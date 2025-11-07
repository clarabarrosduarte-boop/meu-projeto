from __future__ import annotations

import mimetypes
import os
import secrets
import subprocess
import time
import uuid
from collections import defaultdict, deque
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Iterable

import boto3
from botocore.config import Config
from dotenv import load_dotenv
from imageio_ffmpeg import get_ffmpeg_exe

from flask import (
    Flask,
    abort,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    send_from_directory,
    url_for,
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

load_dotenv()
mimetypes.add_type("video/mp4", ".m4v")

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


class DeleteVideoForm(FlaskForm):
    submit = SubmitField("Excluir vídeo")




@app.context_processor
def inject_globals():
    return {
        "config": app.config,
        "subject_options": [item[0] for item in SUBJECT_CHOICES],
        "level_options": [item[0] for item in LEVEL_CHOICES],
    }

# --- Helpers ---------------------------------------------------------------
_rate_buckets: defaultdict[str, deque[float]] = defaultdict(deque)
_direct_playable_exts = {".mp4", ".m4v"}


@lru_cache(maxsize=1)
def _ffmpeg_path() -> str | None:
    try:
        return get_ffmpeg_exe()
    except Exception as exc:  # pragma: no cover - defensive logging
        app.logger.warning("FFmpeg indisponível: %s. Vídeos só serão aceitos se já estiverem em MP4 compatível.", exc)
        return None


def _should_transcode(source_path: Path) -> bool:
    ext = source_path.suffix.lower()
    force = os.environ.get("FORCE_TRANSCODE_MP4", "0") == "1"
    if ext in _direct_playable_exts and not force:
        return False
    return True


def _standardize_video(source_path: Path, token: str) -> tuple[Path, str]:
    """Ensure the uploaded video is a browser-friendly MP4 (H.264 + AAC)."""
    final_filename = f"{token}.mp4"
    final_path = source_path.parent / final_filename
    ffmpeg_bin = _ffmpeg_path()

    if not _should_transcode(source_path):
        source_path.rename(final_path)
        return final_path, "video/mp4"

    if ffmpeg_bin is None:
        raise RuntimeError(
            "Precisamos converter este formato para MP4, mas o FFmpeg não está instalado. "
            "Instale o FFmpeg (ou defina FORCE_TRANSCODE_MP4=0) e tente novamente."
        )

    temp_path = source_path.parent / f"{token}_processing.mp4"
    cmd = [
        ffmpeg_bin,
        "-y",
        "-i",
        str(source_path),
        "-c:v",
        os.environ.get("FFMPEG_VIDEO_CODEC", "libx264"),
        "-preset",
        os.environ.get("FFMPEG_PRESET", "veryfast"),
        "-crf",
        os.environ.get("FFMPEG_CRF", "24"),
        "-pix_fmt",
        "yuv420p",
        "-profile:v",
        "high",
        "-movflags",
        "+faststart",
        "-c:a",
        "aac",
        "-b:a",
        os.environ.get("FFMPEG_AUDIO_BITRATE", "160k"),
        str(temp_path),
    ]
    app.logger.info("Executando FFmpeg para normalizar vídeo: %s", " ".join(cmd))
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        app.logger.error("FFmpeg falhou (%s): %s", result.returncode, result.stderr)
        temp_path.unlink(missing_ok=True)
        source_path.unlink(missing_ok=True)
        raise RuntimeError("Não conseguimos processar o vídeo. Tente outro arquivo ou fale com o suporte.")

    source_path.unlink(missing_ok=True)
    temp_path.rename(final_path)
    return final_path, "video/mp4"


S3_REQUIRED_KEYS = ("S3_ENDPOINT_URL", "S3_KEY", "S3_SECRET", "S3_BUCKET_NAME")


@lru_cache(maxsize=1)
def _s3_settings() -> dict[str, str]:
    missing = [name for name in S3_REQUIRED_KEYS if not os.environ.get(name)]
    if missing:
        raise RuntimeError(
            "Uploads diretos ainda não estão configurados: defina as variáveis "
            + ", ".join(missing)
        )
    return {name: os.environ[name] for name in S3_REQUIRED_KEYS}


@lru_cache(maxsize=1)
def _s3_client():
    settings = _s3_settings()
    return boto3.client(
        "s3",
        endpoint_url=settings["S3_ENDPOINT_URL"],
        aws_access_key_id=settings["S3_KEY"],
        aws_secret_access_key=settings["S3_SECRET"],
        region_name=os.environ.get("S3_REGION", "auto"),
        config=Config(signature_version="s3v4"),
    )


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
            flash("Formato não permitido. Envie arquivos mp4, mov, webm, mkv, avi ou m4v.", "danger")
            return render_template("upload.html", form=form)
        filename = secure_filename(upload_file.filename)
        token = secrets.token_hex(8)
        original_ext = Path(filename).suffix.lower() or ".mp4"
        temp_name = f"{token}_source{original_ext}"
        temp_path = Path(app.config["UPLOAD_FOLDER"]) / temp_name
        upload_file.save(temp_path)
        try:
            processed_path, _ = _standardize_video(temp_path, token)
        except RuntimeError as exc:
            flash(str(exc), "danger")
            return render_template("upload.html", form=form)
        stored_name = processed_path.name
        with SessionLocal() as db:
            video = Video(
                owner_id=current_user.id,
                filename=stored_name,
                title=form.title.data.strip(),
                description=form.description.data.strip() if form.description.data else "",
                subject=form.subject.data,
                level=form.level.data,
                is_published=True,
            )
            db.add(video)
            db.commit()
            flash("Upload concluÃ­do! O vÃ­deo foi normalizado para MP4 e jÃ¡ estÃ¡ pÃºblico.", "success")
            return redirect(url_for("video_detail", video_id=video.id))
    return render_template("upload.html", form=form)


@app.route("/videos/<int:video_id>")
def video_detail(video_id: int):
    with SessionLocal() as db:
        video = db.get(Video, video_id)
        if not video:
            abort(404)
        if not video.is_published and (not current_user.is_authenticated or video.owner_id != current_user.id):
            abort(403)
    mime_type = mimetypes.guess_type(video.filename)[0] or "video/mp4"
    delete_form = DeleteVideoForm() if current_user.is_authenticated and current_user.id == video.owner_id else None
    return render_template("video_detail.html", video=video, video_mime=mime_type, delete_form=delete_form)


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
        delete_form = DeleteVideoForm()
        mime_type = mimetypes.guess_type(video.filename)[0] or "video/mp4"
        if form.validate_on_submit():
            start = form.start_time.data if form.start_time.data is not None else 0.0
            end = form.end_time.data if form.end_time.data is not None else -1.0
            if end not in (-1.0, -1) and end <= start:
                flash("O tempo final deve ser maior que o inicial ou -1.", "warning")
                return render_template("video_edit.html", form=form, video=video, video_mime=mime_type)
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
    return render_template("video_edit.html", form=form, video=video, video_mime=mime_type, delete_form=delete_form)


@app.route("/videos/<int:video_id>/delete", methods=["POST"])
@login_required
def video_delete(video_id: int):
    form = DeleteVideoForm()
    if not form.validate_on_submit():
        abort(400)
    with SessionLocal() as db:
        video = db.get(Video, video_id)
        if not video:
            abort(404)
        if video.owner_id != current_user.id:
            abort(403)
        file_path = Path(app.config["UPLOAD_FOLDER"]) / video.filename
        file_path.unlink(missing_ok=True)
        db.delete(video)
        db.commit()
    flash("Vídeo removido permanentemente.", "info")
    return redirect(url_for("index"))




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
    mime_type = mimetypes.guess_type(filename)[0] or "application/octet-stream"
    response = send_from_directory(
        app.config["UPLOAD_FOLDER"],
        filename,
        mimetype=mime_type,
        conditional=True,
    )
    response.headers.setdefault("Cache-Control", "public, max-age=31536000, immutable")
    return response


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


# --- Direct upload API (S3-compatible) ------------------------------------
@app.post("/api/upload/init")
def upload_init():
    try:
        settings = _s3_settings()
        client = _s3_client()
    except RuntimeError as exc:
        return jsonify({"error": str(exc)}), 503

    data = request.get_json(silent=True) or {}
    filename = secure_filename(data.get("filename", ""))
    if not filename:
        return jsonify({"error": "filename é obrigatório"}), 400
    content_type = data.get("contentType") or "application/octet-stream"
    key = f"uploads/{uuid.uuid4()}_{filename}"

    resp = client.create_multipart_upload(
        Bucket=settings["S3_BUCKET_NAME"],
        Key=key,
        ContentType=content_type,
    )
    return jsonify({"key": key, "uploadId": resp["UploadId"]})


@app.post("/api/upload/parts")
def upload_parts():
    try:
        settings = _s3_settings()
        client = _s3_client()
    except RuntimeError as exc:
        return jsonify({"error": str(exc)}), 503

    data = request.get_json(silent=True) or {}
    key = data.get("key")
    upload_id = data.get("uploadId")
    part_numbers = data.get("parts")

    if not key or not upload_id or not isinstance(part_numbers, list) or not part_numbers:
        return jsonify({"error": "Informe key, uploadId e parts (lista de inteiros)."}), 400

    try:
        urls = [
            {
                "partNumber": int(part_number),
                "url": client.generate_presigned_url(
                    "upload_part",
                    Params={
                        "Bucket": settings["S3_BUCKET_NAME"],
                        "Key": key,
                        "UploadId": upload_id,
                        "PartNumber": int(part_number),
                    },
                    ExpiresIn=3600,
                ),
            }
            for part_number in part_numbers
        ]
    except Exception as exc:  # pragma: no cover - boto3 error surface
        app.logger.error("Falha ao gerar URLs de upload multipart: %s", exc)
        return jsonify({"error": "Não foi possível gerar as URLs de upload."}), 500

    return jsonify({"urls": urls})


@app.post("/api/upload/complete")
def upload_complete():
    try:
        settings = _s3_settings()
        client = _s3_client()
    except RuntimeError as exc:
        return jsonify({"error": str(exc)}), 503

    data = request.get_json(silent=True) or {}
    key = data.get("key")
    upload_id = data.get("uploadId")
    parts = data.get("parts")

    if not key or not upload_id or not isinstance(parts, list) or not parts:
        return jsonify({"error": "Informe key, uploadId e parts (lista de {partNumber, etag})."}), 400

    completed = {
        "Parts": [
            {"ETag": part["etag"], "PartNumber": int(part["partNumber"])}
            for part in parts
            if "etag" in part and "partNumber" in part
        ]
    }
    if not completed["Parts"]:
        return jsonify({"error": "Lista de partes inválida."}), 400

    try:
        client.complete_multipart_upload(
            Bucket=settings["S3_BUCKET_NAME"],
            Key=key,
            UploadId=upload_id,
            MultipartUpload=completed,
        )
    except Exception as exc:  # pragma: no cover - boto3 error surface
        app.logger.error("Falha ao concluir upload multipart: %s", exc)
        return jsonify({"error": "Não foi possível concluir o upload."}), 500

    public_base = os.environ.get("R2_PUBLIC_BASE")
    url = f"{public_base}/{key}" if public_base else None
    return jsonify({"ok": True, "key": key, "url": url})


if __name__ == "__main__":
    debug_enabled = os.environ.get("FLASK_DEBUG") == "1"
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=debug_enabled)
