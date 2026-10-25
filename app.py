import os, re, secrets, sqlite3, sys, shutil, traceback
import html as _html
from functools import wraps
from datetime import datetime, timedelta
import click
from flask import (Flask, render_template, request, redirect,
                   url_for, session, flash, abort, g, send_from_directory)
from werkzeug.exceptions import HTTPException
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash

# ---------------- CONFIG ----------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("SCHOOL_DB_PATH", os.path.join(BASE_DIR, "school.db"))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "static", "uploads")
PRIVATE_UPLOAD_FOLDER = os.path.join(BASE_DIR, "private_uploads")
PUBLIC_FILES_FOLDER = os.path.join(BASE_DIR, "static", "files")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(PRIVATE_UPLOAD_FOLDER, mode=0o700, exist_ok=True)
os.makedirs(PUBLIC_FILES_FOLDER, exist_ok=True)
CLASSES = ["701", "702", "703", "801", "802", "803", "901", "902", "903"]
ALLOWED_EXT = {"png", "jpg", "jpeg", "gif", "webp"}
ALLOWED_DOC_EXT = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "csv", "odt", "ods", "odp"}
UPLOAD_EXTENSIONS = ALLOWED_EXT | ALLOWED_DOC_EXT
POST_TYPES = {"event": "رویدادها", "achievement": "دستاوردها", "news": "اخبار"}


def _load_secret():
    if os.environ.get("FLASK_SECRET_KEY"):
        return os.environ["FLASK_SECRET_KEY"]
    p = os.path.join(BASE_DIR, ".secret_key")
    if os.path.exists(p):
        return open(p).read().strip()
    s = secrets.token_hex(32)
    open(p, "w").write(s)
    return s


app = Flask(__name__)
app.config.update(
    SECRET_KEY=_load_secret(),
    MAX_CONTENT_LENGTH=25 * 1024 * 1024,
    WTF_CSRF_TIME_LIMIT=3600,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "0").lower() in ("1", "true", "yes"),
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
    UPLOAD_FOLDER=UPLOAD_FOLDER,
    PRIVATE_UPLOAD_FOLDER=PRIVATE_UPLOAD_FOLDER,
    PUBLIC_FILES_FOLDER=PUBLIC_FILES_FOLDER,
)
CSRFProtect(app)


# ---------------- DB ----------------
def get_db():
    c = sqlite3.connect(DB_PATH, timeout=10)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys = ON")
    return c


def now_text():
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")


def _db_is_healthy():
    if not os.path.exists(DB_PATH) or os.path.getsize(DB_PATH) == 0:
        return True
    try:
        c = sqlite3.connect(DB_PATH, timeout=5)
        try:
            r = c.execute("PRAGMA integrity_check").fetchone()
        finally:
            c.close()
        return r is not None and r[0] == "ok"
    except Exception:
        return False


def _backup_corrupted_db():
    if not os.path.exists(DB_PATH): return
    backup = DB_PATH + f".corrupted_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
    try: shutil.move(DB_PATH, backup)
    except Exception:
        try: os.remove(DB_PATH)
        except OSError: pass


def _ensure_column(db, table, column, ddl):
    try:
        cols = [r["name"] for r in db.execute(f"PRAGMA table_info({table})").fetchall()]
    except sqlite3.DatabaseError:
        return
    if column not in cols:
        try: db.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}")
        except sqlite3.DatabaseError: pass


def _migrate_check_constraint(db):
    try:
        row = db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='users'").fetchone()
    except sqlite3.DatabaseError:
        return
    if not row: return
    if "CHECK" not in (row["sql"] or "").upper(): return
    try:
        db.execute("PRAGMA foreign_keys = OFF")
        db.executescript("""
            BEGIN;
            CREATE TABLE users_new(
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              username TEXT UNIQUE NOT NULL,
              password_hash TEXT NOT NULL,
              role TEXT NOT NULL,
              full_name TEXT NOT NULL,
              created_at TEXT NOT NULL
            );
            INSERT INTO users_new SELECT id,username,password_hash,role,full_name,created_at FROM users;
            DROP TABLE users;
            ALTER TABLE users_new RENAME TO users;
            COMMIT;
        """)
        db.execute("PRAGMA foreign_keys = ON")
    except sqlite3.DatabaseError:
        try: db.rollback()
        finally: raise


def _gen_code():
    return secrets.token_hex(4).upper()


def _password_min(role):
    return {"owner": 12, "admin": 12, "teacher": 10, "student": 8}.get(role, 8)


def _ensure_legacy_admin_to_owner(db):
    """فقط ارتقای admin قدیمی به owner. هرگز خودکار owner نمی‌سازد."""
    if db.execute("SELECT 1 FROM users WHERE role='owner' LIMIT 1").fetchone():
        return
    existing = db.execute(
        "SELECT id FROM users WHERE username='admin' AND role='admin' LIMIT 1"
    ).fetchone()
    if existing:
        db.execute("UPDATE users SET role='owner' WHERE id=?", (existing["id"],))


def init_db():
    if not _db_is_healthy():
        _backup_corrupted_db()
    db = get_db()
    try:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS users(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          username TEXT UNIQUE NOT NULL,
          password_hash TEXT NOT NULL,
          role TEXT NOT NULL,
          full_name TEXT NOT NULL,
          created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS announcements(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          title TEXT NOT NULL, body TEXT NOT NULL, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS homework(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          title TEXT NOT NULL, body TEXT NOT NULL,
          due_date TEXT, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS grades(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          student_id INTEGER NOT NULL,
          subject TEXT NOT NULL, score REAL NOT NULL,
          note TEXT, created_at TEXT NOT NULL,
          FOREIGN KEY(student_id) REFERENCES users(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS site_posts(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          type TEXT NOT NULL,
          title TEXT NOT NULL, body TEXT NOT NULL,
          image TEXT DEFAULT '',
          created_by INTEGER, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS activity_log(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          actor_id INTEGER, action TEXT NOT NULL,
          target TEXT DEFAULT '', at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS auth_attempts(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          remote_addr TEXT NOT NULL,
          identifier TEXT DEFAULT '',
          attempted_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_auth_attempts_addr_time
          ON auth_attempts(remote_addr, attempted_at);
        CREATE TABLE IF NOT EXISTS comments(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          post_id INTEGER NOT NULL,
          author_name TEXT NOT NULL,
          body TEXT NOT NULL,
          is_approved INTEGER DEFAULT 0,
          created_at TEXT NOT NULL,
          FOREIGN KEY(post_id) REFERENCES site_posts(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS contact_messages(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          name TEXT NOT NULL,
          contact TEXT DEFAULT '',
          body TEXT NOT NULL,
          is_read INTEGER DEFAULT 0,
          created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT);
        CREATE TABLE IF NOT EXISTS exam_schedule(
          id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, class_name TEXT NOT NULL DEFAULT '',
          subject TEXT NOT NULL, exam_date TEXT NOT NULL, exam_time TEXT DEFAULT '', details TEXT DEFAULT '',
          file_name TEXT DEFAULT '', created_by INTEGER NOT NULL, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS exam_results(
          id INTEGER PRIMARY KEY AUTOINCREMENT, exam_id INTEGER, student_id INTEGER NOT NULL,
          subject TEXT NOT NULL, score REAL NOT NULL, note TEXT DEFAULT '', file_name TEXT DEFAULT '',
          created_by INTEGER NOT NULL, created_at TEXT NOT NULL,
          FOREIGN KEY(student_id) REFERENCES users(id) ON DELETE CASCADE,
          FOREIGN KEY(exam_id) REFERENCES exam_schedule(id) ON DELETE SET NULL
        );
        CREATE TABLE IF NOT EXISTS homework_submissions(
          id INTEGER PRIMARY KEY AUTOINCREMENT, homework_id INTEGER NOT NULL, student_id INTEGER NOT NULL,
          body TEXT DEFAULT '', file_name TEXT DEFAULT '', submitted_at TEXT NOT NULL,
          teacher_note TEXT DEFAULT '', status TEXT NOT NULL DEFAULT 'submitted',
          FOREIGN KEY(homework_id) REFERENCES homework(id) ON DELETE CASCADE,
          FOREIGN KEY(student_id) REFERENCES users(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS parent_student(
          parent_id INTEGER NOT NULL, student_id INTEGER NOT NULL,
          PRIMARY KEY(parent_id,student_id),
          FOREIGN KEY(parent_id) REFERENCES users(id) ON DELETE CASCADE,
          FOREIGN KEY(student_id) REFERENCES users(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS fee_payments(
          id INTEGER PRIMARY KEY AUTOINCREMENT, student_id INTEGER NOT NULL, title TEXT NOT NULL,
          amount INTEGER NOT NULL, due_date TEXT DEFAULT '', paid_amount INTEGER NOT NULL DEFAULT 0,
          status TEXT NOT NULL DEFAULT 'unpaid', note TEXT DEFAULT '', created_by INTEGER NOT NULL,
          created_at TEXT NOT NULL,
          FOREIGN KEY(student_id) REFERENCES users(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS parent_messages(
          id INTEGER PRIMARY KEY AUTOINCREMENT, parent_id INTEGER NOT NULL, teacher_id INTEGER NOT NULL,
          student_id INTEGER NOT NULL, body TEXT NOT NULL, sender_role TEXT NOT NULL,
          created_at TEXT NOT NULL, is_read INTEGER NOT NULL DEFAULT 0,
          FOREIGN KEY(parent_id) REFERENCES users(id) ON DELETE CASCADE,
          FOREIGN KEY(teacher_id) REFERENCES users(id) ON DELETE CASCADE,
          FOREIGN KEY(student_id) REFERENCES users(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS notifications(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          kind TEXT NOT NULL,
          target TEXT DEFAULT 'all',
          title TEXT NOT NULL,
          body TEXT DEFAULT '',
          link TEXT DEFAULT '',
          created_at TEXT NOT NULL
        );
        """)
        _migrate_check_constraint(db)
        _ensure_column(db, "users", "class_name", "TEXT DEFAULT ''")
        _ensure_column(db, "users", "is_active", "INTEGER DEFAULT 1")
        _ensure_column(db, "users", "panel_accent", "TEXT DEFAULT ''")
        _ensure_column(db, "homework", "class_name", "TEXT DEFAULT ''")
        _ensure_column(db, "homework", "subject", "TEXT DEFAULT ''")
        _ensure_column(db, "homework", "image", "TEXT DEFAULT ''")
        _ensure_column(db, "homework", "attachment", "TEXT DEFAULT ''")
        _ensure_column(db, "homework", "created_by", "INTEGER")
        _ensure_column(db, "grades", "term", "TEXT DEFAULT ''")
        _ensure_column(db, "grades", "created_by", "INTEGER")
        _ensure_column(db, "announcements", "image", "TEXT DEFAULT ''")
        _ensure_column(db, "announcements", "attachment", "TEXT DEFAULT ''")
        _ensure_column(db, "announcements", "created_by", "INTEGER")
        _ensure_column(db, "announcements", "is_pinned", "INTEGER DEFAULT 0")
        _ensure_column(db, "site_posts", "attachment", "TEXT DEFAULT ''")
        _ensure_column(db, "auth_attempts", "identifier", "TEXT DEFAULT ''")
        for _tbl in ("site_posts", "announcements", "homework"):
            _ensure_column(db, _tbl, "creator_name_snap", "TEXT DEFAULT ''")
            _ensure_column(db, _tbl, "creator_role_snap", "TEXT DEFAULT ''")

        db.executescript("""
        CREATE INDEX IF NOT EXISTS idx_users_role_active ON users(role, is_active);
        CREATE INDEX IF NOT EXISTS idx_users_class ON users(class_name, role, is_active);
        CREATE INDEX IF NOT EXISTS idx_grades_student ON grades(student_id, created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_submissions_student ON homework_submissions(student_id, submitted_at DESC);
        CREATE INDEX IF NOT EXISTS idx_submissions_homework ON homework_submissions(homework_id);
        CREATE INDEX IF NOT EXISTS idx_posts_created ON site_posts(id DESC);
        CREATE INDEX IF NOT EXISTS idx_anns_pinned ON announcements(is_pinned DESC, id DESC);
        CREATE INDEX IF NOT EXISTS idx_notifications_target ON notifications(target, id DESC);
        """)

        _ensure_legacy_admin_to_owner(db)

        used = set()
        for key in ("student_code", "teacher_code", "admin_code", "parent_code"):
            row = db.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
            if row: used.add(row["value"])
            else:
                new = _gen_code()
                while new in used: new = _gen_code()
                used.add(new)
                db.execute("INSERT INTO settings(key,value) VALUES(?,?)", (key, new))

        defaults = {
            "school_name": "مدرسه علامه",
            "hero_line1": "آینده را با",
            "hero_line2": "دانش و خلاقیت",
            "hero_line3": "بسازیم.",
            "hero_description": "در مدرسه علامه، یادگیری فقط به کلاس درس محدود نیست. "
                                "اینجا فضایی برای کشف استعدادها، پرورش ایده‌ها و ساختن فردایی روشن‌تر فراهم می‌کنیم.",
            "style_primary": "#2458d3", "style_accent": "#28d6c2",
            "style_navy": "#101d38", "style_gold": "#ffc96b",
            "site_logo": "", "contact_phone": "", "contact_email": "",
            "contact_address": "",
            "footer_text": "دانش، خلاقیت و تلاش؛ سه گام برای ساختن آینده‌ای روشن‌تر.",
            "public_news": "1", "public_announcements": "1",
            "public_comments": "1", "public_contact": "1",
        }
        for k, v in defaults.items():
            if not db.execute("SELECT 1 FROM settings WHERE key=?", (k,)).fetchone():
                db.execute("INSERT INTO settings(key,value) VALUES(?,?)", (k, v))
        db.commit()
    finally:
        db.close()


init_db()


# ---------------- HELPERS ----------------
def _get_setting(key, default=""):
    db = get_db()
    try:
        r = db.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
        return r["value"] if r else default
    finally:
        db.close()


def _set_setting(key, value):
    db = get_db()
    try:
        db.execute("INSERT INTO settings(key,value) VALUES(?,?) "
                   "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))
        db.commit()
    finally:
        db.close()


def _has_owner():
    if hasattr(g, "_owner_cache"):
        return g._owner_cache
    db = get_db()
    try:
        row = db.execute(
            "SELECT 1 FROM users WHERE role='owner' AND is_active=1 LIMIT 1"
        ).fetchone()
    finally:
        db.close()
    g._owner_cache = bool(row)
    return g._owner_cache


def _style():
    mapping = {"style_primary": "--blue", "style_accent": "--cyan",
               "style_navy": "--navy", "style_gold": "--gold"}
    overrides = []
    for k, var in mapping.items():
        v = _get_setting(k, "")
        if v and re.fullmatch(r"#[0-9a-fA-F]{6}", v):
            overrides.append(f"{var}:{v}")
    if overrides:
        return STYLE + "\n:root{" + ";".join(overrides) + "}"
    return STYLE


def _allowed_image(name):
    return name and "." in name and name.rsplit(".", 1)[1].lower() in ALLOWED_EXT


def _save_image(file):
    if not file or not file.filename or not _allowed_image(file.filename):
        return ""
    ext = file.filename.rsplit(".", 1)[1].lower()
    try:
        from PIL import Image, UnidentifiedImageError
        file.stream.seek(0)
        image = Image.open(file.stream)
        image.verify()
        fmt = (image.format or "").upper()
        expected = {"jpg": "JPEG", "jpeg": "JPEG", "png": "PNG",
                    "gif": "GIF", "webp": "WEBP"}
        if fmt != expected.get(ext):
            return ""
        file.stream.seek(0)
        image = Image.open(file.stream)
        if image.width < 1 or image.height < 1 or image.width > 8000 or image.height > 8000:
            return ""
        image.load()
        if image.mode not in ("RGB", "RGBA"):
            image = image.convert("RGBA" if "transparency" in image.info else "RGB")
        ext_out = "png" if fmt == "PNG" else ("webp" if fmt == "WEBP" else ("gif" if fmt == "GIF" else "jpg"))
        name = secrets.token_hex(16) + "." + ext_out
        dest = os.path.join(app.config["UPLOAD_FOLDER"], name)
        if fmt == "JPEG":
            if image.mode == "RGBA": image = image.convert("RGB")
            image.save(dest, format="JPEG", quality=88, optimize=True)
        elif fmt == "GIF":
            image.save(dest, format="GIF")
        else:
            image.save(dest, format=fmt)
        return name
    except Exception:
        return ""


def _delete_image(name):
    if not name: return
    p = os.path.join(app.config["UPLOAD_FOLDER"], name)
    try:
        if os.path.exists(p): os.remove(p)
    except OSError:
        pass


def _save_attachment(upload, folder_key="PRIVATE_UPLOAD_FOLDER"):
    """Store allowed document/image attachments with random names; never trust client filenames."""
    if not upload or not upload.filename:
        return ""
    original = upload.filename.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    if "." not in original:
        return ""
    ext = original.rsplit(".", 1)[1].lower()
    if ext not in UPLOAD_EXTENSIONS:
        return ""
    name = secrets.token_hex(20) + "." + ext
    folder = app.config[folder_key]
    os.makedirs(folder, exist_ok=True)
    upload.save(os.path.join(folder, name))
    return name


def _log(actor_id, action, target=""):
    db = get_db()
    try:
        db.execute("INSERT INTO activity_log(actor_id,action,target,at) VALUES(?,?,?,?)",
                   (actor_id, action, target, now_text()))
        db.commit()
    finally:
        db.close()


# ---------------- NOTIFICATIONS ----------------
NOTIF_ICONS = {"announcement": "📢", "event": "📅", "achievement": "🏆",
               "news": "📰", "contact_message": "✉️", "grade": "📊",
               "homework": "📝", "registration_pending": "⏳"}


def _icon_for_kind(kind):
    return NOTIF_ICONS.get(kind, "📌")


def _push_notification(kind, title, body="", link="", target="all"):
    db = get_db()
    try:
        db.execute("INSERT INTO notifications(kind,target,title,body,link,created_at) "
                   "VALUES(?,?,?,?,?,?)",
                   (kind, target, (title or "")[:160],
                    (body or "")[:300], link or "", now_text()))
        db.commit()
    finally:
        db.close()


def _get_public_notifications(limit=15):
    db = get_db()
    try:
        return db.execute(
            "SELECT * FROM notifications WHERE target='all' "
            "ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    finally:
        db.close()


# ---------------- AUTHOR HTML ----------------
def _author_html(name, role, css_class="author-pill"):
    labels = {'owner': 'مدیر ارشد', 'admin': 'مدیر',
              'teacher': 'معلم', 'student': 'دانش‌آموز'}
    label = labels.get(role)
    safe_name = _html.escape(name or "نامشخص")
    if not label:
        return f'<span class="{css_class}">{safe_name}</span>'
    crown = f'{ICONS["crown"]} ' if role == 'owner' else ''
    return f'<span class="{css_class} {role}">{crown}{label} — {safe_name}</span>'


# ---------------- ICONS ----------------
def svg_icon(paths, size=24):
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{size}" height="{size}" '
            f'viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" '
            f'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">{paths}</svg>')


ICONS = {
    "book": svg_icon('<path d="M4 5.5A2.5 2.5 0 0 1 6.5 3H20v17H6.5A2.5 2.5 0 0 1 4 17.5z"/><path d="M4 17.5A2.5 2.5 0 0 1 6.5 15H20M8 7h8M8 10h6"/>'),
    "home": svg_icon('<path d="m3 10 9-7 9 7"/><path d="M5 9v12h14V9M9 21v-7h6v7"/>'),
    "news": svg_icon('<rect x="4" y="3" width="16" height="18" rx="2"/><path d="M8 7h8M8 11h8M8 15h3M15 15h1"/>'),
    "bell": svg_icon('<path d="M18 8a6 6 0 0 0-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9"/><path d="M10 21h4"/>'),
    "school": svg_icon('<path d="m3 9 9-6 9 6-9 6z"/><path d="M7 12v5c3 3 7 3 10 0v-5M21 9v7"/>'),
    "trophy": svg_icon('<path d="M8 21h8M12 17v4M7 4h10v5a5 5 0 0 1-10 0z"/><path d="M7 6H3v2a5 5 0 0 0 5 5M17 6h4v2a5 5 0 0 1-5 5"/>'),
    "flask": svg_icon('<path d="M9 3h6M10 3v7L4 19a1.5 1.5 0 0 0 1.3 2h13.4a1.5 1.5 0 0 0 1.3-2l-6-9V3"/><path d="M7 16h10"/>'),
    "palette": svg_icon('<path d="M12 3a9 9 0 1 0 0 18h1a2 2 0 0 0 1.7-3.1 2 2 0 0 1 1.7-3h1.1A4.5 4.5 0 0 0 22 10.4C22 6.3 17.5 3 12 3z"/><circle cx="7.5" cy="10" r="1"/><circle cx="10" cy="6.5" r="1"/><circle cx="15" cy="7" r="1"/>'),
    "calendar": svg_icon('<rect x="3" y="5" width="18" height="16" rx="2"/><path d="M16 3v4M8 3v4M3 10h18M8 14h2M14 14h2M8 17h2"/>'),
    "arrow": svg_icon('<path d="M7 17 17 7M7 7h10v10"/>'),
    "check": svg_icon('<path d="m5 12 4 4L19 6"/>'),
    "star": svg_icon('<path d="m12 3 2.8 5.7 6.2.9-4.5 4.4 1.1 6.2-5.6-3-5.6 3 1.1-6.2L3 9.6l6.2-.9z"/>'),
    "menu": svg_icon('<path d="M4 6h16M4 12h16M4 18h16"/>'),
    "login": svg_icon('<path d="M10 17l5-5-5-5M15 12H3"/><path d="M12 3h6a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-6"/>'),
    "users": svg_icon('<circle cx="9" cy="8" r="3.5"/><path d="M2.5 21a6.5 6.5 0 0 1 13 0"/><circle cx="17" cy="8" r="2.5"/><path d="M22 21a4.5 4.5 0 0 0-5-4"/>'),
    "trash": svg_icon('<path d="M3 6h18M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/>'),
    "key": svg_icon('<circle cx="7.5" cy="15.5" r="4.5"/><path d="m10.5 12.5 9-9 3 3-2 2 2 2-3 3-2-2-3 3"/>'),
    "sort": svg_icon('<path d="M3 6h18M6 12h12M10 18h4"/>'),
    "plus": svg_icon('<path d="M12 5v14M5 12h14"/>'),
    "crown": svg_icon('<path d="M2 18h20l-2-11-5 4-3-7-3 7-5-4z"/>'),
    "image": svg_icon('<rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><path d="m21 15-5-5L5 21"/>'),
    "edit": svg_icon('<path d="M12 20h9M16.5 3.5a2.1 2.1 0 1 1 3 3L7 19l-4 1 1-4z"/>'),
    "log": svg_icon('<path d="M14 3h7v7M10 14 21 3M21 14v7H3V3h7"/>'),
    "settings": svg_icon('<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.9l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.9-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1A1.7 1.7 0 0 0 8.9 19a1.7 1.7 0 0 0-1.9.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.9 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1A1.7 1.7 0 0 0 4.6 8.9a1.7 1.7 0 0 0-.3-1.9l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.9.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.9-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.9V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z"/>'),
    "search": svg_icon('<circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/>'),
    "phone": svg_icon('<path d="M22 16.9v3a2 2 0 0 1-2.2 2 19.8 19.8 0 0 1-8.6-3 19.5 19.5 0 0 1-6-6 19.8 19.8 0 0 1-3-8.6A2 2 0 0 1 4.1 2h3a2 2 0 0 1 2 1.7c.1.9.3 1.8.6 2.6a2 2 0 0 1-.4 2.1L8.1 9.6a16 16 0 0 0 6 6l1.2-1.2a2 2 0 0 1 2.1-.4c.8.3 1.7.5 2.6.6a2 2 0 0 1 1.7 2z"/>'),
    "mail": svg_icon('<path d="M3 5h18v14H3z"/><path d="m3 6 9 7 9-7"/>'),
    "map": svg_icon('<path d="M12 22s8-8 8-14a8 8 0 1 0-16 0c0 6 8 14 8 14z"/><circle cx="12" cy="8" r="3"/>'),
    "comment": svg_icon('<path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>'),
    "file": svg_icon('<path d="M14 3v5h5M14 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>'),
    "download": svg_icon('<path d="M12 3v13M7 11l5 5 5-5M4 21h16"/>'),
}


# ---------------- STYLE ----------------
STYLE = r"""
@import url("https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/Vazirmatn-font-face.css");
:root{--navy:#101d38;--navy2:#172b4d;--blue:#2458d3;--cyan:#28d6c2;--gold:#ffc96b;
--ink:#18243a;--muted:#78849a;--bg:#f5f7fc;--line:#e8edf5;--shadow:0 18px 55px rgba(20,38,75,.09)}
*{box-sizing:border-box}
html{scroll-behavior:smooth;scroll-padding-top:90px}
body{margin:0;direction:rtl;background:var(--bg);color:var(--ink);
font-family:"Vazirmatn","Segoe UI",Tahoma,sans-serif;font-weight:500;line-height:1.85;
-webkit-font-smoothing:antialiased}
a{color:inherit;text-decoration:none}
button,input,select,textarea{font:inherit}
button,a{-webkit-tap-highlight-color:transparent}
.container{width:min(1160px,91%);margin-inline:auto}
.topbar{background:var(--navy);color:#d7e3f8;padding:8px 0;font-size:12px}
.topbar-inner{display:flex;justify-content:space-between;align-items:center;gap:12px}
.topbar .dot{display:inline-block;width:7px;height:7px;border-radius:50%;
background:var(--cyan);margin-left:7px;box-shadow:0 0 12px var(--cyan)}
.nav-wrap{position:sticky;top:0;z-index:20;background:rgba(255,255,255,.92);
backdrop-filter:blur(18px);border-bottom:1px solid rgba(220,228,242,.8)}
.nav{display:flex;align-items:center;justify-content:space-between;gap:20px;min-height:82px}
.brand{display:flex;align-items:center;gap:12px;flex-shrink:0}
.brand-mark{width:48px;height:48px;display:grid;place-items:center;color:var(--cyan);
background:linear-gradient(145deg,var(--navy),#263f6a);border-radius:16px;
box-shadow:0 8px 20px #182c4b28;overflow:hidden}
.brand-mark img{width:100%;height:100%;object-fit:cover}
.brand-name{font-size:18px;font-weight:900;color:var(--navy)}
.brand-sub{display:block;font-size:10px;color:var(--muted);letter-spacing:1px}
.nav-links{display:flex;align-items:center;gap:22px;font-size:13px;font-weight:bold}
.nav-links a{color:#59657a;transition:color .2s}
.nav-links a:hover{color:var(--blue)}
.nav-cta{background:var(--blue);color:white !important;border-radius:13px;
padding:11px 18px;box-shadow:0 7px 20px #2458d333}
.mobile-menu{display:none}
.hero{position:relative;overflow:hidden;padding:65px 0 72px;
background:radial-gradient(ellipse at 4% 8%,#d9e8ff 0,transparent 32%),
radial-gradient(ellipse at 96% 85%,#d6fbf3 0,transparent 30%),#f7f9ff}
.hero::before{content:"";position:absolute;width:290px;height:290px;
border:1px solid #c9d9f4;border-radius:50%;top:-170px;left:12%;
box-shadow:0 0 0 32px #dce7f633,0 0 0 65px #dce7f622}
.hero-grid{display:grid;grid-template-columns:1.05fr .95fr;align-items:center;
gap:55px;position:relative}
.eyebrow{display:inline-flex;align-items:center;gap:9px;border:1px solid #dce5f6;
background:white;border-radius:50px;padding:7px 13px;font-size:12px;color:#415577;
box-shadow:0 4px 14px #1e3a6610}
.eyebrow-dot{width:8px;height:8px;border-radius:50%;background:#20c7ac}
.hero h1{font-size:clamp(33px,4.2vw,54px);line-height:1.55;letter-spacing:-1.4px;
color:var(--navy);margin:20px 0 14px}
.hero h1 .accent{color:var(--blue);position:relative;white-space:nowrap}
.hero h1 .accent::after{content:"";position:absolute;height:8px;right:0;bottom:-2px;
width:100%;background:#ffc96b77;border-radius:10px;z-index:-1;display:none}
.hero-copy{max-width:530px;font-size:15px;line-height:2.2;color:#69768d}
.hero-actions{display:flex;flex-wrap:wrap;align-items:center;gap:13px;margin-top:28px}
.hero-note{margin-top:25px;display:flex;align-items:center;gap:10px;color:#7c879a;font-size:11px}
.note-stars{color:#efa932;letter-spacing:2px;font-size:15px}
.hero-art{min-height:400px;position:relative;display:grid;place-items:center}
.art-orbit{position:absolute;width:330px;height:330px;border:1px dashed #aebfe0;border-radius:50%}
.art-orbit::before,.art-orbit::after{content:"";position:absolute;border-radius:50%;border:1px solid #d0def3}
.art-orbit::before{inset:22px}
.art-orbit::after{inset:48px}
.art-core{width:235px;height:260px;display:flex;flex-direction:column;
align-items:center;justify-content:center;color:white;
background:linear-gradient(155deg,#203d72,#101d38 76%);border-radius:38px;
box-shadow:0 28px 60px #152b5140;position:relative;z-index:2;overflow:hidden}
.art-core::before{content:"";position:absolute;width:210px;height:210px;
border:1px solid #ffffff20;border-radius:50%;top:-100px;right:-80px}
.art-cap{width:104px;height:84px;display:grid;place-items:center;color:var(--gold);margin-bottom:8px}
.art-cap svg{width:90px;height:90px}
.art-core strong{font-size:23px}
.art-core small{color:#c6d7f4;font-size:11px;margin-top:5px}
.float-card{position:absolute;z-index:3;display:flex;align-items:center;gap:11px;
padding:13px 16px;background:rgba(255,255,255,.96);border:1px solid #e9eef8;
border-radius:17px;box-shadow:var(--shadow);font-size:12px;font-weight:bold}
.float-card small{display:block;font-weight:normal;color:var(--muted);font-size:10px}
.float-icon{width:39px;height:39px;display:grid;place-items:center;border-radius:12px}
.float-one{top:35px;right:0}
.float-two{bottom:38px;left:-4px}
.float-three{bottom:8px;right:4px}
.fi-gold{color:#a76a08;background:#fff0d0}
.fi-cyan{color:#078d7c;background:#d8faf3}
.fi-blue{color:#2458d3;background:#e4edff}
.sparkle{position:absolute;color:#e6a938;font-size:25px}
.sparkle-one{top:35px;left:45px}
.sparkle-two{bottom:65px;right:10px;color:#28bda9}
.stats{position:relative;z-index:4;margin-top:-25px}
.stats-inner{background:white;border:1px solid #edf0f7;border-radius:22px;
box-shadow:0 14px 40px #172e5710;display:grid;grid-template-columns:repeat(4,1fr);padding:25px 10px}
.stat{text-align:center;border-left:1px solid var(--line)}
.stat:last-child{border-left:0}
.stat strong{display:block;color:var(--navy);font-size:27px;line-height:1.5}
.stat span{font-size:11px;color:var(--muted)}
.section{padding:82px 0}
.section-white{background:white}
.section-head{display:flex;justify-content:space-between;align-items:end;gap:20px;margin-bottom:30px}
.section-kicker{color:var(--blue);font-size:11px;font-weight:900;letter-spacing:1px}
.section-title{color:var(--navy);font-size:clamp(25px,3vw,34px);line-height:1.6;margin:5px 0 8px}
.section-desc{color:var(--muted);font-size:13px;margin:0}
.text-link{display:inline-flex;align-items:center;gap:8px;color:var(--blue);
font-size:12px;font-weight:bold;white-space:nowrap}
.features{display:grid;grid-template-columns:repeat(4,1fr);gap:17px}
.feature{background:white;padding:24px 20px;border:1px solid #e9edf5;
border-radius:21px;transition:transform .25s,box-shadow .25s,border-color .25s}
.feature:hover{transform:translateY(-6px);box-shadow:var(--shadow);border-color:#cbd8f3}
.feature-icon{width:57px;height:57px;display:grid;place-items:center;border-radius:18px;margin-bottom:18px}
.feature-icon svg{width:28px;height:28px}
.feature h3{margin:0 0 8px;font-size:15px;color:var(--navy)}
.feature p{margin:0;color:var(--muted);font-size:12px;line-height:2.1}
.bg-blue{background:#e8efff;color:#285bd0}
.bg-green{background:#dffaf3;color:#119884}
.bg-gold{background:#fff2d8;color:#bc8018}
.bg-purple{background:#f0e8ff;color:#8356c8}
.news-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:18px}
.news-card{overflow:hidden;border:1px solid var(--line);border-radius:21px;
background:white;transition:transform .2s,box-shadow .2s;display:block}
.news-card:hover{transform:translateY(-4px);box-shadow:var(--shadow)}
.news-cover{min-height:180px;display:grid;place-items:center;position:relative;overflow:hidden}
.news-cover svg{width:65px;height:65px;position:relative;z-index:1}
.news-cover img{width:100%;height:100%;object-fit:cover;position:absolute;inset:0;z-index:0}
.cover-blue{color:white;background:linear-gradient(135deg,#2458d3,#6e91f2)}
.cover-green{color:#fff;background:linear-gradient(135deg,#078b83,#43c8ad)}
.cover-gold{color:#fff;background:linear-gradient(135deg,#b47718,#ffd16f)}
.news-body{padding:19px}
.news-tag{display:inline-block;color:#2458d3;background:#edf2ff;padding:4px 9px;
border-radius:7px;font-size:10px;font-weight:bold}
.news-body h3{font-size:15px;color:var(--navy);margin:12px 0 8px}
.news-body p{color:var(--muted);font-size:12px;line-height:2;margin:0;
display:-webkit-box;-webkit-line-clamp:3;-webkit-box-orient:vertical;overflow:hidden}
.news-meta{display:flex;align-items:center;justify-content:space-between;
color:#8994a6;font-size:10px;border-top:1px solid #eef1f6;margin-top:16px;padding-top:13px}
.announcement{display:flex;align-items:flex-start;gap:17px;background:#fff5dd;
border:1px solid #f7e4b8;padding:20px;border-radius:18px;margin-top:14px}
.announcement-icon{flex-shrink:0;width:47px;height:47px;display:grid;
place-items:center;color:#a86a05;background:#ffe8af;border-radius:15px}
.announcement strong{color:#6f4b12;font-size:13px;display:block;margin-bottom:4px}
.announcement p{color:#92723c;margin:0;font-size:12px}
.announcement img{max-width:200px;border-radius:10px;margin-top:8px}
.about-panel{display:grid;grid-template-columns:1fr 1fr;gap:50px;align-items:center;
padding:40px;background:var(--navy);color:white;border-radius:30px;
position:relative;overflow:hidden}
.about-content,.about-art{position:relative;z-index:1}
.about-content .section-title{color:white}
.about-content p{color:#c2cee4;font-size:13px;line-height:2.3}
.check-list{display:grid;gap:10px;margin-top:20px}
.check-item{display:flex;align-items:center;gap:10px;color:#e1eafa;font-size:12px}
.check-circle{display:grid;place-items:center;width:24px;height:24px;
border-radius:8px;color:var(--cyan);background:#28d6c21a}
.about-art{min-height:260px;display:grid;place-items:center}
.about-emblem{width:225px;height:225px;border-radius:50%;display:grid;place-items:center;
color:var(--gold);border:1px solid #ffffff2e;
background:radial-gradient(circle,#28436b 0%,#182b4c 60%,#13223e 100%);
box-shadow:0 0 0 20px #ffffff08,0 0 0 40px #ffffff05}
.about-emblem svg{width:95px;height:95px}
.footer{background:#0c172d;color:#d4def0;padding:45px 0 20px}
.footer-grid{display:grid;grid-template-columns:1.3fr 1fr 1fr;gap:40px;padding-bottom:35px}
.footer .brand-name{color:white}
.footer p{color:#96a7c3;font-size:12px;line-height:2.2;max-width:330px}
.footer h4{color:white;font-size:13px;margin-top:0}
.footer-links{display:grid;gap:9px;font-size:12px;color:#aab8cf}
.footer-links a:hover{color:var(--cyan)}
.footer-bottom{padding-top:17px;border-top:1px solid #ffffff16;color:#7f91af;
font-size:10px;display:flex;justify-content:space-between;gap:12px}
.footer-contact{display:grid;gap:6px;font-size:12px;color:#aab8cf;margin-top:8px}
.footer-contact span{display:flex;align-items:center;gap:6px}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:10px;
border:0;border-radius:14px;padding:13px 20px;font-weight:bold;font-size:13px;
cursor:pointer;transition:transform .2s,box-shadow .2s}
.btn:hover{transform:translateY(-3px)}
.btn-primary{background:var(--blue);color:white;box-shadow:0 10px 25px #2458d338}
.btn-light{background:white;color:var(--navy);border:1px solid var(--line)}
.btn-danger{background:#fff0ef;color:#a12d28;border:1px solid #fecaca}
.btn-success{background:#ecfdf5;color:#047857;border:1px solid #a7f3d0}
.btn-tiny{padding:6px 10px;font-size:11px;border-radius:8px}
.login-wrap{min-height:78vh;display:grid;place-items:center;padding:40px 15px;
background:radial-gradient(ellipse at top right,#dbe8ff,transparent 40%),var(--bg)}
.login-card{width:min(470px,100%);background:white;padding:32px;border:1px solid var(--line);
border-radius:25px;box-shadow:var(--shadow)}
.login-card h1{color:var(--navy);font-size:25px;margin:0 0 6px}
.login-card>p{color:var(--muted);font-size:12px;margin:0 0 16px}
.field{display:grid;gap:7px;margin:13px 0}
.field label{font-size:12px;font-weight:bold;color:#465570}
.field input,.field select,.field textarea{width:100%;padding:13px;border:1px solid #dfe6f1;
border-radius:12px;outline:none;background:#fbfcff;font-family:inherit}
.field input:focus,.field select:focus,.field textarea:focus{border-color:var(--blue);
box-shadow:0 0 0 3px #2458d31a}
.field textarea{min-height:90px;resize:vertical}
.field input[type=file]{padding:8px;font-size:12px}
.field input[type=color]{height:44px;padding:4px;cursor:pointer}
.help-text{font-size:11px;color:var(--muted);margin-top:4px;line-height:1.6}
.notice{background:#e3f8f0;color:#08785d;border-radius:12px;padding:12px;
font-size:12px;margin:12px 0;border:1px solid #bbf7d0}
.notice-error{background:#fff0ef;color:#a12d28;border-color:#fecaca}
.notice-success{background:#e3f8f0;color:#08785d}
.notice-message{background:#e8efff;color:#1e40af;border-color:#bfdbfe}
.login-tabs{display:flex;gap:4px;margin-bottom:16px;border-bottom:2px solid var(--line)}
.login-tab{flex:1;padding:12px 8px;background:transparent;border:0;cursor:pointer;
font-weight:700;color:var(--muted);border-bottom:3px solid transparent;
margin-bottom:-2px;font-size:13px;transition:.2s}
.login-tab.active{color:var(--blue);border-bottom-color:var(--blue)}
.login-tab:hover{color:var(--blue)}
.tab-panel{display:none}
.tab-panel.active{display:block}
.tab-hint{background:#f7f9fd;border:1px dashed #c7d3ec;border-radius:10px;
padding:8px 12px;font-size:11px;color:var(--muted);margin-bottom:12px;line-height:1.7}
.panel-wrap{padding:35px 0 65px}
.panel-heading{background:linear-gradient(135deg,#101d38,#2458d3);color:white;
padding:25px;border-radius:22px;margin-bottom:25px;display:flex;
justify-content:space-between;align-items:center;flex-wrap:wrap;gap:15px}
.panel-heading h1{margin:0 0 5px;font-size:25px}
.panel-heading p{margin:0;color:#d6e4ff;font-size:13px}
.panel-heading .badge-role{background:rgba(255,255,255,.18);color:#fff;
padding:6px 14px;border-radius:10px;font-size:12px;font-weight:700;
border:1px solid rgba(255,255,255,.25)}
.panel-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:20px}
.panel-card{background:white;border:1px solid var(--line);border-radius:20px;
padding:22px;min-width:0}
.panel-card.full{grid-column:1/-1}
.panel-card h2{font-size:18px;color:var(--navy);margin-top:0;margin-bottom:12px;
display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.panel-card h2 .sub{font-size:11px;font-weight:normal;color:var(--muted);
display:block;margin-top:4px;width:100%}
.panel-form{display:grid;gap:12px}
.panel-form input,.panel-form textarea,.panel-form select{width:100%;padding:12px;
border:1px solid #dfe6f1;border-radius:11px;background:#fbfcff;font-family:inherit}
.panel-form textarea{min-height:90px;resize:vertical}
.panel-form input:focus,.panel-form textarea:focus,.panel-form select:focus{
outline:none;border-color:var(--blue);box-shadow:0 0 0 3px #2458d31a}
.panel-form input[type=file]{padding:8px;font-size:12px}
.panel-form input[type=color]{height:44px;padding:4px;cursor:pointer}
.panel-table-wrap{overflow-x:auto}
.panel-table{width:100%;border-collapse:collapse;font-size:12px}
.panel-table th,.panel-table td{padding:10px;border-bottom:1px solid var(--line);
text-align:right;vertical-align:middle}
.panel-table th{color:var(--navy);background:#f7f9fd;font-weight:800;font-size:11px}
.panel-nav{display:flex;gap:12px;flex-wrap:wrap;align-items:center;margin-bottom:20px}
.panel-nav form{margin:0}
.panel-list{padding-right:0;margin:0;list-style:none}
.panel-list li{margin-bottom:14px;padding:14px;border:1px solid #eef1f6;border-radius:12px;
background:#fafbfe}
.panel-list small{color:var(--muted);display:block;font-size:11px;margin-top:4px}
.panel-list img.thumb{max-width:100%;max-height:160px;border-radius:10px;
margin-top:8px;border:1px solid #dfe6f1;object-fit:cover}
.empty{color:var(--muted);font-size:12px;text-align:center;padding:20px 0}
.inline-form{display:inline;margin:0 3px}
.code-box{font-family:ui-monospace,"Courier New",monospace;background:#f7f9fd;
border:1px dashed #c7d3ec;border-radius:12px;padding:12px 16px;font-size:22px;
letter-spacing:4px;color:var(--blue);font-weight:800;text-align:center}
.badge{display:inline-block;padding:2px 8px;border-radius:7px;font-size:10px;font-weight:bold}
.badge-owner{background:#fff7e0;color:#a86400;border:1px solid #f5d58a}
.badge-admin{background:#f0e8ff;color:#6b3fbb}
.badge-teacher{background:#e8efff;color:#285bd0}
.badge-student{background:#dffaf3;color:#119884}
.badge-off{background:#fff0ef;color:#a12d28}
.badge-pending{background:#fef3c7;color:#a86400;border:1px solid #f5d58a}
.sort-bar{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:10px;
padding:8px 12px;background:#f8fafc;border-radius:10px;font-size:12px;align-items:center}
.sort-bar a{padding:4px 10px;border-radius:6px;color:var(--muted);font-weight:600}
.sort-bar a:hover{background:#eef2ff;color:var(--blue)}
.sort-bar a.active{background:var(--blue);color:#fff}
.tips-box{background:#eef2ff;border-right:3px solid var(--blue);
padding:10px 14px;border-radius:8px;font-size:12px;margin-bottom:14px;color:#334155}
.tips-box.warn{background:#fef3c7;border-right-color:#f59e0b;color:#78350f}
.author-pill{display:inline-flex;align-items:center;gap:4px;
padding:2px 8px;border-radius:6px;font-size:10px;font-weight:600;
background:#f7f9fd;color:var(--muted)}
.author-pill.owner{background:#fff7e0;color:#a86400;border:1px solid #f5d58a}
.author-pill.admin{background:#f0e8ff;color:#5b21b6;border:1px solid #d8c7f5}
.author-pill.teacher{background:#e8efff;color:#285bd0;border:1px solid #c5d5f5}
.author-pill.student{background:#dffaf3;color:#119884}
.post-type-badge{display:inline-block;padding:2px 10px;border-radius:6px;
font-size:10px;font-weight:700;margin-left:6px}
.pt-event{background:#e8efff;color:#285bd0}
.pt-achievement{background:#fff2d8;color:#bc8018}
.pt-news{background:#dffaf3;color:#119884}
.hex-label{font-family:ui-monospace,"Courier New",monospace;font-size:11px;
font-weight:600;color:var(--blue);background:#eff6ff;border:1px solid #bfdbfe;
padding:2px 8px;border-radius:6px;direction:ltr;display:inline-block}
.color-preview{width:100%;height:40px;border-radius:10px;margin-top:6px;
border:1px solid var(--line);transition:background .15s}
.color-usage{font-size:11px;color:#475569;background:#f8fafc;border-radius:6px;
padding:6px 10px;margin-top:6px;line-height:1.6;border-right:3px solid var(--cyan)}
.filter-bar{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:20px;padding:14px;
background:#fff;border:1px solid var(--line);border-radius:14px;align-items:center}
.filter-bar form{display:flex;gap:8px;flex:1;min-width:220px}
.filter-bar input,.filter-bar select{padding:9px 12px;border:1px solid #dfe6f1;
border-radius:10px;font-size:13px;background:#fbfcff;font-family:inherit}
.filter-bar input{flex:1}
.comment-card{background:#fff;border:1px solid var(--line);border-radius:12px;
padding:14px;margin-bottom:10px}
.comment-card strong{color:var(--navy);font-size:13px}
.comment-card small{color:var(--muted);font-size:11px;margin-right:8px}
.comment-card p{margin:6px 0 0;font-size:13px;color:#334155}
.single-post{max-width:800px;margin:0 auto;background:#fff;border:1px solid var(--line);
border-radius:20px;padding:32px;box-shadow:var(--shadow)}
.single-post h1{color:var(--navy);font-size:26px;margin:12px 0}
.single-post .meta{color:var(--muted);font-size:12px;display:flex;
gap:14px;flex-wrap:wrap;border-bottom:1px solid var(--line);padding-bottom:14px;margin-bottom:16px;
align-items:center}
.single-post img.cover{width:100%;border-radius:14px;margin-bottom:16px;max-height:400px;object-fit:cover}
.single-post .body{font-size:14px;line-height:2;color:#334155;white-space:pre-wrap}
.page-hero{position:relative;overflow:hidden;padding:50px 0 55px;margin-bottom:30px;
background:linear-gradient(135deg,var(--navy) 0%,var(--blue) 100%);color:white;
border-radius:0 0 30px 30px}
.page-hero-inner{position:relative;z-index:2;display:flex;align-items:center;
justify-content:space-between;gap:20px;flex-wrap:wrap}
.page-hero-icon{width:70px;height:70px;border-radius:20px;
background:rgba(255,255,255,.15);display:grid;place-items:center;
border:1px solid rgba(255,255,255,.25);flex-shrink:0}
.page-hero-icon svg{width:38px;height:38px;color:var(--cyan)}
.page-hero h1{font-size:clamp(26px,4vw,38px);margin:0 0 6px;line-height:1.3}
.page-hero p{margin:0;color:#d6e4ff;font-size:14px}
.page-hero-stats{display:flex;gap:24px;flex-wrap:wrap}
.page-hero-stats .hs{text-align:center}
.page-hero-stats .hs strong{display:block;font-size:26px;color:var(--cyan);line-height:1.2}
.page-hero-stats .hs span{font-size:11px;color:#d6e4ff}
.filter-chips{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:24px;
padding:14px;background:#fff;border:1px solid var(--line);border-radius:14px}
.filter-chip-lg{padding:8px 18px;border-radius:22px;background:#f1f5f9;
color:#59657a;font-size:13px;font-weight:600;transition:.15s;display:inline-flex;
align-items:center;gap:6px}
.filter-chip-lg:hover{background:#eef2ff;color:var(--blue);transform:translateY(-1px)}
.filter-chip-lg.active{background:var(--blue);color:#fff;box-shadow:0 4px 12px #2458d344}
.filter-chip-lg .count{background:rgba(0,0,0,.1);padding:1px 8px;border-radius:10px;
font-size:11px;font-weight:700}
.filter-chip-lg.active .count{background:rgba(255,255,255,.25)}
.ann-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:18px}
.ann-card{background:#fff;border:1px solid var(--line);border-radius:18px;
padding:22px;transition:.25s;position:relative;overflow:hidden}
.ann-card:hover{transform:translateY(-3px);box-shadow:var(--shadow)}
.ann-card.pinned{border-color:#f5d58a;background:linear-gradient(135deg,#fffbf0 0%,#fff 100%)}
.ann-card-header{display:flex;align-items:flex-start;gap:12px;margin-bottom:12px}
.ann-card-icon{width:44px;height:44px;border-radius:12px;background:#eef2ff;
color:var(--blue);display:grid;place-items:center;flex-shrink:0}
.ann-card-icon svg{width:22px;height:22px}
.ann-card-title{margin:0;font-size:15px;color:var(--navy);line-height:1.5;flex:1}
.ann-card-body{color:#475569;font-size:13px;line-height:2;margin:0 0 14px;white-space:pre-wrap}
.ann-card-footer{display:flex;justify-content:space-between;align-items:center;
border-top:1px solid #f1f5f9;padding-top:12px;font-size:11px;color:var(--muted);
flex-wrap:wrap;gap:8px}
.empty-state{text-align:center;padding:70px 20px;background:#fff;
border:2px dashed var(--line);border-radius:20px}
.empty-state .icon{width:80px;height:80px;border-radius:50%;background:#eef2ff;
color:var(--blue);display:grid;place-items:center;margin:0 auto 20px}
.empty-state .icon svg{width:40px;height:40px}
.empty-state h3{margin:0 0 8px;color:var(--navy);font-size:18px}
.empty-state p{margin:0 0 20px;color:var(--muted);font-size:13px}
.notif-bell-btn{position:relative;background:#f1f5f9;border:1px solid var(--line);
width:42px;height:42px;border-radius:12px;display:inline-flex;align-items:center;
justify-content:center;cursor:pointer;color:var(--navy);transition:.2s;flex-shrink:0;
font-family:inherit}
.notif-bell-btn:hover{background:#eef2ff;color:var(--blue);border-color:#c7d2fe}
.notif-bell-btn svg{width:20px;height:20px}
.notif-badge{position:absolute;top:-4px;right:-4px;background:#ef4444;color:white;
font-size:10px;font-weight:700;min-width:18px;height:18px;border-radius:10px;
display:inline-flex;align-items:center;justify-content:center;padding:0 4px;
box-shadow:0 0 0 2px white;animation:notifPulse 1.5s infinite}
@keyframes notifPulse{0%,100%{transform:scale(1)}50%{transform:scale(1.15)}}
.notif-overlay{position:fixed;inset:0;background:rgba(15,23,42,.45);z-index:40;
backdrop-filter:blur(2px)}
.notif-panel{position:fixed;top:90px;left:50%;transform:translateX(-50%);
width:min(480px,92%);max-height:70vh;background:white;border-radius:18px;
box-shadow:0 25px 80px rgba(15,23,42,.35);z-index:50;overflow:hidden;
display:flex;flex-direction:column;direction:rtl;border:1px solid var(--line)}
.notif-panel-header{display:flex;justify-content:space-between;align-items:center;
padding:16px 20px;background:linear-gradient(135deg,var(--navy),var(--blue));color:white}
.notif-panel-header strong{font-size:15px}
.notif-close{background:rgba(255,255,255,.2);border:0;color:white;width:30px;height:30px;
border-radius:8px;cursor:pointer;font-size:14px;font-family:inherit}
.notif-panel-body{overflow-y:auto;padding:8px;flex:1}
.notif-item{display:flex;gap:12px;padding:12px;border-radius:12px;
text-decoration:none;color:var(--ink);transition:.15s;position:relative;
border:1px solid transparent;margin-bottom:4px}
.notif-item:hover{background:#f8fafc;border-color:var(--line)}
.notif-item.new{background:#eff6ff;border-color:#bfdbfe}
.notif-item-icon{width:36px;height:36px;border-radius:10px;background:#f1f5f9;
display:grid;place-items:center;font-size:18px;flex-shrink:0}
.notif-item-body{flex:1;min-width:0}
.notif-item-title{font-size:13px;font-weight:700;color:var(--navy);margin-bottom:3px;
line-height:1.5;overflow:hidden;text-overflow:ellipsis;
display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical}
.notif-item-time{font-size:11px;color:var(--muted)}
.notif-banner{background:linear-gradient(135deg,#fef3c7,#fde68a);
border-bottom:2px solid #f59e0b;padding:10px 0;position:relative;z-index:15}
.notif-banner-inner{display:flex;align-items:center;gap:12px;flex-wrap:wrap}
.notif-banner .notif-bell-icon{width:36px;height:36px;background:#f59e0b;color:white;
border-radius:10px;display:grid;place-items:center;flex-shrink:0;
animation:notifPulse 2s infinite}
.notif-banner .notif-bell-icon svg{width:20px;height:20px}
.notif-banner-list{flex:1;display:flex;gap:8px;flex-wrap:wrap;overflow:hidden}
.notif-banner-item{background:white;border-radius:8px;padding:5px 12px;font-size:12px;
font-weight:600;color:#78350f;white-space:nowrap;box-shadow:0 2px 6px rgba(0,0,0,.06);
transition:.15s}
.notif-banner-close{background:rgba(120,53,15,.15);border:0;color:#78350f;
width:30px;height:30px;border-radius:8px;cursor:pointer;flex-shrink:0;
font-size:14px;font-weight:700;font-family:inherit}
@media(max-width:900px){
  .hero-grid{gap:25px}
  .features{grid-template-columns:repeat(2,1fr)}
  .news-grid{grid-template-columns:repeat(2,1fr)}
  .about-panel{gap:20px;padding:30px}
  .panel-grid,.ann-grid{grid-template-columns:1fr}
  .single-post{padding:20px}
}
@media(max-width:650px){
  .nav{min-height:70px}
  .brand-mark{width:42px;height:42px}
  .nav-links{display:none;position:absolute;top:70px;right:4%;left:4%;
  padding:20px;background:white;border:1px solid var(--line);border-radius:18px;
  box-shadow:var(--shadow);flex-direction:column;align-items:stretch;gap:15px}
  .nav-links.open{display:flex}
  .mobile-menu{display:grid;place-items:center;width:43px;height:43px;
  border:1px solid var(--line);background:white;color:var(--navy);
  border-radius:13px;cursor:pointer}
  .hero{padding:42px 0 48px}
  .hero-grid{grid-template-columns:1fr}
  .hero h1{font-size:35px}
  .hero-art{min-height:340px;margin-top:5px}
  .art-orbit{width:270px;height:270px}
  .art-core{width:205px;height:225px}
  .stats-inner{grid-template-columns:repeat(2,1fr);gap:20px 0;padding:20px 5px}
  .section{padding:58px 0}
  .section-head{align-items:start;flex-direction:column}
  .news-grid{grid-template-columns:1fr}
  .about-panel{grid-template-columns:1fr;padding:25px 20px}
  .footer-grid{grid-template-columns:1fr;gap:25px}
  .footer-bottom{flex-direction:column}
  .panel-card{padding:16px}
  .notif-panel{top:70px}
}
h1,h2,h3,h4,.brand-name,.stat strong{font-weight:800;letter-spacing:-.5px}
:root{--radius:22px;--ease:cubic-bezier(.22,.8,.3,1)}
.topbar-inner{font-size:12px}
.nav{gap:16px}
.nav-links{flex:1;justify-content:center;gap:4px;font-size:14px;font-weight:700}
.nav-links a{position:relative;padding:9px 15px;border-radius:12px;color:#59657a;
transition:background .2s,color .2s}
.nav-links a:hover{background:#eef3ff;color:var(--blue)}
.nav-links a.active{background:#e8efff;color:var(--blue)}
.nav-links a.active::after{content:"";position:absolute;bottom:3px;right:50%;width:16px;height:3px;
margin-right:-8px;border-radius:3px;background:var(--blue)}
.nav-actions{display:flex;align-items:center;gap:10px;flex-shrink:0}
.nav-cta{display:inline-flex;align-items:center;gap:8px;font-size:13px;font-weight:800;
background:linear-gradient(135deg,var(--blue),#4a7bf0);transition:transform .2s,box-shadow .2s}
.nav-cta:hover{transform:translateY(-2px);box-shadow:0 12px 26px #2458d344}
.nav-cta svg{width:18px;height:18px}
.cta-short{display:none}
.mobile-menu[aria-expanded="true"]{background:var(--blue);color:#fff;border-color:var(--blue)}
:focus-visible{outline:3px solid #2458d355;outline-offset:2px}
.hero.hero-slider{padding:0}
.slides{position:relative;display:grid}
.slide{grid-area:1/1;position:relative;opacity:0;visibility:hidden;
transition:opacity .9s var(--ease),visibility .9s;display:flex;align-items:center}
.slide.is-active{opacity:1;visibility:visible;z-index:1}
.slide-pad{padding-top:42px;padding-bottom:128px}
.slide-media{color:#fff;overflow:hidden;min-height:430px}
.slide-bg{position:absolute;inset:0;width:100%;height:100%;object-fit:cover;z-index:0;
transform:scale(1.06);transition:transform 7s linear}
.slide.is-active .slide-bg{transform:scale(1)}
.slide-shade{position:absolute;inset:0;z-index:1;
background:linear-gradient(to left,rgba(10,22,48,.88) 0%,rgba(10,22,48,.55) 52%,rgba(10,22,48,.12) 100%)}
.slide-media::after{content:"";position:absolute;width:420px;height:420px;border-radius:50%;
left:-120px;bottom:-200px;border:1px solid #ffffff2a;box-shadow:0 0 0 40px #ffffff0a,0 0 0 80px #ffffff06;z-index:1}
.slide-content{position:relative;z-index:2;padding:42px 0 128px;max-width:1160px}
.slide-content>*{max-width:560px}
.slide-tag{display:inline-flex;align-items:center;gap:8px;padding:6px 14px;border-radius:50px;
background:rgba(255,255,255,.16);border:1px solid rgba(255,255,255,.3);
backdrop-filter:blur(8px);font-size:12px;font-weight:800}
.slide-content h2{font-size:clamp(27px,3.6vw,44px);line-height:1.6;margin:16px 0 10px;color:#fff}
.slide-content p{font-size:14px;line-height:2.1;color:#e3ebfa;margin:0 0 24px;
display:-webkit-box;-webkit-line-clamp:3;-webkit-box-orient:vertical;overflow:hidden}
.slide-content .btn-primary{background:#fff;color:var(--navy);box-shadow:0 12px 28px #0006}
.slide-ann{background:linear-gradient(135deg,#7a4a06,#e0a43a)}
.slide-ann .slide-icon{width:84px;height:84px;border-radius:26px;display:grid;place-items:center;
background:rgba(255,255,255,.18);border:1px solid rgba(255,255,255,.35);margin-bottom:6px}
.slide-ann .slide-icon svg{width:44px;height:44px}
.slider-ui{position:absolute;inset-inline:0;bottom:78px;z-index:6;display:flex;justify-content:center;pointer-events:none}
.slider-ui-inner{pointer-events:auto;display:flex;align-items:center;gap:12px;padding:7px 12px;
background:rgba(255,255,255,.88);backdrop-filter:blur(12px);border-radius:60px;
border:1px solid rgba(255,255,255,.7);box-shadow:0 10px 30px #0d1f4a26}
.slider-btn{width:34px;height:34px;border-radius:50%;border:0;cursor:pointer;display:grid;place-items:center;
background:#eef3ff;color:var(--navy);transition:background .2s,color .2s,transform .2s}
.slider-btn:hover{background:var(--blue);color:#fff;transform:scale(1.08)}
.slider-btn svg{width:17px;height:17px}
.slider-dots{display:flex;gap:7px;align-items:center}
.slider-dots button{width:9px;height:9px;border-radius:9px;border:0;padding:0;cursor:pointer;
background:#c4d0e8;transition:width .35s var(--ease),background .3s}
.slider-dots button.on{width:30px;background:var(--blue)}
.slider-progress{position:absolute;top:0;right:0;left:0;height:3px;z-index:7;background:transparent}
.slider-progress i{display:block;height:100%;width:0;background:linear-gradient(90deg,var(--cyan),var(--blue));
transform-origin:right}
.slider-progress.run i{animation:sliderRun var(--dur,6500ms) linear forwards}
.slider-progress.paused i{animation-play-state:paused}
@keyframes sliderRun{from{width:0}to{width:100%}}
.quick{margin-top:-58px;position:relative;z-index:8}
.quick-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:14px}
.quick-card{display:flex;align-items:center;gap:14px;background:#fff;border:1px solid var(--line);
border-radius:20px;padding:16px 18px;box-shadow:var(--shadow);transition:transform .25s var(--ease),box-shadow .25s,border-color .25s}
.quick-card:hover{transform:translateY(-5px);border-color:#cbd8f3;box-shadow:0 22px 50px #1a2f6120}
.quick-ico{width:50px;height:50px;border-radius:16px;display:grid;place-items:center;flex-shrink:0}
.quick-ico svg{width:25px;height:25px}
.quick-card strong{display:block;font-size:14px;color:var(--navy);line-height:1.6}
.quick-card small{display:block;color:var(--muted);font-size:11px;line-height:1.7}
.quick-card{animation:rise .7s var(--ease) backwards}
.quick-card:nth-child(2){animation-delay:.07s}.quick-card:nth-child(3){animation-delay:.14s}.quick-card:nth-child(4){animation-delay:.21s}
@keyframes rise{from{opacity:0;transform:translateY(22px)}}
.quick-card.main{background:linear-gradient(135deg,var(--navy),#27498f);border-color:transparent}
.quick-card.main strong{color:#fff}.quick-card.main small{color:#c6d7f4}
.quick-card.main .quick-ico{background:rgba(255,255,255,.15);color:var(--cyan)}
.carousel{position:relative}
.carousel-nav{display:flex;gap:8px}
.carousel-nav button{width:42px;height:42px;border-radius:14px;border:1px solid var(--line);background:#fff;
color:var(--navy);cursor:pointer;display:grid;place-items:center;transition:.2s}
.carousel-nav button:hover:not(:disabled){background:var(--blue);color:#fff;border-color:var(--blue)}
.carousel-nav button:disabled{opacity:.35;cursor:default}
.carousel-nav svg{width:18px;height:18px}
.carousel.no-scroll .carousel-nav{display:none}
.news-track{display:flex;gap:18px;overflow-x:auto;scroll-snap-type:x mandatory;scrollbar-width:none;
padding:6px 4px 22px;margin:0 -4px;-webkit-overflow-scrolling:touch}
.news-track::-webkit-scrollbar{display:none}
.news-track>.news-card{flex:0 0 calc((100% - 36px)/3);scroll-snap-align:start}
.section-head-actions{display:flex;align-items:center;gap:18px}
.hero-art .art-orbit{animation:spin 60s linear infinite}
.hero-art .float-card{animation:bob 6s ease-in-out infinite}
.hero-art .float-two{animation-delay:-2s}.hero-art .float-three{animation-delay:-4s}
.sparkle{animation:twinkle 3s ease-in-out infinite}.sparkle-two{animation-delay:-1.5s}
.art-core{transition:transform .4s var(--ease)}
.hero-art:hover .art-core{transform:scale(1.03) rotate(-1.5deg)}
@keyframes spin{to{transform:rotate(360deg)}}
@keyframes bob{0%,100%{transform:translateY(0)}50%{transform:translateY(-10px)}}
@keyframes twinkle{0%,100%{opacity:.4;transform:scale(.85)}50%{opacity:1;transform:scale(1.15)}}
.hero h1 .accent{background:linear-gradient(120deg,var(--blue),#4f8bff 60%,var(--cyan));
-webkit-background-clip:text;background-clip:text;color:transparent}
.hero h1 .accent{isolation:isolate}
.btn-primary{background:linear-gradient(135deg,var(--blue),#4a7bf0)}
.feature{position:relative;overflow:hidden}
.feature::before{content:"";position:absolute;top:0;right:0;left:0;height:4px;
background:linear-gradient(90deg,var(--blue),var(--cyan));transform:scaleX(0);transform-origin:right;transition:transform .35s var(--ease)}
.feature:hover::before{transform:scaleX(1)}
.feature-icon{transition:transform .35s var(--ease)}
.feature:hover .feature-icon{transform:rotate(-8deg) scale(1.08)}
.news-card{border-radius:22px}
.news-cover img{transition:transform .6s var(--ease)}
.news-card:hover .news-cover img{transform:scale(1.07)}
.section-alt{background:linear-gradient(180deg,#f5f7fc 0%,#eaf0fb 100%)}
.stats-block{padding:0 0 70px}
.stats-block .stats{margin-top:0}
.stat strong{background:linear-gradient(135deg,var(--navy),var(--blue));-webkit-background-clip:text;
background-clip:text;color:transparent}
.about-panel::before{content:"";position:absolute;width:360px;height:360px;border-radius:50%;
background:radial-gradient(circle,#28d6c233,transparent 65%);top:-140px;left:-100px}
.about-panel::after{content:"";position:absolute;width:300px;height:300px;border-radius:50%;
background:radial-gradient(circle,#2458d355,transparent 65%);bottom:-140px;right:-80px}
.about-emblem{animation:bob 7s ease-in-out infinite}
.js .reveal{opacity:0;transform:translateY(26px);transition:opacity .7s var(--ease),transform .7s var(--ease)}
.js .reveal.in{opacity:1;transform:none}
.js .reveal.d1{transition-delay:.08s}.js .reveal.d2{transition-delay:.16s}.js .reveal.d3{transition-delay:.24s}
@media(max-width:1000px){
  .nav-links{font-size:13px}.nav-links a{padding:8px 11px}
  .news-track>.news-card{flex-basis:calc((100% - 18px)/2)}
}
@media(max-width:650px){
  .topbar{display:none}
  .nav{gap:10px;min-height:68px}
  .brand-sub{display:none}
  .brand-name{font-size:16px}
  .nav-actions{gap:8px}
  .nav-links{display:none;position:absolute;top:100%;right:4%;left:4%;margin-top:8px;padding:10px;
  background:#fff;border:1px solid var(--line);border-radius:20px;box-shadow:0 24px 60px #14264b2b;
  flex-direction:column;align-items:stretch;gap:3px;flex:none}
  .nav-links.open{display:flex}
  .nav-links a{padding:14px 16px;font-size:15px;border-radius:14px}
  .nav-links a.active::after{display:none}
  .mobile-menu{display:grid;place-items:center;width:42px;height:42px;border:1px solid var(--line);
  background:#fff;color:var(--navy);border-radius:13px;cursor:pointer}
  .notif-bell-btn{width:40px;height:40px}
  .cta-full{display:none}.cta-short{display:inline}
  .nav-cta{padding:10px 13px}
  .slide-pad{padding-top:30px;padding-bottom:150px}
  .slide-content{padding:34px 0 150px}
  .hero-art{display:none}
  .hero-note{display:none}
  .slide-media{min-height:400px}
  .slider-ui{bottom:84px}
  .slider-btn{width:32px;height:32px}
  .quick{margin-top:-52px}
  .quick-grid{grid-template-columns:repeat(2,1fr);gap:10px}
  .quick-card{flex-direction:column;text-align:center;padding:16px 8px;gap:8px}
  .section-head-actions{width:100%;justify-content:space-between}
  .news-track>.news-card{flex-basis:84%}
  .carousel-nav button{width:38px;height:38px}
}
@media(prefers-reduced-motion:reduce){
  *,*::before,*::after{animation:none !important;transition-duration:.01ms !important}
  .js .reveal{opacity:1;transform:none}
  html{scroll-behavior:auto}
}
/* ALLAMEH MODERN REFRESH */
:root{--bg:#f4f7ff;--line:#e4eaf5;--shadow:0 18px 48px rgba(24,45,90,.09);--radius-lg:24px}
body{background:radial-gradient(ellipse at 100% 0%,rgba(218,232,255,.55),transparent 28%),radial-gradient(ellipse at 0% 40%,rgba(209,250,241,.32),transparent 26%),var(--bg)}
::selection{background:#c8dcff;color:#15284d}
a,button,.btn,.panel-card,.card,.notice,.badge-role{transition:transform .22s ease,box-shadow .22s ease,border-color .22s ease,background-color .22s ease}
a:focus-visible,button:focus-visible,input:focus-visible,select:focus-visible,textarea:focus-visible{outline:3px solid #6b9cff;outline-offset:3px}
.nav-wrap{box-shadow:0 8px 28px rgba(24,45,90,.045)}
.brand-mark{border-radius:17px;box-shadow:0 10px 24px rgba(36,88,211,.2)}
.btn{border-radius:13px;font-weight:800;letter-spacing:.05px;box-shadow:0 4px 12px rgba(22,42,78,.06)}
.btn:hover{transform:translateY(-2px);box-shadow:0 9px 22px rgba(22,42,78,.13)}
.btn-primary{background:linear-gradient(135deg,var(--blue),#5278e9)}
.panel-wrap{padding-bottom:56px}
.panel-heading{position:relative;overflow:hidden;border:1px solid rgba(215,226,246,.85);border-radius:26px;padding:24px 28px!important;background:linear-gradient(115deg,#fff 5%,#f2f6ff 62%,#e7fbf6 100%);box-shadow:var(--shadow);margin:24px 0!important}
.panel-heading:after{content:"";position:absolute;width:180px;height:180px;border:1px solid #d4e2fb;border-radius:50%;left:-52px;top:-82px;box-shadow:0 0 0 20px #d4e2fb30,0 0 0 42px #d4e2fb20;pointer-events:none}
.panel-heading h1{font-size:clamp(23px,3vw,32px);letter-spacing:-.5px}
.panel-heading p{color:var(--muted)}
.badge-role{border:1px solid #d9e6ff;background:#fff;color:var(--blue);box-shadow:0 5px 16px #2458d313;border-radius:999px;padding:8px 15px;font-weight:850}
.panel-card{border:1px solid rgba(224,231,244,.95)!important;border-radius:22px!important;background:rgba(255,255,255,.94)!important;box-shadow:0 8px 28px rgba(25,46,87,.055);padding:clamp(17px,2.2vw,26px)!important}
.panel-card:hover{box-shadow:0 14px 36px rgba(25,46,87,.085)}
.panel-card h2{display:flex;align-items:center;gap:10px;flex-wrap:wrap;color:#1a2c4d;font-size:18px;margin-top:0}
.panel-grid{gap:18px!important}
.panel-table-wrap{border:1px solid #e5ebf6;border-radius:16px;overflow:auto;background:#fff}
.panel-table{border-collapse:separate!important;border-spacing:0!important;min-width:620px}
.panel-table th{position:sticky;top:0;background:#f0f5ff!important;color:#3d5276;font-weight:900;font-size:12px;border-bottom:1px solid #dfe8f8!important}
.panel-table td,.panel-table th{padding:12px 14px!important;border-bottom:1px solid #edf1f8!important}
.panel-table tr:last-child td{border-bottom:0!important}
.panel-table tr:hover td{background:#f8faff}
.panel-form input,.panel-form select,.panel-form textarea,input,select,textarea{border-radius:12px}
input:focus,select:focus,textarea:focus{border-color:#8daeff!important;box-shadow:0 0 0 4px rgba(68,115,229,.1)}
.tips-box{border:1px solid #dce8ff!important;border-radius:18px!important;background:linear-gradient(120deg,#edf4ff,#f2fffc)!important;box-shadow:0 8px 24px #244b8010}
.notice{border-radius:14px!important}
.activity-pager{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-top:14px;padding-top:12px;border-top:1px solid #edf1f8}
.activity-pager .pager-actions{display:flex;align-items:center;gap:6px;flex-wrap:wrap}
.activity-pager a,.activity-pager span{display:inline-flex;align-items:center;justify-content:center;min-width:36px;height:36px;padding:0 10px;border:1px solid #dce5f5;border-radius:11px;background:#fff;color:#3c5277;font-size:12px;font-weight:800}
.activity-pager a:hover{background:#edf4ff;border-color:#a9c2fa;transform:translateY(-1px)}
.activity-pager .current{background:var(--blue);color:#fff;border-color:var(--blue)}
@keyframes riseIn{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}
.panel-card,.panel-heading,.tips-box{animation:riseIn .42s ease both}
.panel-card:nth-of-type(2){animation-delay:.04s}.panel-card:nth-of-type(3){animation-delay:.08s}
@media(prefers-reduced-motion:reduce){*,*::before,*::after{animation-duration:.01ms!important;transition-duration:.01ms!important;scroll-behavior:auto!important}}
@media(max-width:720px){.panel-heading{padding:18px!important;border-radius:20px!important}.panel-heading h1{font-size:23px}.panel-nav{gap:6px;flex-wrap:wrap}.panel-card{padding:15px!important}.panel-table{min-width:560px}}

/* ===== FINAL FIXES ===== */
.panel-heading .badge-role{background:#fff !important;color:var(--blue) !important;
  border:1px solid #c7d8ff !important;box-shadow:0 6px 18px rgba(36,88,211,.14) !important;font-weight:850 !important}
.panel-heading .badge-role svg{color:var(--blue) !important}
.file-chip{display:inline-flex;align-items:center;gap:8px;background:#eff6ff;
  border:1px solid #bfdbfe;border-radius:10px;padding:7px 12px;font-size:12px;
  color:#1e40af;font-weight:700;margin-top:8px;transition:.2s}
.file-chip:hover{background:#dbeafe;transform:translateY(-1px)}
.file-chip svg{width:16px;height:16px}
@keyframes slideFadeIn{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:none}}
.panel-card{animation:slideFadeIn .35s ease both}
.comment-card{border-right:3px solid var(--cyan);background:linear-gradient(90deg,#f0fdfa,#fff)}
.badge-pagination{display:flex;align-items:center;gap:6px;margin-top:14px;flex-wrap:wrap}
.badge-pagination a,.badge-pagination span{display:inline-flex;align-items:center;
  justify-content:center;min-width:34px;height:34px;padding:0 10px;border:1px solid #dce5f5;
  border-radius:10px;background:#fff;color:#3c5277;font-size:12px;font-weight:800}
.badge-pagination a:hover{background:#edf4ff;border-color:#a9c2fa}
.badge-pagination .current{background:var(--blue);color:#fff;border-color:var(--blue)}
"""


# ---------------- PUBLIC HEADER / FOOTER ----------------
def _public_header(active=""):
    site_name = _html.escape(_get_setting("school_name", "مدرسه علامه"))
    logo = _get_setting("site_logo", "")
    logo_html = f'<img src="/static/uploads/{_html.escape(logo)}" alt="">' if logo else ICONS["school"]
    pn = _get_setting("public_news", "1") == "1"
    pa = _get_setting("public_announcements", "1") == "1"
    pc = _get_setting("public_contact", "1") == "1"

    path = request.path

    def _lnk(href, label):
        is_cur = (path == "/") if href == "/" else path.startswith(href)
        cur = ' class="active" aria-current="page"' if is_cur else ""
        return f'<a href="{href}"{cur}>{label}</a>'

    links = [_lnk("/", "صفحه اصلی")]
    if pn: links.append(_lnk("/news", "اخبار و رویدادها"))
    if pa: links.append(_lnk("/announcements", "اطلاعیه‌ها"))
    if pc: links.append(_lnk("/contact", "تماس با ما"))

    bell_html = (
        '<button class="notif-bell-btn" onclick="toggleNotifPanel(event)" '
        'aria-label="اعلان‌ها" type="button">' + ICONS["bell"] +
        '<span class="notif-badge" id="notifBadge" style="display:none">0</span>'
        '</button>'
    )
    role = session.get("role")
    role_labels = {"owner": "مدیر ارشد", "admin": "مدیر عادی", "teacher": "معلم",
                   "student": "دانش‌آموز", "parent": "والدین"}
    if session.get("user_id") and role in role_labels:
        cta_html = (f'<a class="nav-cta" href="/dashboard">{ICONS["login"]}'
                    f'<span class="cta-full">ورود به پنل {role_labels[role]}</span>'
                    f'<span class="cta-short">پنل من</span></a>')
    else:
        cta_html = (f'<a class="nav-cta" href="/login">{ICONS["login"]}'
                    '<span class="cta-full">ورود / ثبت‌نام</span>'
                    '<span class="cta-short">ورود</span></a>')

    notifs = _get_public_notifications(15)
    items_html = ""
    for n in notifs:
        items_html += (
            f'<a href="{_html.escape(n["link"] or "#")}" class="notif-item" '
            f'data-id="{n["id"]}">'
            f'<span class="notif-item-icon">{_icon_for_kind(n["kind"])}</span>'
            '<div class="notif-item-body">'
            '<span class="notif-item-new" style="display:none">جدید</span>'
            f'<div class="notif-item-title">{_html.escape(n["title"])}</div>'
            f'<div class="notif-item-time">{_html.escape((n["created_at"] or "")[:16])}</div>'
            '</div></a>'
        )
    if not items_html:
        items_html = '<div style="padding:30px;text-align:center;color:#94a3b8">اعلانی وجود ندارد</div>'

    return f"""<div class="topbar"><div class="container topbar-inner">
<span><i class="dot"></i>به وب‌سایت {site_name} خوش آمدید</span>
<span class="topbar-motto">دانش امروز، آینده‌ای روشن‌تر</span></div></div>
<header class="nav-wrap"><div class="container nav">
<a href="/" class="brand">
  <span class="brand-mark">{logo_html}</span>
  <span><span class="brand-name">{site_name}</span>
  <span class="brand-sub">ALLAMEH SCHOOL</span></span>
</a>
<nav class="nav-links" id="navLinks" aria-label="منوی اصلی">{''.join(links)}</nav>
<div class="nav-actions">{bell_html}{cta_html}
<button class="mobile-menu" aria-label="باز و بسته کردن منو" aria-expanded="false"
        aria-controls="navLinks" onclick="toggleMenu()" type="button">{ICONS["menu"]}</button></div>
</div></header>

<div class="notif-overlay" id="notifOverlay" onclick="closeNotifPanel()" style="display:none"></div>
<div class="notif-panel" id="notifPanel" style="display:none">
  <div class="notif-panel-header">
    <strong>اعلان‌ها</strong>
    <button class="notif-close" onclick="closeNotifPanel()" type="button">✕</button>
  </div>
  <div class="notif-panel-body">{items_html}</div>
</div>

<script>
(function(){{
  var KEY='allameh_notif_seen',lastSeen=parseInt(localStorage.getItem(KEY)||'0',10);
  var items=document.querySelectorAll('.notif-item[data-id]'),unseen=0;
  items.forEach(function(el){{
    var id=parseInt(el.getAttribute('data-id'),10);
    if(id>lastSeen){{el.classList.add('new');unseen++;}}
  }});
  var badge=document.getElementById('notifBadge');
  if(badge&&unseen>0){{badge.textContent=unseen;badge.style.display='inline-flex';}}
  var banner=document.getElementById('notifBanner');
  if(banner&&unseen>0)banner.style.display='block';
  function markAllSeen(){{
    var maxId=0;
    items.forEach(function(el){{var id=parseInt(el.getAttribute('data-id'),10);if(id>maxId)maxId=id;}});
    if(maxId>0)localStorage.setItem(KEY,String(maxId));
    if(badge)badge.style.display='none';
  }}
  window.toggleNotifPanel=function(e){{
    if(e)e.preventDefault();
    var p=document.getElementById('notifPanel'),o=document.getElementById('notifOverlay');
    if(p.style.display==='none'){{p.style.display='block';o.style.display='block';markAllSeen();}}
    else{{p.style.display='none';o.style.display='none';}}
  }};
  window.closeNotifPanel=function(){{
    document.getElementById('notifPanel').style.display='none';
    document.getElementById('notifOverlay').style.display='none';
  }};
  window.dismissNotifBanner=function(){{
    var b=document.getElementById('notifBanner');
    if(b)b.style.display='none';
    markAllSeen();
  }};
}})();
</script>"""


def _public_footer():
    site_name = _html.escape(_get_setting("school_name", "مدرسه علامه"))
    footer_text = _html.escape(_get_setting("footer_text", ""))
    phone = _html.escape(_get_setting("contact_phone", ""))
    email = _html.escape(_get_setting("contact_email", ""))
    addr = _html.escape(_get_setting("contact_address", ""))
    pn = _get_setting("public_news", "1") == "1"
    pa = _get_setting("public_announcements", "1") == "1"
    pc = _get_setting("public_contact", "1") == "1"

    contact_html = ""
    if phone or email or addr:
        contact_html = '<div class="footer-contact">'
        if phone: contact_html += f'<span>{ICONS["phone"]} {phone}</span>'
        if email: contact_html += f'<span>{ICONS["mail"]} {email}</span>'
        if addr: contact_html += f'<span>{ICONS["map"]} {addr}</span>'
        contact_html += '</div>'

    quick = ['<a href="/">صفحه اصلی</a>']
    if pn: quick.append('<a href="/news">اخبار</a>')
    if pa: quick.append('<a href="/announcements">اطلاعیه‌ها</a>')
    if pc: quick.append('<a href="/contact">تماس</a>')

    return f"""<footer class="footer"><div class="container">
<div class="footer-grid">
  <div><h4>{site_name}</h4><p>{footer_text}</p>{contact_html}</div>
  <div><h4>دسترسی سریع</h4><div class="footer-links">{''.join(quick)}</div></div>
  <div><h4>ورود کاربران</h4><div class="footer-links">
    <a href="/login">ورود مدیر / معلم / دانش‌آموز</a>
  </div></div>
</div>
<div class="footer-bottom">
  <span>© {site_name} — تمامی حقوق محفوظ است.</span>
  <span>طراحی‌شده با هدف آموزش بهتر</span>
</div>
</div></footer>
<script>
function toggleMenu(force){{
    var m=document.getElementById("navLinks");
    var b=document.querySelector(".mobile-menu");
    if(!m||!b) return;
    var open=(typeof force==="boolean")?force:!m.classList.contains("open");
    m.classList.toggle("open",open);
    b.setAttribute("aria-expanded",String(open));
}}
document.addEventListener("click",function(e){{
    var m=document.getElementById("navLinks");
    if(!m||!m.classList.contains("open")) return;
    if(e.target.closest("#navLinks a")||!e.target.closest(".nav")) toggleMenu(false);
}});
document.addEventListener("keydown",function(e){{ if(e.key==="Escape") toggleMenu(false); }});
</script>"""


# ---------------- AUTH HELPERS ----------------
def role_required(*roles):
    roles = set(roles)
    if "admin" in roles: roles.add("owner")
    def dec(view):
        @wraps(view)
        def wrapped(*a, **k):
            user_id = session.get("user_id")
            if not user_id:
                flash("ابتدا وارد حساب کاربری خود شوید.", "error")
                return redirect(url_for("login"))
            db = get_db()
            try:
                user = db.execute(
                    "SELECT id, username, role, full_name, class_name, is_active "
                    "FROM users WHERE id=?", (user_id,)
                ).fetchone()
            finally:
                db.close()
            if not user or not user["is_active"]:
                session.clear()
                flash("حساب کاربری فعال نیست؛ دوباره وارد شوید.", "error")
                return redirect(url_for("login"))
            if user["role"] not in roles:
                abort(403)
            session.update(username=user["username"], role=user["role"],
                           full_name=user["full_name"], class_name=user["class_name"] or "")
            return view(*a, **k)
        return wrapped
    return dec


def owner_required(view):
    @wraps(view)
    def wrapped(*a, **k):
        if "user_id" not in session:
            flash("ابتدا وارد شوید.", "error")
            return redirect(url_for("login"))
        if session.get("role") != "owner": abort(403)
        return view(*a, **k)
    return wrapped


@app.context_processor
def inject_globals():
    pending_count = 0
    pending_users = []
    if session.get("role") in ("owner", "admin"):
        db = get_db()
        try:
            pending_users = db.execute(
                "SELECT id, username, role, full_name, class_name, created_at "
                "FROM users WHERE is_active=0 ORDER BY created_at ASC"
            ).fetchall()
            pending_count = len(pending_users)
        finally:
            db.close()
    panel_accent = ""
    if session.get("user_id"):
        db = get_db()
        try:
            r = db.execute("SELECT panel_accent FROM users WHERE id=?",
                           (session["user_id"],)).fetchone()
            if r and r["panel_accent"]:
                panel_accent = r["panel_accent"]
        except Exception:
            pass
        finally:
            db.close()
    return {
        "icons": ICONS, "classes": CLASSES, "post_types": POST_TYPES,
        "author_html": _author_html,
        "site_logo": _get_setting("site_logo", ""),
        "site_name": _get_setting("school_name", "مدرسه علامه"),
        "has_owner": _has_owner(),
        "pending_count": pending_count,
        "pending_users": pending_users,
        "panel_accent": panel_accent,
        "contact_info": {
            "contact_phone": _get_setting("contact_phone", ""),
            "contact_email": _get_setting("contact_email", ""),
            "contact_address": _get_setting("contact_address", ""),
        },
        "public": {
            "public_news": _get_setting("public_news", "1"),
            "public_announcements": _get_setting("public_announcements", "1"),
            "public_comments": _get_setting("public_comments", "1"),
            "public_contact": _get_setting("public_contact", "1"),
        },
    }


@app.before_request
def limit_login_attempts():
    if request.path != "/login" or request.method != "POST":
        return None
    addr = (request.remote_addr or "unknown")[:64]
    username = (request.form.get("username", "") or "").strip().lower()[:80]
    cutoff = (datetime.utcnow() - timedelta(minutes=15)).strftime("%Y-%m-%d %H:%M:%S")
    db = get_db()
    try:
        db.execute("DELETE FROM auth_attempts WHERE attempted_at < ?",
                   ((datetime.utcnow() - timedelta(days=1)).strftime("%Y-%m-%d %H:%M:%S"),))
        count = db.execute(
            "SELECT COUNT(*) FROM auth_attempts WHERE attempted_at>=? "
            "AND (remote_addr=? OR (identifier<>'' AND identifier=?))",
            (cutoff, addr, username)
        ).fetchone()[0]
        db.commit()
    finally:
        db.close()
    if count >= 10:
        return ("تعداد تلاش‌های ورود بیش از حد مجاز است. ۱۵ دقیقه دیگر دوباره تلاش کنید.", 429)
    return None


@app.after_request
def record_failed_login_attempts(response):
    if request.path == "/login" and request.method == "POST" and response.status_code == 200:
        addr = (request.remote_addr or "unknown")[:64]
        username = (request.form.get("username", "") or "").strip().lower()[:80]
        db = get_db()
        try:
            db.execute("INSERT INTO auth_attempts(remote_addr, identifier, attempted_at) "
                       "VALUES(?,?,?)", (addr, username, now_text()))
            db.commit()
        finally:
            db.close()
    return response


@app.after_request
def security_headers(response):
    response.headers.update({
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
        "Content-Security-Policy": (
            "default-src 'self'; "
            "img-src 'self' data:; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "font-src 'self' data: https://cdn.jsdelivr.net; "
            "script-src 'self' 'unsafe-inline'; "
            "connect-src 'self'; base-uri 'self'; form-action 'self'; "
            "frame-ancestors 'none'"
        ),
    })
    private_prefixes = ("/dashboard", "/admin", "/teacher", "/student", "/parent", "/account", "/academics", "/homework", "/exams", "/reports")
    if request.path.startswith(private_prefixes):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    else:
        response.headers.setdefault("Cache-Control", "public, max-age=300")
    return response


@app.errorhandler(HTTPException)
def http_error(e):
    if e.code == 403: return ("دسترسی ممنوع. <a href='/dashboard'>بازگشت</a>", 403)
    if e.code == 404: return ("صفحه یافت نشد. <a href='/'>بازگشت</a>", 404)
    if e.code == 413: return ("فایل بیش از ۲۵ مگابایت. <a href='/dashboard'>بازگشت</a>", 413)
    return e


@app.errorhandler(Exception)
def generic_error(e):
    traceback.print_exc()
    return ("خطای داخلی سرور. لطفاً بعداً دوباره تلاش کنید. <a href='/'>بازگشت</a>", 500)


# ---------------- PUBLIC ROUTES ----------------
@app.route("/")
def home():
    db = get_db()
    try:
        posts = db.execute("""
            SELECT p.*,
                   COALESCE(NULLIF(u.full_name,''), NULLIF(p.creator_name_snap,''), 'نامشخص') AS creator_name,
                   COALESCE(NULLIF(u.role,''), NULLIF(p.creator_role_snap,'')) AS creator_role
            FROM site_posts p LEFT JOIN users u ON u.id=p.created_by
            ORDER BY p.id DESC LIMIT 6""").fetchall()
        announcements = db.execute("""
            SELECT a.*,
                   COALESCE(NULLIF(u.full_name,''), NULLIF(a.creator_name_snap,''), 'نامشخص') AS creator_name,
                   COALESCE(NULLIF(u.role,''), NULLIF(a.creator_role_snap,'')) AS creator_role
            FROM announcements a LEFT JOIN users u ON u.id=a.created_by
            ORDER BY a.is_pinned DESC, a.id DESC LIMIT 5""").fetchall()
        stats = {
            "posts": db.execute("SELECT COUNT(*) FROM site_posts").fetchone()[0],
            "announcements": db.execute("SELECT COUNT(*) FROM announcements").fetchone()[0],
            "students": db.execute("SELECT COUNT(*) FROM users WHERE role='student' AND is_active=1").fetchone()[0],
            "teachers": db.execute("SELECT COUNT(*) FROM users WHERE role='teacher' AND is_active=1").fetchone()[0],
        }
        site = {r["key"]: r["value"] for r in db.execute("SELECT key,value FROM settings").fetchall()}
        notifs_top = db.execute(
            "SELECT * FROM notifications WHERE target='all' ORDER BY id DESC LIMIT 3"
        ).fetchall()
        notif_banner_items = ""
        for n in notifs_top:
            notif_banner_items += (
                f'<a href="{_html.escape(n["link"] or "#")}" class="notif-banner-item">'
                f'{_icon_for_kind(n["kind"])} {_html.escape(n["title"])}</a>'
            )
    finally:
        db.close()
    return render_template("home.html", style=_style(), posts=posts,
                                  announcements=announcements, site=site, stats=stats,
                                  notif_banner_items=notif_banner_items,
                                  header=_public_header(), footer=_public_footer())


@app.route("/news")
def public_news():
    if _get_setting("public_news", "1") != "1": abort(404)
    q = request.args.get("q", "").strip()
    ptype = request.args.get("type", "").strip()
    db = get_db()
    try:
        base_sql = ("SELECT p.*, "
                    "COALESCE(NULLIF(u.full_name,''), NULLIF(p.creator_name_snap,''), 'نامشخص') AS creator_name, "
                    "COALESCE(NULLIF(u.role,''), NULLIF(p.creator_role_snap,'')) AS creator_role "
                    "FROM site_posts p LEFT JOIN users u ON u.id=p.created_by")
        params, conds = [], []
        if ptype and ptype in POST_TYPES:
            conds.append("p.type=?"); params.append(ptype)
        if q:
            conds.append("(p.title LIKE ? OR p.body LIKE ?)")
            params.extend([f"%{q}%", f"%{q}%"])
        where = (" WHERE " + " AND ".join(conds)) if conds else ""
        page = max(1, min(int(request.args.get("page", "1") or "1"), 100000))
        per_page = 12
        total = db.execute("SELECT COUNT(*) FROM site_posts p" + where, params).fetchone()[0]
        all_posts = db.execute(
            base_sql + where + " ORDER BY p.id DESC LIMIT ? OFFSET ?",
            params + [per_page + 1, (page - 1) * per_page]
        ).fetchall()
        has_more = len(all_posts) > per_page
        all_posts = all_posts[:per_page]
        type_stats = {k: 0 for k in POST_TYPES}
        for row in db.execute("SELECT type, COUNT(*) AS c FROM site_posts GROUP BY type").fetchall():
            if row["type"] in type_stats: type_stats[row["type"]] = row["c"]
        featured = None; posts = all_posts
        if not q and not ptype and all_posts:
            featured = all_posts[0]; posts = all_posts[1:]
        site = {r["key"]: r["value"] for r in db.execute("SELECT key,value FROM settings").fetchall()}
    finally:
        db.close()
    return render_template("news.html", style=_style(), site=site,
                                  site_name=_html.escape(_get_setting("school_name", "مدرسه علامه")),
                                  posts=posts, featured=featured, query=q, ptype=ptype,
                                  stats={"total": total}, type_stats=type_stats,
                                  page=page, has_more=has_more,
                                  header=_public_header(), footer=_public_footer())


@app.route("/news/<int:pid>", methods=["GET", "POST"])
def public_post(pid):
    if _get_setting("public_news", "1") != "1": abort(404)
    db = get_db()
    try:
        post = db.execute("""
            SELECT p.*,
                   COALESCE(NULLIF(u.full_name,''), NULLIF(p.creator_name_snap,''), 'نامشخص') AS creator_name,
                   COALESCE(NULLIF(u.role,''), NULLIF(p.creator_role_snap,'')) AS creator_role
            FROM site_posts p LEFT JOIN users u ON u.id=p.created_by
            WHERE p.id=?""", (pid,)).fetchone()
        if not post: abort(404)
        if request.method == "POST":
            if _get_setting("public_comments", "1") != "1":
                flash("ثبت نظر غیرفعال است.", "error"); return redirect(url_for("public_post", pid=pid))
            name = request.form.get("name", "").strip()[:60]
            body = request.form.get("body", "").strip()[:1000]
            if name and body:
                db.execute("INSERT INTO comments(post_id,author_name,body,is_approved,created_at) "
                           "VALUES(?,?,?,0,?)", (pid, name, body, now_text()))
                db.commit()
                flash("نظر شما ارسال شد. پس از تأیید نمایش داده می‌شود.", "success")
                return redirect(url_for("public_post", pid=pid))
            flash("نام و متن نظر الزامی است.", "error")
        comments = db.execute("SELECT * FROM comments WHERE post_id=? AND is_approved=1 "
                              "ORDER BY id DESC LIMIT 100", (pid,)).fetchall()
        site = {r["key"]: r["value"] for r in db.execute("SELECT key,value FROM settings").fetchall()}
    finally:
        db.close()
    return render_template("post.html", style=_style(), site=site,
                                  site_name=_html.escape(_get_setting("school_name", "مدرسه علامه")),
                                  post=post, comments=comments,
                                  public_comments=(_get_setting("public_comments", "1") == "1"),
                                  header=_public_header(), footer=_public_footer())


@app.route("/announcements")
def public_announcements():
    if _get_setting("public_announcements", "1") != "1": abort(404)
    filter_ = request.args.get("filter", "all").strip()
    db = get_db()
    try:
        base = ("SELECT a.*, "
                "COALESCE(NULLIF(u.full_name,''), NULLIF(a.creator_name_snap,''), 'نامشخص') AS creator_name, "
                "COALESCE(NULLIF(u.role,''), NULLIF(a.creator_role_snap,'')) AS creator_role "
                "FROM announcements a LEFT JOIN users u ON u.id=a.created_by")
        all_rows = db.execute(base + " ORDER BY a.is_pinned DESC, a.id DESC").fetchall()
        total = len(all_rows)
        pinned_count = sum(1 for r in all_rows if r["is_pinned"])
        week_cutoff = (datetime.utcnow() - timedelta(days=7)).strftime("%Y-%m-%d %H:%M:%S")
        week_count = sum(1 for r in all_rows if r["created_at"] >= week_cutoff)
        if filter_ == "pinned":
            pinned, regular = [], [r for r in all_rows if r["is_pinned"]]
        elif filter_ == "week":
            pinned, regular = [], [r for r in all_rows if r["created_at"] >= week_cutoff]
        else:
            pinned = [r for r in all_rows if r["is_pinned"]]
            regular = [r for r in all_rows if not r["is_pinned"]]
        stats = {"total": total, "pinned": pinned_count, "week": week_count}
        site = {r["key"]: r["value"] for r in db.execute("SELECT key,value FROM settings").fetchall()}
    finally:
        db.close()
    return render_template("announcements.html", style=_style(), site=site,
                                  site_name=_html.escape(_get_setting("school_name", "مدرسه علامه")),
                                  pinned=pinned, regular=regular, filter=filter_,
                                  stats=stats,
                                  header=_public_header(), footer=_public_footer())


@app.route("/contact", methods=["GET", "POST"])
def public_contact():
    if _get_setting("public_contact", "1") != "1": abort(404)
    if request.method == "POST":
        name = request.form.get("name", "").strip()[:60]
        contact = request.form.get("contact", "").strip()[:100]
        body = request.form.get("body", "").strip()[:2000]
        if name and body:
            db = get_db()
            try:
                db.execute("INSERT INTO contact_messages(name,contact,body,created_at) "
                           "VALUES(?,?,?,?)", (name, contact, body, now_text()))
                db.commit()
            finally:
                db.close()
            _push_notification("contact_message",
                               f"پیام جدید از {name}",
                               body[:200], "/admin", target="admin")
            flash("پیام شما ارسال شد. سپاسگزاری!", "success")
            return redirect(url_for("public_contact"))
        flash("نام و متن پیام الزامی است.", "error")
    db = get_db()
    try:
        site = {r["key"]: r["value"] for r in db.execute("SELECT key,value FROM settings").fetchall()}
    finally:
        db.close()
    return render_template("contact.html", style=_style(), site=site,
                                  site_name=_html.escape(_get_setting("school_name", "مدرسه علامه")),
                                  header=_public_header(), footer=_public_footer())


# ---------------- FILES ----------------
@app.route("/files/<path:filename>")
def public_file(filename):
    if not re.fullmatch(r"[a-f0-9]{40}\.[a-z0-9]{2,5}", filename):
        abort(404)
    return send_from_directory(app.config["PUBLIC_FILES_FOLDER"], filename)


# ---------------- LOGIN ----------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("user_id"): return redirect(url_for("dashboard"))
    active_role = "admin"
    if request.method == "POST":
        role = request.form.get("role", "").strip()
        if role in ("owner", "admin", "teacher", "student", "parent"):
            active_role = role
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        code = request.form.get("code", "").strip()
        full_name = request.form.get("full_name", "").strip()
        class_name = request.form.get("class_name", "").strip()
        mode = request.form.get("mode", "login")

        if role == "owner":
            if mode == "register":
                if _has_owner():
                    flash("مدیر ارشد قبلاً ساخته شده است.", "error")
                    return redirect(url_for("login"))
                confirm = request.form.get("confirm", "")
                errors = []
                if not re.fullmatch(r"[a-zA-Z0-9_.-]{3,40}", username):
                    errors.append("نام کاربری نامعتبر (۳ تا ۴۰ نویسه انگلیسی/عدد/نقطه).")
                if len(full_name) < 3 or len(full_name) > 80:
                    errors.append("نام کامل باید ۳ تا ۸۰ نویسه باشد.")
                if len(password) < 12:
                    errors.append("رمز عبور مدیر ارشد باید حداقل ۱۲ نویسه باشد.")
                if password != confirm:
                    errors.append("رمزها یکسان نیستند.")
                if errors:
                    for e in errors: flash(e, "error")
                    return redirect(url_for("login"))
                try:
                    db = get_db()
                    try:
                        db.execute(
                            "INSERT INTO users(username,password_hash,role,full_name,"
                            "class_name,is_active,created_at) VALUES(?,?,'owner',?,'',1,?)",
                            (username, generate_password_hash(password), full_name, now_text()))
                        new_id = db.execute("SELECT id FROM users WHERE username=?",
                                            (username,)).fetchone()["id"]
                        db.commit()
                    finally:
                        db.close()
                    g._owner_cache = True
                    _log(new_id, "owner_created_via_login_register", username)
                    flash("حساب مدیر ارشد ساخته شد. حالا وارد شوید.", "success")
                    return redirect(url_for("login"))
                except sqlite3.IntegrityError:
                    flash("نام کاربری گرفته شده.", "error")
                    return redirect(url_for("login"))

            if not username or not password:
                flash("نام کاربری و رمز عبور را وارد کنید.", "error")
                return redirect(url_for("login"))
            db = get_db()
            try:
                u = db.execute("SELECT id,username,password_hash,role,full_name,is_active "
                               "FROM users WHERE username=? AND role='owner'",
                               (username,)).fetchone()
            finally:
                db.close()
            if u and u["is_active"] and check_password_hash(u["password_hash"], password):
                session.clear()
                session.permanent = True
                session.update(user_id=u["id"], username=u["username"], role="owner",
                               full_name=u["full_name"], class_name="")
                _log(u["id"], "login_owner", f"ip={request.remote_addr}")
                flash(f"خوش آمدید {u['full_name']}.", "success")
                return redirect(url_for("admin_panel"))
            flash("نام کاربری یا رمز اشتباه است.", "error")
            return redirect(url_for("login"))

        if role == "admin":
            if mode == "register":
                errors = []
                min_pw = _password_min("admin")
                if not re.fullmatch(r"[a-zA-Z0-9_.-]{3,40}", username):
                    errors.append("نام کاربری نامعتبر.")
                if len(full_name) < 3 or len(full_name) > 80:
                    errors.append("نام کامل معتبر نیست.")
                if len(password) < min_pw:
                    errors.append(f"رمز عبور حداقل {min_pw} نویسه.")
                db = get_db()
                try:
                    row = db.execute("SELECT value FROM settings WHERE key='admin_code'").fetchone()
                    expected = row["value"] if row else ""
                    if not expected or expected != code.upper():
                        errors.append("کد مدیر معتبر نیست.")
                    elif db.execute("SELECT 1 FROM users WHERE username=?",
                                    (username,)).fetchone():
                        errors.append("این نام کاربری گرفته شده.")
                finally:
                    db.close()
                if errors:
                    for e in errors: flash(e, "error")
                    return redirect(url_for("login"))
                db = get_db()
                try:
                    db.execute("INSERT INTO users(username,password_hash,role,full_name,"
                               "class_name,is_active,created_at) VALUES(?,?,'admin',?,'',0,?)",
                               (username, generate_password_hash(password), full_name, now_text()))
                    new_id = db.execute("SELECT id FROM users WHERE username=?",
                                        (username,)).fetchone()["id"]
                    db.commit()
                finally:
                    db.close()
                _push_notification("registration_pending",
                                   f"درخواست ثبت‌نام مدیر: {full_name}",
                                   f"نام کاربری: {username}",
                                   "/admin", target="admin")
                _log(new_id, "admin_registration_pending", username)
                flash("درخواست ثبت‌نام مدیر ثبت شد. پس از تأیید مدیر ارشد می‌توانید وارد شوید.", "success")
                return redirect(url_for("login"))

            if not username or not password:
                flash("نام کاربری و رمز عبور را وارد کنید.", "error")
                return redirect(url_for("login"))
            db = get_db()
            try:
                u = db.execute("SELECT id,username,password_hash,role,full_name,is_active "
                               "FROM users WHERE username=? AND role IN ('owner','admin')",
                               (username,)).fetchone()
            finally:
                db.close()
            if u and check_password_hash(u["password_hash"], password):
                if not u["is_active"]:
                    flash("حساب شما در انتظار تأیید مدیر است. لطفاً بعداً تلاش کنید.", "error")
                    return redirect(url_for("login"))
                session.clear()
                session.permanent = True
                session.update(user_id=u["id"], username=u["username"],
                               role=u["role"], full_name=u["full_name"], class_name="")
                _log(u["id"], f"login_{u['role']}", f"ip={request.remote_addr}")
                flash(f"خوش آمدید {u['full_name']}.", "success")
                return redirect(url_for("admin_panel"))
            flash("نام کاربری یا رمز اشتباه است.", "error")
            return redirect(url_for("login"))

        if role in ("teacher", "student", "parent"):
            min_pw = _password_min(role)
            child_username = request.form.get("child_username", "").strip() if role == "parent" else ""
            if code:
                errors = []
                if len(full_name) < 3: errors.append("نام کامل معتبر نیست.")
                if len(password) < min_pw: errors.append(f"رمز عبور حداقل {min_pw} نویسه.")
                if not re.fullmatch(r"[a-zA-Z0-9_.-]{3,40}", username): errors.append("نام کاربری نامعتبر.")
                if role == "student" and class_name not in CLASSES: errors.append("کلاس را انتخاب کنید.")
                if role == "parent" and not re.fullmatch(r"[a-zA-Z0-9_.-]{3,40}", child_username):
                    errors.append("نام کاربری فرزند را دقیق وارد کنید.")
                key = f"{role}_code"
                db = get_db()
                try:
                    row = db.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
                    expected = row["value"] if row else ""
                    if not expected or expected != code.upper():
                        errors.append(f"کد {role} معتبر نیست.")
                    elif db.execute("SELECT 1 FROM users WHERE username=?",
                                    (username,)).fetchone():
                        errors.append("این نام کاربری گرفته شده.")
                    if role == "parent" and not errors:
                        child = db.execute("SELECT id FROM users WHERE username=? AND role='student' AND is_active=1",
                                           (child_username,)).fetchone()
                        if not child:
                            errors.append("دانش‌آموز فعال با این نام کاربری پیدا نشد.")
                finally:
                    db.close()
                if errors:
                    for e in errors: flash(e, "error")
                    return redirect(url_for("login"))
                db = get_db()
                try:
                    db.execute("INSERT INTO users(username,password_hash,role,full_name,"
                               "class_name,is_active,created_at) VALUES(?,?,?,?,?,0,?)",
                               (username, generate_password_hash(password), role,
                                full_name, class_name, now_text()))
                    new_id = db.execute("SELECT id FROM users WHERE username=?",
                                        (username,)).fetchone()["id"]
                    if role == "parent":
                        child = db.execute("SELECT id FROM users WHERE username=? AND role='student' AND is_active=1",
                                           (child_username,)).fetchone()
                        if child:
                            db.execute("INSERT OR IGNORE INTO parent_student(parent_id,student_id) VALUES(?,?)",
                                       (new_id, child["id"]))
                    db.commit()
                finally:
                    db.close()
                _push_notification("registration_pending",
                                   f"درخواست ثبت‌نام {role}: {full_name}",
                                   f"نام کاربری: {username}" + (f" — کلاس: {class_name}" if class_name else ""),
                                   "/admin", target="admin")
                _log(new_id, f"{role}_registration_pending", username)
                flash("ثبت‌نام شما ثبت شد. پس از تأیید مدیر می‌توانید وارد شوید.", "success")
                return redirect(url_for("login"))

            if not username or not password:
                flash("نام کاربری و رمز عبور را وارد کنید.", "error")
                return redirect(url_for("login"))
            db = get_db()
            try:
                u = db.execute("SELECT id,username,password_hash,role,full_name,class_name,is_active "
                               "FROM users WHERE username=? AND role=?", (username, role)).fetchone()
            finally:
                db.close()
            if u and check_password_hash(u["password_hash"], password):
                if not u["is_active"]:
                    flash("حساب شما در انتظار تأیید مدیر است. لطفاً بعداً تلاش کنید.", "error")
                    return redirect(url_for("login"))
                session.clear()
                session.permanent = True
                session.update(user_id=u["id"], username=u["username"], role=u["role"],
                               full_name=u["full_name"], class_name=u["class_name"] or "")
                _log(u["id"], f"login_{role}", f"ip={request.remote_addr}")
                return redirect(url_for("dashboard"))
            flash("نام کاربری یا رمز صحیح نیست.", "error")
            return redirect(url_for("login"))

    return render_template("login.html", style=_style(),
                                  site_name=_html.escape(_get_setting("school_name", "مدرسه علامه")),
                                  active_role=active_role)


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("خارج شدید.", "message")
    return redirect(url_for("login"))


@app.route("/dashboard")
@role_required("admin", "teacher", "student", "parent")
def dashboard():
    endpoints = {"owner": "admin_panel", "admin": "admin_panel",
                 "teacher": "teacher_panel", "student": "student_panel", "parent": "parent_panel"}
    if session.get("role") not in endpoints:
        return redirect(url_for("login"))
    return redirect(url_for(endpoints[session["role"]]))


@app.route("/account", methods=["GET", "POST"])
@role_required("admin", "teacher", "student", "parent")
def account():
    if request.method == "POST":
        old, new, confirm = (request.form.get("old", ""), request.form.get("new", ""),
                             request.form.get("confirm", ""))
        min_pw = _password_min(session.get("role", "student"))
        if len(new) < min_pw:
            flash(f"رمز جدید باید حداقل {min_pw} نویسه باشد.", "error")
            return redirect(url_for("account"))
        if new != confirm: flash("رمزها یکسان نیستند.", "error"); return redirect(url_for("account"))
        db = get_db()
        try:
            row = db.execute("SELECT password_hash FROM users WHERE id=?",
                             (session["user_id"],)).fetchone()
            if not row or not check_password_hash(row["password_hash"], old):
                flash("رمز فعلی صحیح نیست.", "error"); return redirect(url_for("account"))
            db.execute("UPDATE users SET password_hash=? WHERE id=?",
                       (generate_password_hash(new), session["user_id"]))
            db.commit()
        finally:
            db.close()
        flash("رمز تغییر یافت.", "success")
        return redirect(url_for("dashboard"))
    return render_template("account.html", style=_style(),
                                  site_name=_html.escape(_get_setting("school_name", "مدرسه علامه")))


@app.route("/account/panel-theme", methods=["POST"])
@role_required("admin", "teacher", "student", "parent")
def save_panel_theme():
    accent = request.form.get("panel_accent", "").strip()
    if re.fullmatch(r"#[0-9a-fA-F]{6}", accent):
        db = get_db()
        try:
            db.execute("UPDATE users SET panel_accent=? WHERE id=?",
                       (accent.lower(), session["user_id"]))
            db.commit()
        finally:
            db.close()
        flash("رنگ پنل شما ذخیره شد.", "success")
    else:
        flash("کد رنگ نامعتبر است.", "error")
    return redirect(url_for("dashboard"))


# ---------------- ADMIN PANEL ----------------
def _safe_sort(default="role"):
    sort = request.args.get("sort", default)
    allowed = {"role": "role, full_name", "name": "full_name",
               "class": "class_name, full_name", "date": "created_at DESC"}
    return sort, allowed.get(sort, allowed[default])


@app.route("/admin")
@role_required("admin")
def admin_panel():
    sort, order = _safe_sort()
    db = get_db()
    try:
        users_page = max(1, min(request.args.get("users_page", 1, type=int) or 1, 100000))
        users_per = 10
        users_total = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        users_pages = max(1, (users_total + users_per - 1) // users_per)
        users_page = min(users_page, users_pages)
        users = db.execute(
            f"SELECT * FROM users ORDER BY {order} LIMIT ? OFFSET ?",
            (users_per, (users_page - 1) * users_per)
        ).fetchall()
        posts = db.execute("""
            SELECT p.*,
                   COALESCE(NULLIF(u.full_name,''), NULLIF(p.creator_name_snap,''), 'نامشخص') AS creator_name,
                   COALESCE(NULLIF(u.role,''), NULLIF(p.creator_role_snap,'')) AS creator_role
            FROM site_posts p LEFT JOIN users u ON u.id=p.created_by
            ORDER BY p.id DESC LIMIT 30""").fetchall()
        announcements = db.execute("""
            SELECT a.*,
                   COALESCE(NULLIF(u.full_name,''), NULLIF(a.creator_name_snap,''), 'نامشخص') AS creator_name,
                   COALESCE(NULLIF(u.role,''), NULLIF(a.creator_role_snap,'')) AS creator_role
            FROM announcements a LEFT JOIN users u ON u.id=a.created_by
            ORDER BY a.is_pinned DESC, a.id DESC LIMIT 30""").fetchall()
        pending_comments = db.execute("""
            SELECT c.*, p.title AS post_title FROM comments c
            JOIN site_posts p ON p.id=c.post_id
            WHERE c.is_approved=0 ORDER BY c.id DESC LIMIT 100""").fetchall()
        approved_comments = db.execute("""
            SELECT c.*, p.title AS post_title FROM comments c
            JOIN site_posts p ON p.id=c.post_id
            WHERE c.is_approved=1 ORDER BY c.id DESC LIMIT 50""").fetchall()
        contact_messages = db.execute(
            "SELECT * FROM contact_messages ORDER BY id DESC LIMIT 50").fetchall()
        def _g(key):
            r = db.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
            return r["value"] if r else ""
        site = {k: _g(k) for k in
                ("school_name", "hero_line1", "hero_line2", "hero_line3", "hero_description")}
        appearance = {k: _g(k) for k in
                      ("style_primary", "style_accent", "style_navy", "style_gold", "site_logo")}
        contact = {k: _g(k) for k in
                   ("contact_phone", "contact_email", "contact_address", "footer_text")}
        student_code = _g("student_code"); teacher_code = _g("teacher_code"); admin_code = _g("admin_code"); parent_code = _g("parent_code")
        logs = []
        logs_page = max(1, min(request.args.get("logs_page", 1, type=int) or 1, 100000))
        logs_total = 0
        logs_pages = 1
        logs_per_page = 10
        if session["role"] == "owner":
            logs_total = db.execute("SELECT COUNT(*) FROM activity_log").fetchone()[0]
            logs_pages = max(1, (logs_total + logs_per_page - 1) // logs_per_page)
            logs_page = min(logs_page, logs_pages)
            logs = db.execute("""
                SELECT l.*, u.full_name AS actor_name, u.role AS actor_role
                FROM activity_log l LEFT JOIN users u ON u.id=l.actor_id
                ORDER BY l.id DESC LIMIT ? OFFSET ?""",
                (logs_per_page, (logs_page - 1) * logs_per_page)).fetchall()
    finally:
        db.close()
    return render_template("panel.html", style=_style(), page_title="پنل مدیریت",
        site_name=_html.escape(_get_setting("school_name", "مدرسه علامه")),
        user=session, users=users, posts=posts, announcements=announcements,
        site=site, appearance=appearance, contact=contact,
        student_code=student_code, teacher_code=teacher_code, admin_code=admin_code, parent_code=parent_code,
        logs=logs, logs_page=logs_page, logs_pages=logs_pages,
        logs_total=logs_total, logs_per_page=logs_per_page,
        users_page=users_page, users_pages=users_pages, users_total=users_total, users_per=users_per,
        comments=[], pending_comments=pending_comments,
        approved_comments=approved_comments, contact_messages=contact_messages,
        students=[], my_homework=[], my_grades=[],
        selected_class="", student_class="", sort=sort)


@app.route("/admin_panel")
def admin_panel_alias(): return redirect(url_for("admin_panel"))


@app.route("/admin/users/<int:uid>/approve", methods=["POST"])
@role_required("admin")
def admin_approve_user(uid):
    db = get_db()
    try:
        u = db.execute("SELECT role, full_name, username FROM users WHERE id=?", (uid,)).fetchone()
        if not u: abort(404)
        if u["role"] == "admin" and session["role"] != "owner":
            flash("فقط مدیر ارشد می‌تواند مدیران را تأیید کند.", "error")
            return redirect(url_for("admin_panel"))
        if u["role"] == "owner":
            flash("مدیر ارشد قابل تأیید نیست.", "error")
            return redirect(url_for("admin_panel"))
        db.execute("UPDATE users SET is_active=1 WHERE id=?", (uid,))
        db.commit()
    finally:
        db.close()
    _log(session["user_id"], f"approved_{u['role']}", u["username"])
    flash(f"حساب «{u['full_name']}» تأیید شد.", "success")
    return redirect(url_for("admin_panel"))


@app.route("/admin/users/<int:uid>/reject", methods=["POST"])
@role_required("admin")
def admin_reject_user(uid):
    db = get_db()
    try:
        u = db.execute("SELECT role, full_name, username FROM users WHERE id=?", (uid,)).fetchone()
        if not u: abort(404)
        if u["role"] == "admin" and session["role"] != "owner":
            flash("فقط مدیر ارشد می‌تواند مدیران را رد کند.", "error")
            return redirect(url_for("admin_panel"))
        if u["role"] == "owner":
            flash("مدیر ارشد قابل حذف نیست.", "error")
            return redirect(url_for("admin_panel"))
        db.execute("DELETE FROM users WHERE id=?", (uid,))
        db.commit()
    finally:
        db.close()
    _log(session["user_id"], f"rejected_{u['role']}", u["username"])
    flash(f"درخواست «{u['full_name']}» رد شد.", "success")
    return redirect(url_for("admin_panel"))


@app.route("/owner/appearance", methods=["POST"])
@owner_required
def owner_save_appearance():
    any_change = False
    for k in ("style_primary", "style_accent", "style_navy", "style_gold"):
        v = request.form.get(k, "").strip()
        if v and re.fullmatch(r"#[0-9a-fA-F]{6}", v):
            _set_setting(k, v.lower())
            any_change = True
    if request.form.get("remove_logo") == "1":
        old = _get_setting("site_logo", ""); _delete_image(old); _set_setting("site_logo", "")
        any_change = True
    new_logo = _save_image(request.files.get("site_logo"))
    if new_logo:
        old = _get_setting("site_logo", "")
        if old: _delete_image(old)
        _set_setting("site_logo", new_logo)
        any_change = True
    if any_change:
        _log(session["user_id"], "appearance_updated")
        flash("ظاهر سایت ذخیره شد.", "success")
    else:
        flash("تغییری ذخیره نشد.", "message")
    return redirect(url_for("admin_panel"))


@app.route("/owner/site", methods=["POST"])
@owner_required
def owner_save_site():
    for k in ("school_name", "hero_line1", "hero_line2", "hero_line3"):
        v = request.form.get(k, "").strip()
        if v: _set_setting(k, v[:120])
    d = request.form.get("hero_description", "").strip()
    if d: _set_setting("hero_description", d[:500])
    _log(session["user_id"], "site_updated")
    flash("اطلاعات مدرسه ذخیره شد.", "success")
    return redirect(url_for("admin_panel"))


@app.route("/owner/contact-info", methods=["POST"])
@owner_required
def owner_save_contact():
    for k in ("contact_phone", "contact_email", "contact_address", "footer_text"):
        _set_setting(k, request.form.get(k, "").strip()[:300])
    _log(session["user_id"], "contact_updated")
    flash("اطلاعات تماس ذخیره شد.", "success")
    return redirect(url_for("admin_panel"))


@app.route("/owner/toggles", methods=["POST"])
@owner_required
def owner_save_toggles():
    for k in ("public_news", "public_announcements", "public_comments", "public_contact"):
        _set_setting(k, "1" if request.form.get(k) == "1" else "0")
    _log(session["user_id"], "toggles_updated")
    flash("تنظیمات ذخیره شد.", "success")
    return redirect(url_for("admin_panel"))


def _regen_code(which):
    key = f"{which}_code"
    other = [f"{k}_code" for k in ("admin", "teacher", "student", "parent") if k != which]
    db = get_db()
    try:
        used = set()
        for ok in other:
            r = db.execute("SELECT value FROM settings WHERE key=?", (ok,)).fetchone()
            if r: used.add(r["value"])
        new = _gen_code()
        while new in used: new = _gen_code()
        db.execute("UPDATE settings SET value=? WHERE key=?", (new, key))
        db.commit()
    finally:
        db.close()
    _log(session["user_id"], f"code_regen_{which}")
    flash(f"کد جدید {which}: {new}", "success")
    return redirect(url_for("admin_panel"))


@app.route("/admin/code/regen/teacher", methods=["POST"])
@owner_required
def admin_regen_teacher_code(): return _regen_code("teacher")

@app.route("/admin/code/regen/student", methods=["POST"])
@owner_required
def admin_regen_student_code(): return _regen_code("student")

@app.route("/admin/code/regen/admin", methods=["POST"])
@owner_required
def admin_regen_admin_code(): return _regen_code("admin")

@app.route("/admin/code/regen/parent", methods=["POST"])
@owner_required
def admin_regen_parent_code(): return _regen_code("parent")


@app.route("/admin/posts", methods=["POST"])
@role_required("admin")
def admin_add_post():
    ptype = request.form.get("type", "").strip()
    if ptype not in POST_TYPES:
        flash("نوع نامعتبر.", "error"); return redirect(url_for("admin_panel"))
    if session["role"] != "owner" and ptype != "news":
        flash("مدیر عادی فقط می‌تواند خبر بسازد.", "error")
        return redirect(url_for("admin_panel"))
    title = request.form.get("title", "").strip()
    body = request.form.get("body", "").strip()
    if not title or not body or len(title) > 160 or len(body) > 5000:
        flash("اطلاعات نامعتبر.", "error"); return redirect(url_for("admin_panel"))
    image = _save_image(request.files.get("image"))
    attachment = _save_attachment(request.files.get("attachment"), "PUBLIC_FILES_FOLDER")
    db = get_db()
    try:
        db.execute("INSERT INTO site_posts(type,title,body,image,attachment,created_by,created_at,"
                   "creator_name_snap,creator_role_snap) VALUES(?,?,?,?,?,?,?,?,?)",
                   (ptype, title, body, image, attachment, session["user_id"], now_text(),
                    session.get("full_name", ""), session.get("role", "")))
        pid = db.execute("SELECT id FROM site_posts ORDER BY id DESC LIMIT 1").fetchone()["id"]
        db.commit()
    finally:
        db.close()
    _push_notification(ptype, title, body, f"/news/{pid}", target="all")
    _log(session["user_id"], "post_created", f"#{pid}")
    flash("پست منتشر شد.", "success")
    return redirect(url_for("admin_panel"))


@app.route("/admin/posts/<int:pid>/edit", methods=["POST"])
@role_required("admin")
def admin_edit_post(pid):
    db = get_db()
    try:
        row = db.execute("SELECT * FROM site_posts WHERE id=?", (pid,)).fetchone()
        if not row: abort(404)
        if session["role"] != "owner" and row["created_by"] != session["user_id"]: abort(403)
        ptype = request.form.get("type", "").strip()
        if session["role"] != "owner": ptype = "news"
        if ptype not in POST_TYPES:
            flash("نوع نامعتبر.", "error"); return redirect(url_for("admin_panel"))
        title = request.form.get("title", "").strip()
        body = request.form.get("body", "").strip()
        if not title or not body:
            flash("اطلاعات نامعتبر.", "error"); return redirect(url_for("admin_panel"))
        final_img = row["image"]
        new_img = _save_image(request.files.get("image"))
        if new_img:
            if final_img: _delete_image(final_img)
            final_img = new_img
        elif request.form.get("remove_image") == "1" and final_img:
            _delete_image(final_img); final_img = ""
        db.execute("UPDATE site_posts SET type=?, title=?, body=?, image=? WHERE id=?",
                   (ptype, title, body, final_img, pid))
        db.commit()
    finally:
        db.close()
    _log(session["user_id"], "post_edited", f"#{pid}")
    flash("تغییرات ذخیره شد.", "success")
    return redirect(url_for("admin_panel"))


@app.route("/admin/posts/<int:pid>/delete", methods=["POST"])
@role_required("admin")
def admin_delete_post(pid):
    db = get_db()
    try:
        row = db.execute("SELECT * FROM site_posts WHERE id=?", (pid,)).fetchone()
        if not row: abort(404)
        if session["role"] != "owner" and row["created_by"] != session["user_id"]: abort(403)
        db.execute("DELETE FROM site_posts WHERE id=?", (pid,))
        db.commit()
    finally:
        db.close()
    _delete_image(row["image"])
    _log(session["user_id"], "post_deleted", f"#{pid}")
    flash("پست حذف شد.", "success")
    return redirect(url_for("admin_panel"))


@app.route("/admin/announcements", methods=["POST"])
@role_required("admin")
def admin_add_announcement():
    title = request.form.get("title", "").strip()
    body = request.form.get("body", "").strip()
    if not title or not body or len(title) > 160 or len(body) > 5000:
        flash("اطلاعات نامعتبر.", "error"); return redirect(url_for("admin_panel"))
    image = _save_image(request.files.get("image"))
    attachment = _save_attachment(request.files.get("attachment"), "PUBLIC_FILES_FOLDER")
    is_pinned = 1 if request.form.get("is_pinned") == "1" else 0
    db = get_db()
    try:
        db.execute("INSERT INTO announcements(title,body,created_at,created_by,image,attachment,is_pinned,"
                   "creator_name_snap,creator_role_snap) VALUES(?,?,?,?,?,?,?,?,?)",
                   (title, body, now_text(), session["user_id"], image, attachment, is_pinned,
                    session.get("full_name", ""), session.get("role", "")))
        db.commit()
    finally:
        db.close()
    _push_notification("announcement", title, body, "/announcements", target="all")
    _log(session["user_id"], "announcement_created", title[:50])
    flash("اطلاعیه منتشر شد.", "success")
    return redirect(url_for("admin_panel"))


@app.route("/admin/announcements/<int:aid>/delete", methods=["POST"])
@role_required("admin")
def admin_delete_announcement(aid):
    db = get_db()
    try:
        row = db.execute("SELECT created_by,image FROM announcements WHERE id=?", (aid,)).fetchone()
        if not row: abort(404)
        if session["role"] != "owner" and row["created_by"] != session["user_id"]: abort(403)
        db.execute("DELETE FROM announcements WHERE id=?", (aid,))
        db.commit()
    finally:
        db.close()
    _delete_image(row["image"])
    _log(session["user_id"], "announcement_deleted", f"#{aid}")
    flash("اطلاعیه حذف شد.", "success")
    return redirect(url_for("admin_panel"))


@app.route("/admin/announcements/<int:aid>/pin", methods=["POST"])
@role_required("admin")
def admin_toggle_ann_pin(aid):
    db = get_db()
    try:
        row = db.execute("SELECT created_by FROM announcements WHERE id=?", (aid,)).fetchone()
        if not row: abort(404)
        if session["role"] != "owner" and row["created_by"] != session["user_id"]: abort(403)
        db.execute("UPDATE announcements SET is_pinned=1-is_pinned WHERE id=?", (aid,))
        db.commit()
    finally:
        db.close()
    flash("وضعیت سنجاق تغییر کرد.", "success")
    return redirect(url_for("admin_panel"))


@app.route("/admin/comments/<int:cid>/approve", methods=["POST"])
@role_required("admin")
def admin_approve_comment(cid):
    db = get_db()
    try:
        db.execute("UPDATE comments SET is_approved=1 WHERE id=?", (cid,))
        db.commit()
    finally:
        db.close()
    _log(session["user_id"], "comment_approved", f"#{cid}")
    flash("نظر تأیید شد.", "success")
    return redirect(url_for("admin_panel"))


@app.route("/admin/comments/<int:cid>/delete", methods=["POST"])
@role_required("admin")
def admin_delete_comment(cid):
    db = get_db()
    try:
        db.execute("DELETE FROM comments WHERE id=?", (cid,))
        db.commit()
    finally:
        db.close()
    _log(session["user_id"], "comment_deleted", f"#{cid}")
    flash("نظر حذف شد.", "success")
    return redirect(url_for("admin_panel"))


@app.route("/admin/messages/<int:mid>/delete", methods=["POST"])
@role_required("admin")
def admin_delete_message(mid):
    db = get_db()
    try:
        db.execute("DELETE FROM contact_messages WHERE id=?", (mid,))
        db.commit()
    finally:
        db.close()
    flash("پیام حذف شد.", "success")
    return redirect(url_for("admin_panel"))


@app.route("/admin/users", methods=["POST"])
@role_required("admin")
def admin_add_user():
    role = request.form.get("role", "")
    allowed = ("teacher", "student")
    if session["role"] == "owner": allowed = ("teacher", "student", "admin")
    if role not in allowed:
        flash("نقش مجاز نیست.", "error"); return redirect(url_for("admin_panel"))
    username = request.form.get("username", "").strip()
    full_name = request.form.get("full_name", "").strip()
    password = request.form.get("password", "")
    class_name = request.form.get("class_name", "").strip()
    min_pw = _password_min(role)
    if not re.fullmatch(r"[a-zA-Z0-9_.-]{3,40}", username) or len(password) < min_pw or len(full_name) < 3:
        flash(f"اطلاعات نامعتبر. رمز برای نقش {role} باید حداقل {min_pw} نویسه باشد.", "error")
        return redirect(url_for("admin_panel"))
    if role == "student" and class_name not in CLASSES:
        flash("کلاس دانش‌آموز الزامی است.", "error"); return redirect(url_for("admin_panel"))
    db = get_db()
    try:
        if db.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone():
            flash("نام کاربری گرفته شده.", "error"); return redirect(url_for("admin_panel"))
        db.execute("INSERT INTO users(username,password_hash,role,full_name,class_name,"
                   "is_active,created_at) VALUES(?,?,?,?,?,1,?)",
                   (username, generate_password_hash(password), role, full_name, class_name, now_text()))
        db.commit()
    finally:
        db.close()
    _log(session["user_id"], f"{role}_created_direct", username)
    flash("کاربر ساخته شد.", "success")
    return redirect(url_for("admin_panel"))


@app.route("/admin/users/<int:uid>/toggle", methods=["POST"])
@role_required("admin")
def admin_toggle_user(uid):
    if uid == session["user_id"]: abort(400)
    db = get_db()
    try:
        t = db.execute("SELECT role FROM users WHERE id=?", (uid,)).fetchone()
        if not t: abort(404)
        if t["role"] == "owner":
            flash("مدیر ارشد محافظت‌شده.", "error"); return redirect(url_for("admin_panel"))
        if session["role"] == "admin" and t["role"] == "admin":
            flash("فقط مدیر ارشد می‌تواند مدیران را مدیریت کند.", "error"); return redirect(url_for("admin_panel"))
        db.execute("UPDATE users SET is_active=1-is_active WHERE id=?", (uid,))
        db.commit()
    finally:
        db.close()
    _log(session["user_id"], "user_toggled", f"#{uid}")
    return redirect(url_for("admin_panel"))


@app.route("/admin/users/<int:uid>/delete", methods=["POST"])
@role_required("admin")
def admin_delete_user(uid):
    if uid == session["user_id"]: abort(400)
    db = get_db()
    try:
        t = db.execute("SELECT role FROM users WHERE id=?", (uid,)).fetchone()
        if not t: abort(404)
        if t["role"] == "owner":
            flash("مدیر ارشد قابل حذف نیست.", "error"); return redirect(url_for("admin_panel"))
        if session["role"] == "admin" and t["role"] == "admin":
            flash("فقط مدیر ارشد می‌تواند مدیران را حذف کند.", "error"); return redirect(url_for("admin_panel"))
        db.execute("DELETE FROM users WHERE id=?", (uid,))
        db.commit()
    finally:
        db.close()
    _log(session["user_id"], "user_deleted", f"#{uid}")
    flash("کاربر حذف شد.", "success")
    return redirect(url_for("admin_panel"))


# ---------------- TEACHER ----------------
@app.route("/teacher")
@role_required("teacher")
def teacher_panel():
    selected = session.get("selected_class", "")
    if selected not in CLASSES:
        selected = ""; session["selected_class"] = ""
    sort = request.args.get("sort", "date")
    h_ord = {"date": "id DESC", "due": "due_date DESC", "subject": "subject ASC"}.get(sort, "id DESC")
    db = get_db()
    try:
        students = []
        if selected:
            students = db.execute("SELECT id,full_name,username,is_active FROM users "
                                  "WHERE role='student' AND class_name=? AND is_active=1 ORDER BY full_name",
                                  (selected,)).fetchall()
        my_homework = db.execute(f"""
            SELECT h.*,
                   COALESCE(NULLIF(u.full_name,''), NULLIF(h.creator_name_snap,''), 'نامشخص') AS creator_name,
                   COALESCE(NULLIF(u.role,''), NULLIF(h.creator_role_snap,'')) AS creator_role
            FROM homework h LEFT JOIN users u ON u.id=h.created_by
            WHERE h.created_by=? ORDER BY h.{h_ord} LIMIT 30""",
            (session["user_id"],)).fetchall()
        announcements = db.execute("""
            SELECT a.*,
                   COALESCE(NULLIF(u.full_name,''), NULLIF(a.creator_name_snap,''), 'نامشخص') AS creator_name,
                   COALESCE(NULLIF(u.role,''), NULLIF(a.creator_role_snap,'')) AS creator_role
            FROM announcements a LEFT JOIN users u ON u.id=a.created_by
            ORDER BY a.is_pinned DESC, a.id DESC LIMIT 15""").fetchall()
    finally:
        db.close()
    return render_template("panel.html", style=_style(), page_title="پنل معلم",
        site_name=_html.escape(_get_setting("school_name", "مدرسه علامه")),
        user=session, students=students, my_homework=my_homework,
        announcements=announcements, posts=[], my_grades=[], users=[],
        site={}, appearance={}, contact={}, student_code="", teacher_code="",
        admin_code="", parent_code="", logs=[], comments=[], pending_comments=[],
        approved_comments=[], contact_messages=[],
        users_page=1, users_pages=1, users_total=0, users_per=10,
        logs_page=1, logs_pages=1, logs_total=0, logs_per_page=10,
        selected_class=selected, student_class="", sort=sort)


@app.route("/teacher_panel")
def teacher_panel_alias(): return redirect(url_for("teacher_panel"))


@app.route("/teacher/select-class", methods=["POST"])
@role_required("teacher")
def teacher_select_class():
    cls = request.form.get("class_name", "")
    if cls in CLASSES or cls == "":
        session["selected_class"] = cls
        if cls: flash(f"کلاس فعال: {cls}", "success")
    return redirect(url_for("teacher_panel"))


@app.route("/teacher/homework", methods=["POST"])
@role_required("teacher")
def teacher_add_homework():
    cls = session.get("selected_class", "")
    if not cls or cls not in CLASSES:
        flash("ابتدا کلاس را انتخاب کنید.", "error"); return redirect(url_for("teacher_panel"))
    title = request.form.get("title", "").strip()
    body = request.form.get("body", "").strip()
    if not title or not body or len(title) > 160 or len(body) > 5000:
        flash("اطلاعات نامعتبر.", "error"); return redirect(url_for("teacher_panel"))
    due = request.form.get("due_date", "").strip() or None
    if due:
        try: datetime.strptime(due, "%Y-%m-%d")
        except ValueError: flash("تاریخ نامعتبر.", "error"); return redirect(url_for("teacher_panel"))
    image = _save_image(request.files.get("image"))
    attachment = _save_attachment(request.files.get("attachment"))
    db = get_db()
    try:
        db.execute("INSERT INTO homework(title,body,due_date,class_name,subject,image,attachment,"
                   "created_by,created_at,creator_name_snap,creator_role_snap) "
                   "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                   (title, body, due, cls, request.form.get("subject", "").strip(),
                    image, attachment, session["user_id"], now_text(),
                    session.get("full_name", ""), session.get("role", "")))
        db.commit()
    finally:
        db.close()
    _log(session["user_id"], "homework_created", title[:50])
    flash("تکلیف ثبت شد.", "success")
    return redirect(url_for("teacher_panel"))


@app.route("/teacher/homework/<int:hid>/delete", methods=["POST"])
@role_required("teacher")
def teacher_delete_homework(hid):
    db = get_db()
    try:
        row = db.execute("SELECT created_by,image FROM homework WHERE id=?", (hid,)).fetchone()
        if not row or row["created_by"] != session["user_id"]: abort(403)
        db.execute("DELETE FROM homework WHERE id=?", (hid,))
        db.commit()
    finally:
        db.close()
    _delete_image(row["image"])
    flash("تکلیف حذف شد.", "success")
    return redirect(url_for("teacher_panel"))


@app.route("/teacher/grades", methods=["POST"])
@role_required("teacher")
def teacher_add_grade():
    cls = session.get("selected_class", "")
    if not cls or cls not in CLASSES:
        flash("ابتدا کلاس را انتخاب کنید.", "error"); return redirect(url_for("teacher_panel"))
    student_id = request.form.get("student_id", type=int)
    subject = request.form.get("subject", "").strip()
    score = request.form.get("score", type=float)
    term = request.form.get("term", "").strip()
    note = request.form.get("note", "").strip()
    if (not student_id or not subject or len(subject) > 80 or len(note) > 500
            or len(term) > 40 or score is None or not 0 <= score <= 20):
        flash("اطلاعات نمره نامعتبر.", "error"); return redirect(url_for("teacher_panel"))
    db = get_db()
    try:
        ok = db.execute("SELECT 1 FROM users WHERE id=? AND role='student' AND class_name=? AND is_active=1",
                        (student_id, cls)).fetchone()
        if not ok:
            flash("دانش‌آموز در کلاس انتخابی نیست.", "error"); return redirect(url_for("teacher_panel"))
        db.execute("INSERT INTO grades(student_id,subject,score,term,note,"
                   "created_by,created_at) VALUES(?,?,?,?,?,?,?)",
                   (student_id, subject, score, term, note, session["user_id"], now_text()))
        db.commit()
    finally:
        db.close()
    _push_notification("grade",
                       f"نمره جدید در {subject}",
                       f"نمره: {score} از ۲۰ — نوبت: {term or '—'}",
                       "/student", target=f"user:{student_id}")
    _log(session["user_id"], "grade_created", f"student:{student_id}")
    flash("نمره ثبت شد.", "success")
    return redirect(url_for("teacher_panel"))


# ---------------- STUDENT ----------------
@app.route("/student")
@role_required("student")
def student_panel():
    sort = request.args.get("sort", "date")
    g_ord = {"date": "id DESC", "subject": "subject ASC", "score": "score DESC"}.get(sort, "id DESC")
    h_ord = {"date": "id DESC", "due": "due_date DESC", "subject": "subject ASC"}.get(sort, "id DESC")
    db = get_db()
    try:
        me = db.execute("SELECT class_name FROM users WHERE id=?", (session["user_id"],)).fetchone()
        my_class = (me["class_name"] or "") if me else ""
        my_grades = db.execute(f"SELECT subject, score, term, note, created_at FROM grades "
                               f"WHERE student_id=? ORDER BY {g_ord}",
                               (session["user_id"],)).fetchall()
        my_homework = db.execute(f"""
            SELECT h.*,
                   COALESCE(NULLIF(u.full_name,''), NULLIF(h.creator_name_snap,''), 'نامشخص') AS creator_name,
                   COALESCE(NULLIF(u.role,''), NULLIF(h.creator_role_snap,'')) AS creator_role
            FROM homework h LEFT JOIN users u ON u.id=h.created_by
            WHERE h.class_name=? OR h.class_name=''
            ORDER BY h.{h_ord}
            LIMIT 30""", (my_class,)).fetchall()
        announcements = db.execute("""
            SELECT a.*,
                   COALESCE(NULLIF(u.full_name,''), NULLIF(a.creator_name_snap,''), 'نامشخص') AS creator_name,
                   COALESCE(NULLIF(u.role,''), NULLIF(a.creator_role_snap,'')) AS creator_role
            FROM announcements a LEFT JOIN users u ON u.id=a.created_by
            ORDER BY a.is_pinned DESC, a.id DESC LIMIT 20""").fetchall()
        posts = db.execute("""
            SELECT p.*,
                   COALESCE(NULLIF(u.full_name,''), NULLIF(p.creator_name_snap,''), 'نامشخص') AS creator_name,
                   COALESCE(NULLIF(u.role,''), NULLIF(p.creator_role_snap,'')) AS creator_role
            FROM site_posts p LEFT JOIN users u ON u.id=p.created_by
            ORDER BY p.id DESC LIMIT 10""").fetchall()
    finally:
        db.close()
    return render_template("panel.html", style=_style(), page_title="پنل دانش‌آموز",
        site_name=_html.escape(_get_setting("school_name", "مدرسه علامه")),
        user=session, my_grades=my_grades, my_homework=my_homework,
        announcements=announcements, posts=posts, students=[], users=[],
        site={}, appearance={}, contact={}, student_code="", teacher_code="",
        admin_code="", parent_code="", logs=[], comments=[], pending_comments=[],
        approved_comments=[], contact_messages=[],
        users_page=1, users_pages=1, users_total=0, users_per=10,
        logs_page=1, logs_pages=1, logs_total=0, logs_per_page=10,
        selected_class="", student_class=my_class, sort=sort)


@app.route("/student_panel")
def student_panel_alias(): return redirect(url_for("student_panel"))


# ---------------- ACADEMIC / PARENT PORTALS ----------------
def _owned_students(db, parent_id):
    return db.execute("""SELECT u.id,u.full_name,u.username,u.class_name FROM users u
        JOIN parent_student ps ON ps.student_id=u.id WHERE ps.parent_id=? AND u.role='student'""",
        (parent_id,)).fetchall()


@app.route("/academics")
@role_required("admin", "teacher", "student", "parent")
def academics_portal():
    db = get_db()
    students_for_results = []
    try:
        role = session["role"]
        if role == "teacher":
            students_for_results = db.execute("SELECT id,full_name,class_name FROM users WHERE role='student' AND is_active=1 ORDER BY class_name,full_name").fetchall()
        if role == "student":
            me = db.execute("SELECT class_name FROM users WHERE id=?", (session["user_id"],)).fetchone()
            cls = (me["class_name"] or "") if me else ""
            exams = db.execute("SELECT * FROM exam_schedule WHERE class_name IN (?, '') ORDER BY exam_date,exam_time", (cls,)).fetchall()
            results = db.execute("SELECT r.*,s.full_name AS student_name FROM exam_results r JOIN users s ON s.id=r.student_id WHERE r.student_id=? ORDER BY r.created_at DESC", (session["user_id"],)).fetchall()
        elif role == "parent":
            kids = _owned_students(db, session["user_id"])
            ids = [x["id"] for x in kids]
            exams = []; results = []
            if ids:
                qs = ",".join("?" for _ in ids)
                exams = db.execute(f"SELECT * FROM exam_schedule WHERE class_name IN ({qs},'') ORDER BY exam_date,exam_time", [x["class_name"] for x in kids]).fetchall()
                results = db.execute(f"SELECT r.*,s.full_name AS student_name FROM exam_results r JOIN users s ON s.id=r.student_id WHERE r.student_id IN ({qs}) ORDER BY r.created_at DESC", ids).fetchall()
        else:
            exams = db.execute("SELECT * FROM exam_schedule ORDER BY exam_date DESC,id DESC LIMIT 100").fetchall()
            results = db.execute("""SELECT r.*,s.full_name AS student_name FROM exam_results r
                JOIN users s ON s.id=r.student_id ORDER BY r.created_at DESC LIMIT 100""").fetchall()
    finally:
        db.close()
    return render_template("academic_portal.html", style=_style(), role=role, exams=exams, results=results, students=students_for_results)


@app.route("/exams/schedule", methods=["POST"])
@role_required("admin", "teacher")
def add_exam_schedule():
    title = request.form.get("title", "").strip()[:160]
    subject = request.form.get("subject", "").strip()[:80]
    cls = request.form.get("class_name", "").strip()
    date = request.form.get("exam_date", "").strip()
    time = request.form.get("exam_time", "").strip()[:20]
    details = request.form.get("details", "").strip()[:3000]
    if not title or not subject or not date or (cls and cls not in CLASSES):
        flash("عنوان، درس، تاریخ و کلاس معتبر لازم است.", "error"); return redirect(url_for("academics_portal"))
    file_name = _save_attachment(request.files.get("attachment"))
    db = get_db()
    try:
        db.execute("""INSERT INTO exam_schedule(title,class_name,subject,exam_date,exam_time,details,file_name,created_by,created_at)
        VALUES(?,?,?,?,?,?,?,?,?)""", (title, cls, subject, date, time, details, file_name, session["user_id"], now_text()))
        db.commit()
    finally:
        db.close()
    _log(session["user_id"], "exam_schedule_created", title)
    flash("برنامه امتحان ثبت شد.", "success")
    return redirect(url_for("academics_portal"))


@app.route("/exams/results", methods=["POST"])
@role_required("teacher")
def add_exam_result():
    student_id = request.form.get("student_id", type=int)
    exam_id = request.form.get("exam_id", type=int)
    subject = request.form.get("subject", "").strip()[:80]
    score = request.form.get("score", type=float)
    note = request.form.get("note", "").strip()[:1000]
    if not student_id or not subject or score is None or not 0 <= score <= 20:
        flash("اطلاعات نتیجه معتبر نیست.", "error"); return redirect(url_for("academics_portal"))
    db = get_db()
    try:
        student = db.execute("SELECT id,class_name FROM users WHERE id=? AND role='student' AND is_active=1", (student_id,)).fetchone()
        if not student: abort(400)
        if exam_id and not db.execute("SELECT 1 FROM exam_schedule WHERE id=? AND (class_name='' OR class_name=?)", (exam_id, student["class_name"] or "")).fetchone():
            abort(400)
        file_name = _save_attachment(request.files.get("attachment"))
        db.execute("""INSERT INTO exam_results(exam_id,student_id,subject,score,note,file_name,created_by,created_at)
            VALUES(?,?,?,?,?,?,?,?)""", (exam_id or None, student_id, subject, score, note, file_name, session["user_id"], now_text()))
        db.commit()
    finally:
        db.close()
    _log(session["user_id"], "exam_result_created", f"student:{student_id}")
    flash("نتیجه امتحان ثبت شد.", "success")
    return redirect(url_for("academics_portal"))


@app.route("/homework/submit", methods=["POST"])
@role_required("student")
def submit_homework():
    homework_id = request.form.get("homework_id", type=int)
    body = request.form.get("body", "").strip()[:10000]
    upload = request.files.get("attachment")
    file_name = _save_attachment(upload)
    if not homework_id or (not body and not file_name):
        flash("متن پاسخ یا یک فایل پیوست لازم است.", "error"); return redirect(url_for("student_panel"))
    db = get_db()
    try:
        student = db.execute("SELECT class_name FROM users WHERE id=?", (session["user_id"],)).fetchone()
        hw = db.execute("SELECT id,class_name FROM homework WHERE id=?", (homework_id,)).fetchone()
        if not hw or (hw["class_name"] and hw["class_name"] != (student["class_name"] or "")):
            abort(404)
        db.execute("""INSERT INTO homework_submissions(homework_id,student_id,body,file_name,submitted_at)
            VALUES(?,?,?,?,?)""", (homework_id, session["user_id"], body, file_name, now_text()))
        db.commit()
    finally:
        db.close()
    flash("تکلیف شما ارسال شد.", "success")
    return redirect(url_for("student_panel"))


@app.route("/homework/submissions")
@role_required("teacher", "admin")
def homework_submissions():
    page = max(1, min(request.args.get("page", 1, type=int) or 1, 100000))
    per = 10
    db = get_db()
    try:
        if session["role"] == "teacher":
            cond = "WHERE h.created_by=?"
            args = (session["user_id"],)
        else:
            cond = ""
            args = ()
        total = db.execute(
            f"SELECT COUNT(*) FROM homework_submissions s "
            f"JOIN homework h ON h.id=s.homework_id {cond}", args).fetchone()[0]
        pages = max(1, (total + per - 1) // per)
        page = min(page, pages)
        rows = db.execute(
            f"""SELECT s.*,u.full_name AS student_name,h.title AS homework_title
                FROM homework_submissions s JOIN users u ON u.id=s.student_id
                JOIN homework h ON h.id=s.homework_id {cond}
                ORDER BY s.submitted_at DESC LIMIT ? OFFSET ?""",
            args + (per, (page - 1) * per)).fetchall()
    finally:
        db.close()
    return render_template("submissions.html", style=_style(), rows=rows,
                           page=page, pages=pages, total=total,
                           site_name=_html.escape(_get_setting("school_name", "مدرسه علامه")))


@app.route("/parent")
@role_required("parent")
def parent_panel():
    db = get_db()
    try:
        kids = _owned_students(db, session["user_id"])
        ids = [x["id"] for x in kids]
        fees = []; grades = []; exams = []; teachers = []
        if ids:
            qs = ",".join("?" for _ in ids)
            fees = db.execute(f"SELECT f.*,u.full_name AS student_name FROM fee_payments f JOIN users u ON u.id=f.student_id WHERE f.student_id IN ({qs}) ORDER BY f.due_date DESC", ids).fetchall()
            grades = db.execute(f"SELECT g.*,u.full_name AS student_name FROM grades g JOIN users u ON u.id=g.student_id WHERE g.student_id IN ({qs}) ORDER BY g.created_at DESC LIMIT 100", ids).fetchall()
            teachers = db.execute("SELECT id,full_name,class_name FROM users WHERE role='teacher' AND is_active=1 ORDER BY full_name").fetchall()
        messages = db.execute("""SELECT m.*,t.full_name AS teacher_name,s.full_name AS student_name FROM parent_messages m
            JOIN users t ON t.id=m.teacher_id JOIN users s ON s.id=m.student_id
            WHERE m.parent_id=? ORDER BY m.created_at DESC LIMIT 100""", (session["user_id"],)).fetchall()
    finally:
        db.close()
    return render_template("parent.html", style=_style(), kids=kids, fees=fees, grades=grades, teachers=teachers, messages=messages,
                           site_name=_html.escape(_get_setting("school_name", "مدرسه علامه")))


@app.route("/parent/message", methods=["POST"])
@role_required("parent")
def parent_send_message():
    student_id = request.form.get("student_id", type=int)
    teacher_id = request.form.get("teacher_id", type=int)
    body = request.form.get("body", "").strip()[:3000]
    db = get_db()
    try:
        linked = db.execute("SELECT 1 FROM parent_student WHERE parent_id=? AND student_id=?", (session["user_id"], student_id)).fetchone()
        teacher = db.execute("SELECT id FROM users WHERE id=? AND role='teacher' AND is_active=1", (teacher_id,)).fetchone()
        if not linked or not teacher or not body:
            flash("اطلاعات پیام معتبر نیست.", "error"); return redirect(url_for("parent_panel"))
        db.execute("INSERT INTO parent_messages(parent_id,teacher_id,student_id,body,sender_role,created_at) VALUES(?,?,?,?,?,?)",
                   (session["user_id"], teacher_id, student_id, body, "parent", now_text()))
        db.commit()
    finally:
        db.close()
    flash("پیام برای معلم ثبت شد.", "success")
    return redirect(url_for("parent_panel"))


@app.route("/parent/messages")
@role_required("teacher")
def teacher_parent_messages():
    db = get_db()
    try:
        rows = db.execute("""SELECT m.*,p.full_name AS parent_name,s.full_name AS student_name FROM parent_messages m
            JOIN users p ON p.id=m.parent_id JOIN users s ON s.id=m.student_id
            WHERE m.teacher_id=? ORDER BY m.created_at DESC LIMIT 100""", (session["user_id"],)).fetchall()
    finally:
        db.close()
    return render_template("parent_messages.html", style=_style(), rows=rows,
                           site_name=_html.escape(_get_setting("school_name", "مدرسه علامه")))


@app.route("/teacher/parent-message/<int:message_id>/reply", methods=["POST"])
@role_required("teacher")
def teacher_reply_parent(message_id):
    body = request.form.get("body", "").strip()[:3000]
    if not body:
        flash("متن پاسخ را وارد کنید.", "error")
        return redirect(url_for("teacher_parent_messages"))
    db = get_db()
    try:
        original = db.execute("SELECT parent_id,student_id FROM parent_messages WHERE id=? AND teacher_id=?",
                              (message_id, session["user_id"])).fetchone()
        if not original: abort(404)
        db.execute("INSERT INTO parent_messages(parent_id,teacher_id,student_id,body,sender_role,created_at) VALUES(?,?,?,?,?,?)",
                   (original["parent_id"], session["user_id"], original["student_id"], body, "teacher", now_text()))
        db.commit()
    finally:
        db.close()
    flash("پاسخ برای والد ثبت شد.", "success")
    return redirect(url_for("teacher_parent_messages"))


@app.route("/admin/fees", methods=["GET", "POST"])
@role_required("admin")
def manage_fees():
    db = get_db()
    try:
        if request.method == "POST":
            student_id = request.form.get("student_id", type=int)
            title = request.form.get("title", "").strip()[:160]
            amount = request.form.get("amount", type=int)
            paid = request.form.get("paid_amount", default=0, type=int)
            due = request.form.get("due_date", "").strip()
            note = request.form.get("note", "").strip()[:1000]
            student = db.execute("SELECT id FROM users WHERE id=? AND role='student'", (student_id,)).fetchone()
            if not student or not title or amount is None or amount < 0 or paid is None or paid < 0 or paid > amount:
                flash("اطلاعات شهریه معتبر نیست.", "error"); return redirect(url_for("manage_fees"))
            status = "paid" if paid >= amount else ("partial" if paid > 0 else "unpaid")
            db.execute("""INSERT INTO fee_payments(student_id,title,amount,due_date,paid_amount,status,note,created_by,created_at)
                VALUES(?,?,?,?,?,?,?,?,?)""", (student_id, title, amount, due, paid, status, note, session["user_id"], now_text()))
            db.commit()
            flash("وضعیت پرداخت در دیتابیس ذخیره شد.", "success")
            return redirect(url_for("manage_fees"))
        students = db.execute("SELECT id,full_name,class_name FROM users WHERE role='student' AND is_active=1 ORDER BY class_name,full_name").fetchall()
        fees = db.execute("""SELECT f.*,u.full_name AS student_name FROM fee_payments f JOIN users u ON u.id=f.student_id ORDER BY f.id DESC LIMIT 200""").fetchall()
    finally:
        db.close()
    return render_template("fees.html", style=_style(), students=students, fees=fees,
                           site_name=_html.escape(_get_setting("school_name", "مدرسه علامه")))


@app.route("/reports/<int:student_id>")
@role_required("admin")
def report_card(student_id):
    db = get_db()
    try:
        student = db.execute("SELECT id,full_name,username,class_name FROM users WHERE id=? AND role='student'", (student_id,)).fetchone()
        if not student: abort(404)
        grades = db.execute("SELECT subject,score,term,note,created_at FROM grades WHERE student_id=? ORDER BY term,subject", (student_id,)).fetchall()
    finally:
        db.close()
    return render_template("report_card.html", style=_style(), student=student, grades=grades,
                           site_name=_html.escape(_get_setting("school_name", "مدرسه علامه")))


@app.route("/attachments/<path:filename>")
def protected_attachment(filename):
    if not re.fullmatch(r"[a-f0-9]{40}\.[a-z0-9]{2,5}", filename):
        abort(404)

    # فایل‌های عمومی سایت/اطلاعیه: هر بازدیدکننده‌ای می‌تواند
    db = get_db()
    try:
        pub = db.execute(
            "SELECT 1 FROM site_posts WHERE attachment=? "
            "UNION SELECT 1 FROM announcements WHERE attachment=?",
            (filename, filename)
        ).fetchone()
        if pub:
            return send_from_directory(app.config["PRIVATE_UPLOAD_FOLDER"], filename)
    finally:
        db.close()

    if not session.get("user_id"):
        abort(401)
    role = session["role"]; user_id = session["user_id"]
    db = get_db()
    try:
        if role in ("owner", "admin"):
            pass
        elif role == "teacher":
            ok = db.execute("""
                SELECT 1 FROM exam_schedule WHERE file_name=?
                UNION SELECT 1 FROM exam_results WHERE file_name=? AND created_by=?
                UNION SELECT 1 FROM homework_submissions s
                    JOIN homework h ON h.id=s.homework_id
                    WHERE s.file_name=? AND h.created_by=?
                UNION SELECT 1 FROM homework WHERE attachment=? AND created_by=?
            """, (filename, filename, user_id, filename, user_id, filename, user_id)).fetchone()
            if not ok: abort(403)
        elif role == "student":
            student = db.execute("SELECT class_name FROM users WHERE id=?", (user_id,)).fetchone()
            cls = (student["class_name"] or "") if student else ""
            ok = db.execute("""
                SELECT 1 FROM homework_submissions WHERE file_name=? AND student_id=?
                UNION SELECT 1 FROM exam_results WHERE file_name=? AND student_id=?
                UNION SELECT 1 FROM exam_schedule WHERE file_name=? AND (class_name='' OR class_name=?)
                UNION SELECT 1 FROM homework WHERE attachment=? AND (class_name='' OR class_name=?)
            """, (filename, user_id, filename, user_id, filename, cls, filename, cls)).fetchone()
            if not ok: abort(403)
        elif role == "parent":
            ok = db.execute("""
                SELECT 1 FROM homework_submissions s JOIN parent_student p ON p.student_id=s.student_id
                    WHERE s.file_name=? AND p.parent_id=?
                UNION SELECT 1 FROM exam_results r JOIN parent_student p ON p.student_id=r.student_id
                    WHERE r.file_name=? AND p.parent_id=?
                UNION SELECT 1 FROM exam_schedule e
                    JOIN parent_student p ON 1=1 JOIN users st ON st.id=p.student_id
                    WHERE e.file_name=? AND p.parent_id=? AND (e.class_name='' OR e.class_name=st.class_name)
                UNION SELECT 1 FROM homework h
                    JOIN parent_student p ON 1=1 JOIN users st ON st.id=p.student_id
                    WHERE h.attachment=? AND p.parent_id=? AND (h.class_name='' OR h.class_name=st.class_name)
            """, (filename, user_id, filename, user_id, filename, user_id, filename, user_id)).fetchone()
            if not ok: abort(403)
        else:
            abort(403)
    finally:
        db.close()
    return send_from_directory(app.config["PRIVATE_UPLOAD_FOLDER"], filename, as_attachment=True)


# ---------------- MAIN ----------------
if __name__ == "__main__":
    debug_mode = os.environ.get("FLASK_DEBUG") == "1"
    app.run(debug=debug_mode, host="127.0.0.1", port=5000)