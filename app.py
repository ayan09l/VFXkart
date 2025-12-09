# -*- coding: utf-8 -*-
"""
VFXKart — full app (products visible immediately)
- Users (password + OTP), Sellers (password + OTP)
- Products: multi-image uploads + thumbnails (Pillow)
- Shop: search, seller filter, price, sort, pagination
- Cart + Checkout + Orders (simulated paid)
- Admin (simple): sellers list + CSV export
- SEO: robots.txt + sitemap.xml
- Deploy-friendly: DB & uploads paths via env (Render/Cloud)
"""
import os, re, json, csv, uuid, random, smtplib
from math import ceil
from datetime import datetime, timedelta
from io import BytesIO, StringIO
from email.message import EmailMessage

from PIL import Image

from flask import (
    Flask, render_template, request, redirect, url_for, flash,
    session, Response, abort, send_from_directory, make_response
)
from werkzeug.utils import secure_filename, safe_join
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, login_user, logout_user, current_user, UserMixin,
    login_required as login_required_user
)
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

# ---------- Paths / config ----------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATE_DIR = os.path.join(BASE_DIR, "templates")
STATIC_DIR = os.path.join(BASE_DIR, "static")
DATA_DIR = os.path.join(BASE_DIR, "data")
JSON_SELLERS = os.path.join(DATA_DIR, "sellers.json")

# Deploy tweak: allow overriding DB & uploads path via env (for Render/Cloud)
DB_PATH = os.environ.get("VFXKART_DB", os.path.join(BASE_DIR, "app.db"))
UPLOAD_FOLDER = os.environ.get("VFXKART_UPLOADS", os.path.join(BASE_DIR, "uploads"))
THUMB_SUFFIX = "thumb"

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(os.path.join(STATIC_DIR, "css"), exist_ok=True)
os.makedirs(os.path.join(STATIC_DIR, "js"), exist_ok=True)

if not os.path.exists(JSON_SELLERS):
    with open(JSON_SELLERS, "w", encoding="utf-8") as f:
        json.dump([], f, ensure_ascii=False, indent=2)

app = Flask(__name__, template_folder=TEMPLATE_DIR, static_folder=STATIC_DIR)
app.secret_key = os.environ.get("VFXKART_SECRET", "dev-secret-key")
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{DB_PATH}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "webp"}
MAX_CONTENT_BYTES = 3 * 1024 * 1024  # 3MB

# Email (OTP). If not set, OTP prints in console for dev.
SMTP_HOST = os.environ.get("VFXKART_SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("VFXKART_SMTP_PORT", "587"))
SMTP_USER = os.environ.get("VFXKART_SMTP_USER", "")
SMTP_PASS = os.environ.get("VFXKART_SMTP_PASS", "")
SMTP_FROM = os.environ.get("VFXKART_SMTP_FROM", "no-reply@vfxkart.local")
OTP_TTL_MINUTES = 5

db = SQLAlchemy(app)

# ---------- Models ----------
class Seller(db.Model):
    __tablename__ = "seller"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200))
    brand = db.Column(db.String(200))
    email = db.Column(db.String(200))
    phone = db.Column(db.String(100))
    note = db.Column(db.Text)
    approved = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class SellerUser(db.Model):
    __tablename__ = "seller_user"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(200), unique=True, nullable=False)
    password_hash = db.Column(db.String(300), nullable=False)
    seller_profile_id = db.Column(db.Integer, db.ForeignKey('seller.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    def check_password(self, raw): return check_password_hash(self.password_hash, raw)

class User(db.Model, UserMixin):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(200), unique=True, nullable=False)
    password_hash = db.Column(db.String(300), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    def set_password(self, raw): self.password_hash = generate_password_hash(raw)
    def check_password(self, raw): return check_password_hash(self.password_hash, raw)

class Product(db.Model):
    __tablename__ = "product"
    id = db.Column(db.Integer, primary_key=True)
    seller_id = db.Column(db.Integer, db.ForeignKey('seller_user.id'), nullable=False)
    title = db.Column(db.String(250), nullable=False)
    price = db.Column(db.String(80), nullable=True)
    description = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class ProductImage(db.Model):
    __tablename__ = "product_image"
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    filename = db.Column(db.String(300), nullable=False)
    thumb = db.Column(db.String(300), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Order(db.Model):
    __tablename__ = "order"
    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    buyer_name = db.Column(db.String(200))
    email = db.Column(db.String(200))
    phone = db.Column(db.String(50))
    address = db.Column(db.Text)
    city = db.Column(db.String(120))
    pincode = db.Column(db.String(20))
    total_amount = db.Column(db.Float, default=0.0)
    status = db.Column(db.String(40), default="paid")

class OrderItem(db.Model):
    __tablename__ = "order_item"
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    title = db.Column(db.String(250))
    price_each = db.Column(db.Float, default=0.0)
    qty = db.Column(db.Integer, default=1)

class LoginCode(db.Model):  # seller OTP
    __tablename__ = "login_code"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('seller_user.id'), nullable=False)
    code = db.Column(db.String(6), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False)

class PublicLoginCode(db.Model):  # user OTP
    __tablename__ = "public_login_code"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    code = db.Column(db.String(6), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False)

# ---------- Admin basics ----------
ADMIN_USER = os.environ.get("VFXKART_ADMIN_USER", "admin")
ADMIN_PASS = os.environ.get("VFXKART_ADMIN_PASS", "changeme")
ADMIN_PASS_HASH = os.environ.get("VFXKART_ADMIN_PASS_HASH", None)

def check_admin_password(password: str) -> bool:
    if ADMIN_PASS_HASH: return check_password_hash(ADMIN_PASS_HASH, password)
    return password == ADMIN_PASS

def admin_login_required(fn):
    from functools import wraps
    @wraps(fn)
    def wrapper(*a, **kw):
        if not session.get("admin_logged_in"):
            return redirect(url_for("admin_login", next=request.path))
        return fn(*a, **kw)
    return wrapper

def seller_login_required(fn):
    from functools import wraps
    @wraps(fn)
    def wrapper(*a, **kw):
        if not session.get("seller_id"):
            return redirect(url_for("seller_login", next=request.path))
        return fn(*a, **kw)
    return wrapper

# ---------- Login manager ----------
login_manager = LoginManager(app)
login_manager.login_view = "auth_login"
login_manager.login_message_category = "error"

@login_manager.user_loader
def load_user(user_id):
    try:
        return db.session.get(User, int(user_id))
    except Exception:
        return None

def _token_serializer():
    secret = app.secret_key or "dev-secret-key"
    return URLSafeTimedSerializer(secret_key=secret, salt="vfxkart-reset")

# ---------- DB init ----------
def import_json_to_db():
    db.create_all()
    if Seller.query.count() == 0:
        try:
            with open(JSON_SELLERS, "r", encoding="utf-8") as f:
                items = json.load(f)
        except Exception:
            items = []
        for it in items:
            db.session.add(Seller(
                name=it.get("name",""),
                brand=it.get("brand",""),
                email=it.get("email",""),
                phone=it.get("phone",""),
                note=it.get("note",""),
                approved=it.get("approved", False)
            ))
        db.session.commit()

with app.app_context():
    import_json_to_db()

# ---------- Helpers ----------
def allowed_file(filename: str) -> bool:
    if not filename: return False
    ext = filename.rsplit(".", 1)[-1].lower()
    return ext in ALLOWED_EXTENSIONS

def make_unique_filename(original: str) -> str:
    ext = original.rsplit(".", 1)[-1].lower() if "." in original else "jpg"
    return f"{uuid.uuid4().hex}.{ext}"

def create_thumbnail(in_bytes: bytes, dest_path: str, size=(560, 360)):
    try:
        img = Image.open(BytesIO(in_bytes)).convert("RGB")
        img.thumbnail(size, Image.LANCZOS)
        img.save(dest_path, format="JPEG", quality=82)
        return True
    except Exception:
        return False

def _parse_price_to_number(price_str):
    if not price_str: return None
    m = re.search(r"([0-9]+(?:[.,][0-9]+)?)", str(price_str))
    if not m: return None
    num = m.group(1).replace(",", "")
    try: return float(num)
    except Exception:
        try: return float(num.replace(",", ""))
        except Exception: return None

def _price_to_float(price_str):
    n = _parse_price_to_number(price_str)
    return float(n) if n is not None else 0.0

def get_by_id(model, ident):
    return db.session.get(model, ident)

def _gen_otp(): return f"{random.randint(0, 999999):06d}"

def _send_otp_email(to_email: str, code: str):
    subject = "Your VFXKart login code"
    body = f"Your one-time code is: {code}\nThis code expires in {OTP_TTL_MINUTES} minutes."
    if SMTP_HOST and SMTP_USER and SMTP_PASS and SMTP_FROM:
        try:
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as s:
                s.starttls(); s.login(SMTP_USER, SMTP_PASS)
                msg = EmailMessage(); msg["Subject"]=subject; msg["From"]=SMTP_FROM; msg["To"]=to_email
                msg.set_content(body); s.send_message(msg)
            return True
        except Exception as e:
            print("[OTP EMAIL ERROR]", e); return False
    else:
        print(f"[DEV OTP] Send to {to_email}: {body}"); return True

# ---------- Context: cart badge ----------
@app.context_processor
def inject_cart_badge():
    cart = session.get("cart", {})
    count = sum(int(v.get("qty", 1)) for v in cart.values())
    return {"cart_count": count}

# ---------- Static + uploads + favicon ----------
@app.route("/uploads/<path:filename>")
def uploaded_file(filename):
    # safe_join returns a safe path when called with app.root_path etc; but we only need to ensure file exists
    path = os.path.join(UPLOAD_FOLDER, filename)
    if not path or not os.path.exists(path): abort(404)
    return send_from_directory(UPLOAD_FOLDER, filename)

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'),
                               'favicon.ico', mimetype='image/vnd.microsoft.icon')

# ---------- Convenience redirect for /seller ----------
@app.route("/seller")
def seller_root():
    if session.get("seller_id"):
        return redirect(url_for("seller_dashboard"))
    return redirect(url_for("seller_login"))

# ---------- Pages ----------
@app.route("/")
def index():
    return render_template("index.html", user=current_user if current_user.is_authenticated else None)

# ---------- Shop ----------
@app.route("/shop")
def shop():
    q = request.args.get("q", "").strip()
    seller_filter = request.args.get("seller", "").strip()
    min_price_raw = request.args.get("min_price", "").strip()
    max_price_raw = request.args.get("max_price", "").strip()
    sort = request.args.get("sort", "newest")
    try: page = max(int(request.args.get("page", 1)), 1)
    except Exception: page = 1
    try: per_page = max(int(request.args.get("per_page", 12)), 1)
    except Exception: per_page = 12

    min_price = None; max_price = None
    try:
        if min_price_raw != "": min_price = float(min_price_raw)
    except Exception: pass
    try:
        if max_price_raw != "": max_price = float(max_price_raw)
    except Exception: pass

    products = Product.query.order_by(Product.created_at.desc()).all()
    candidate = []
    for p in products:
        seller = get_by_id(SellerUser, p.seller_id)
        seller_name = seller.username if seller else "Unknown"
        img = ProductImage.query.filter_by(product_id=p.id).first()
        img_url = url_for('uploaded_file', filename=img.thumb) if img and img.thumb else None
        numeric_price = _parse_price_to_number(p.price)

        if q:
            combined = f"{p.title or ''} {p.description or ''} {seller_name}"
            if q.lower() not in combined.lower(): continue
        if seller_filter:
            if seller_name.lower() != seller_filter.lower(): continue
        if (min_price is not None or max_price is not None):
            if numeric_price is None: continue
            if min_price is not None and numeric_price < min_price: continue
            if max_price is not None and numeric_price > max_price: continue

        candidate.append({
            "id": p.id, "title": p.title, "price": p.price, "price_num": numeric_price,
            "description": p.description, "seller": seller_name,
            "created_at": p.created_at, "image": img_url
        })

    if sort == "price_asc":
        candidate.sort(key=lambda x: (x["price_num"] is None, x["price_num"] if x["price_num"] is not None else float("inf")))
    elif sort == "price_desc":
        candidate.sort(key=lambda x: (x["price_num"] is None, -(x["price_num"] if x["price_num"] is not None else 0)))
    else:
        candidate.sort(key=lambda x: x["created_at"], reverse=True)

    total = len(candidate)
    total_pages = max(1, ceil(total / per_page))
    if page > total_pages: page = total_pages
    start = (page - 1) * per_page; end = start + per_page
    page_items = candidate[start:end]

    sellers = [u.username for u in SellerUser.query.order_by(SellerUser.username.asc()).all()]
    query_args = {"q": q, "seller": seller_filter, "min_price": min_price_raw,
                  "max_price": max_price_raw, "sort": sort, "page": page, "per_page": per_page}

    return render_template("shop.html",
        products=page_items, total=total, page=page, total_pages=total_pages,
        per_page=per_page, sellers=sellers, query_args=query_args,
        user=current_user if current_user.is_authenticated else None
    )

@app.route("/product/<int:product_id>")
def product_detail(product_id):
    p = db.session.get(Product, product_id) or abort(404)
    seller = get_by_id(SellerUser, p.seller_id)
    seller_name = seller.username if seller else "Unknown"
    images = ProductImage.query.filter_by(product_id=p.id).order_by(ProductImage.created_at.asc()).all()
    imgs = []
    for im in images:
        full = url_for('uploaded_file', filename=im.filename) if im.filename else None
        thumb = url_for('uploaded_file', filename=im.thumb) if im.thumb else full
        imgs.append({"full": full, "thumb": thumb})
    return render_template("product_detail.html",
        product=p, seller_name=seller_name, images=imgs,
        user=current_user if current_user.is_authenticated else None
    )

# ---------- Public Auth (password + OTP) ----------
@app.route("/auth/login", methods=["GET","POST"])
def auth_login():
    if request.method == "POST":
        user_or_email = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        remember = True if request.form.get("remember") == "on" else False

        u = User.query.filter((User.username==user_or_email)|(User.email==user_or_email)).first()
        if u and u.check_password(password):
            login_user(u, remember=remember)
            flash("Welcome back!", "success")
            next_url = request.args.get("next") or url_for("shop")
            return redirect(next_url)
        flash("Invalid username/email or password.", "error")
        return redirect(url_for("auth_login"))
    return render_template("auth_login.html", user=current_user if current_user.is_authenticated else None)

@app.route("/auth/register", methods=["GET","POST"])
def auth_register():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        email = (request.form.get("email") or "").strip()
        password = request.form.get("password") or ""
        if not (username and email and password):
            flash("Please fill username, email and password.", "error")
            return redirect(url_for("auth_register"))
        if User.query.filter((User.username==username)|(User.email==email)).first():
            flash("Username or email already exists.", "error")
            return redirect(url_for("auth_register"))
        u = User(username=username, email=email)
        u.set_password(password)
        db.session.add(u)
        db.session.commit()
        flash("Account created. You can log in now.", "success")
        return redirect(url_for("auth_login"))
    return render_template("auth_register.html", user=current_user if current_user.is_authenticated else None)

@app.route("/auth/logout")
@login_required_user
def auth_logout():
    logout_user()
    flash("Logged out.", "success")
    return redirect(url_for("shop"))

@app.route("/auth/forgot", methods=["GET","POST"])
def auth_forgot():
    if request.method == "POST":
        email = (request.form.get("email") or "").strip()
        u = User.query.filter_by(email=email).first()
        if not u:
            flash("If this email exists, a reset link has been sent.", "success")
            return redirect(url_for("auth_forgot"))
        s = _token_serializer()
        token = s.dumps({"uid": u.id})
        reset_link = url_for("auth_reset", token=token, _external=True)
        print("\n*** PASSWORD RESET LINK (DEV):", reset_link, "***\n")
        flash("Reset link generated. Check server console for the link (dev mode).", "success")
        return redirect(url_for("auth_forgot"))
    return render_template("auth_forgot.html")

@app.route("/auth/reset/<token>", methods=["GET","POST"])
def auth_reset(token):
    s = _token_serializer()
    try:
        data = s.loads(token, max_age=60*60*2)
        uid = data.get("uid")
    except SignatureExpired:
        flash("Reset link expired. Request a new one.", "error")
        return redirect(url_for("auth_forgot"))
    except BadSignature:
        flash("Invalid reset link.", "error")
        return redirect(url_for("auth_forgot"))

    u = db.session.get(User, uid) or abort(404)
    if request.method == "POST":
        pw = request.form.get("password") or ""
        if len(pw) < 6:
            flash("Password must be at least 6 characters.", "error")
            return redirect(url_for("auth_reset", token=token))
        u.set_password(pw)
        db.session.commit()
        flash("Password updated. Log in now.", "success")
        return redirect(url_for("auth_login"))
    return render_template("auth_reset.html", token=token)

# OTP for users
@app.route("/auth/login/request-otp", methods=["POST"])
def auth_request_otp():
    user_or_email = (request.form.get("username") or "").strip()
    if not user_or_email:
        flash("Enter your username or email.", "error")
        return redirect(url_for("auth_login", mode="otp"))
    u = User.query.filter((User.username==user_or_email)|(User.email==user_or_email)).first()
    if not u:
        flash("No account found.", "error")
        return redirect(url_for("auth_login", mode="otp"))

    code = _gen_otp()
    now = datetime.utcnow()
    otp = PublicLoginCode(user_id=u.id, code=code, created_at=now,
                          expires_at=now + timedelta(minutes=OTP_TTL_MINUTES), used=False)
    db.session.add(otp); db.session.commit()
    _send_otp_email(u.email, code)
    session["auth_otp_uid"] = u.id
    flash(f"OTP sent to {u.email}. Expires in {OTP_TTL_MINUTES} minutes.", "success")
    return redirect(url_for("auth_login", mode="otp"))

@app.route("/auth/login/verify-otp", methods=["POST"])
def auth_verify_otp():
    user_or_email = (request.form.get("username") or "").strip()
    code = (request.form.get("otp") or "").strip()
    if not (user_or_email and code):
        flash("Enter username/email and the 6-digit code.", "error")
        return redirect(url_for("auth_login", mode="otp"))

    u = User.query.filter((User.username==user_or_email)|(User.email==user_or_email)).first()
    if not u:
        flash("No account found.", "error")
        return redirect(url_for("auth_login", mode="otp"))

    now = datetime.utcnow()
    match = (PublicLoginCode.query
             .filter_by(user_id=u.id, code=code, used=False)
             .order_by(PublicLoginCode.created_at.desc())
             .first())
    if not match:
        flash("Invalid code.", "error")
        return redirect(url_for("auth_login", mode="otp"))
    if now > match.expires_at:
        flash("Code expired. Request a new one.", "error")
        return redirect(url_for("auth_login", mode="otp"))

    match.used = True
    db.session.commit()
    login_user(u, remember=True)
    flash("Logged in via OTP.", "success")
    next_url = request.args.get("next") or url_for("shop")
    return redirect(next_url)

# ---------- Seller auth (password + OTP) ----------
@app.route("/seller/login", methods=["GET","POST"])
def seller_login():
    if request.method == "POST":
        user_or_email = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        u = SellerUser.query.filter((SellerUser.username==user_or_email)|(SellerUser.email==user_or_email)).first()
        if u and check_password_hash(u.password_hash, password):
            session["seller_id"] = u.id
            flash("Logged in.", "success")
            return redirect(url_for("seller_dashboard"))
        flash("Invalid credentials.", "error")
        return redirect(url_for("seller_login"))
    return render_template("seller_login.html")

@app.route("/seller/logout")
def seller_logout():
    session.pop("seller_id", None)
    flash("Logged out.", "success")
    return redirect(url_for("index"))

@app.route("/seller/register", methods=["GET","POST"])
def seller_register():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        email = (request.form.get("email") or "").strip()
        password = request.form.get("password") or ""
        name = (request.form.get("name") or "").strip()
        brand = (request.form.get("brand") or "").strip()

        if not (username and email and password):
            flash("Please fill username, email and password.", "error")
            return redirect(url_for("seller_register"))
        if SellerUser.query.filter((SellerUser.username==username)|(SellerUser.email==email)).first():
            flash("Username or email already taken.", "error")
            return redirect(url_for("seller_register"))

        seller_profile = Seller(name=name, brand=brand, email=email, approved=False)
        db.session.add(seller_profile)
        db.session.flush()

        # handle optional logo upload
        logo_file = request.files.get("brand_logo")
        if logo_file and logo_file.filename:
            filename = secure_filename(logo_file.filename)
            if allowed_file(filename):
                data = logo_file.read()
                if len(data) <= MAX_CONTENT_BYTES:
                    unique_name = make_unique_filename(filename)
                    dest = os.path.join(UPLOAD_FOLDER, unique_name)
                    with open(dest, "wb") as out: out.write(data)
                    # store reference in seller.note as quick solution
                    seller_profile.note = (seller_profile.note or "") + f"\nlogo:{unique_name}"
                else:
                    flash("Logo exceeded 3MB; skipped.", "error")
            else:
                flash("Unsupported logo type; skipped.", "error")

        user = SellerUser(
            username=username,
            email=email,
            password_hash=generate_password_hash(password),
            seller_profile_id=seller_profile.id
        )
        db.session.add(user)
        db.session.commit()
        flash("Seller account created. Please log in.", "success")
        return redirect(url_for("seller_login"))

    return render_template("auth_register.html")

@app.route("/seller/login/request-otp", methods=["POST"])
def seller_request_otp():
    user_or_email = (request.form.get("username") or "").strip()
    if not user_or_email:
        flash("Enter your username or email.", "error")
        return redirect(url_for("seller_login"))
    u = SellerUser.query.filter((SellerUser.username==user_or_email)|(SellerUser.email==user_or_email)).first()
    if not u:
        flash("No account found for that user.", "error")
        return redirect(url_for("seller_login"))

    code = _gen_otp()
    now = datetime.utcnow()
    otp = LoginCode(user_id=u.id, code=code, created_at=now,
                    expires_at=now + timedelta(minutes=OTP_TTL_MINUTES), used=False)
    db.session.add(otp); db.session.commit()
    _send_otp_email(u.email, code)
    session["otp_pending_user"] = u.id
    flash(f"OTP sent to {u.email}. Expires in {OTP_TTL_MINUTES} minutes.", "success")
    return redirect(url_for("seller_login", mode="otp"))

@app.route("/seller/login/verify-otp", methods=["POST"])
def seller_verify_otp():
    user_or_email = (request.form.get("username") or "").strip()
    code = (request.form.get("otp") or "").strip()
    if not (user_or_email and code):
        flash("Enter username/email and the 6-digit code.", "error")
        return redirect(url_for("seller_login", mode="otp"))

    u = SellerUser.query.filter((SellerUser.username==user_or_email)|(SellerUser.email==user_or_email)).first()
    if not u:
        flash("No account found.", "error")
        return redirect(url_for("seller_login", mode="otp"))

    now = datetime.utcnow()
    match = (LoginCode.query
             .filter_by(user_id=u.id, code=code, used=False)
             .order_by(LoginCode.created_at.desc())
             .first())
    if not match:
        flash("Invalid code.", "error")
        return redirect(url_for("seller_login", mode="otp"))
    if now > match.expires_at:
        flash("Code expired. Request a new one.", "error")
        return redirect(url_for("seller_login", mode="otp"))

    match.used = True
    db.session.commit()
    session["seller_id"] = u.id
    flash("Logged in via OTP.", "success")
    return redirect(url_for("seller_dashboard"))

# ---------- Seller dashboard & products ----------
@app.route("/seller/dashboard", methods=["GET","POST"])
@seller_login_required
def seller_dashboard():
    user = get_by_id(SellerUser, session.get("seller_id"))
    if not user:
        flash("Session invalid.", "error")
        return redirect(url_for("seller_login"))

    if request.method == "POST":
        title = (request.form.get("title") or "").strip()
        price = request.form.get("price") or ""
        desc = (request.form.get("description") or "").strip()
        if not title:
            flash("Product title required.", "error")
            return redirect(url_for("seller_dashboard"))
        p = Product(seller_id=user.id, title=title, price=price, description=desc)
        db.session.add(p)
        db.session.commit()

        files = request.files.getlist("images")
        added_image = False
        for file in files:
            if file and file.filename:
                filename = secure_filename(file.filename)
                if allowed_file(filename):
                    data = file.read()
                    if len(data) <= MAX_CONTENT_BYTES:
                        unique_name = make_unique_filename(filename)
                        dest = os.path.join(UPLOAD_FOLDER, unique_name)
                        with open(dest, "wb") as out: out.write(data)
                        thumb_name = f"{uuid.uuid4().hex}_{THUMB_SUFFIX}.jpg"
                        thumb_path = os.path.join(UPLOAD_FOLDER, thumb_name)
                        ok = create_thumbnail(data, thumb_path, size=(560,360))
                        if not ok: thumb_name = None
                        img = ProductImage(product_id=p.id, filename=unique_name, thumb=thumb_name)
                        db.session.add(img); added_image = True
                    else:
                        flash("One image exceeded 3MB and was skipped.", "error")
                else:
                    flash("Unsupported image type skipped.", "error")
        if added_image:
            db.session.commit(); flash("Product and images uploaded.", "success")
        else:
            flash("Product added.", "success")
        return redirect(url_for("seller_dashboard"))

    products = Product.query.filter_by(seller_id=user.id).order_by(Product.created_at.desc()).all()
    products_with_images = []
    for p in products:
        img = ProductImage.query.filter_by(product_id=p.id).first()
        img_url = url_for('uploaded_file', filename=img.thumb) if img and img.thumb else None
        products_with_images.append((p, img_url))
    return render_template("seller_dashboard.html", user=user, products=products_with_images)

@app.route("/product/<int:product_id>/edit", methods=["GET","POST"])
@seller_login_required
def product_edit(product_id):
    user = get_by_id(SellerUser, session.get("seller_id"))
    p = db.session.get(Product, product_id) or abort(404)
    if p.seller_id != user.id:
        abort(403)
    if request.method == "POST":
        title = (request.form.get("title") or "").strip()
        price = request.form.get("price") or ""
        desc = (request.form.get("description") or "").strip()
        if not title:
            flash("Title required.", "error")
            return redirect(url_for("product_edit", product_id=product_id))
        p.title = title; p.price = price; p.description = desc
        db.session.add(p)
        files = request.files.getlist("images")
        added = False
        for file in files:
            if file and file.filename:
                filename = secure_filename(file.filename)
                if allowed_file(filename):
                    data = file.read()
                    if len(data) <= MAX_CONTENT_BYTES:
                        unique = make_unique_filename(filename)
                        dest = os.path.join(UPLOAD_FOLDER, unique)
                        with open(dest, "wb") as out: out.write(data)
                        thumb_name = f"{uuid.uuid4().hex}_{THUMB_SUFFIX}.jpg"
                        thumb_path = os.path.join(UPLOAD_FOLDER, thumb_name)
                        ok = create_thumbnail(data, thumb_path, size=(560,360))
                        if not ok: thumb_name = None
                        img = ProductImage(product_id=p.id, filename=unique, thumb=thumb_name)
                        db.session.add(img); added = True
                    else:
                        flash("One image exceeded 3MB and was skipped.", "error")
                else:
                    flash("Unsupported image type skipped.", "error")
        db.session.commit()
        flash("Product updated." + (" Images added." if added else ""), "success")
        return redirect(url_for("product_edit", product_id=product_id))
    images = ProductImage.query.filter_by(product_id=p.id).order_by(ProductImage.created_at.asc()).all()
    return render_template("product_edit.html", product=p, images=images)

@app.route("/product/<int:product_id>/image/delete/<int:image_id>", methods=["POST"])
@seller_login_required
def product_image_delete(product_id, image_id):
    user = get_by_id(SellerUser, session.get("seller_id"))
    p = db.session.get(Product, product_id) or abort(404)
    if p.seller_id != user.id: abort(403)
    img = db.session.get(ProductImage, image_id) or abort(404)
    try:
        if img.filename:
            fp = os.path.join(UPLOAD_FOLDER, img.filename)
            if os.path.exists(fp): os.remove(fp)
        if img.thumb:
            fp = os.path.join(UPLOAD_FOLDER, img.thumb)
            if os.path.exists(fp): os.remove(fp)
    except Exception: pass
    db.session.delete(img); db.session.commit()
    flash("Image deleted.", "success")
    return redirect(url_for("product_edit", product_id=product_id))

@app.route("/seller/product/delete/<int:product_id>", methods=["POST"])
@seller_login_required
def seller_product_delete(product_id):
    user = get_by_id(SellerUser, session.get("seller_id"))
    p = db.session.get(Product, product_id) or abort(404)
    if p.seller_id != user.id: abort(403)
    imgs = ProductImage.query.filter_by(product_id=p.id).all()
    for img in imgs:
        try:
            if img.filename:
                fpath = os.path.join(UPLOAD_FOLDER, img.filename)
                if os.path.exists(fpath): os.remove(fpath)
            if img.thumb:
                fpath = os.path.join(UPLOAD_FOLDER, img.thumb)
                if os.path.exists(fpath): os.remove(fpath)
        except Exception: pass
        db.session.delete(img)
    db.session.delete(p); db.session.commit()
    flash("Product deleted.", "success")
    return redirect(url_for("seller_dashboard"))

# ---------- Cart & Checkout ----------
def _get_cart(): return session.get("cart", {})
def _save_cart(cart): session["cart"] = cart; session.modified = True

def _cart_items():
    cart = _get_cart(); rows=[]; total=0.0
    ids = [int(pid) for pid in cart.keys()] if cart else []
    if not ids: return [], 0.0
    products = {p.id: p for p in Product.query.filter(Product.id.in_(ids)).all()}
    for pid_s, meta in cart.items():
        pid = int(pid_s); p = products.get(pid)
        if not p: continue
        qty = max(int(meta.get("qty", 1)), 1)
        price = _price_to_float(p.price); subtotal = price * qty; total += subtotal
        thumb=None; img = ProductImage.query.filter_by(product_id=p.id).first()
        if img and img.thumb: thumb=url_for('uploaded_file', filename=img.thumb)
        rows.append({"id": p.id, "title": p.title, "price": price, "qty": qty, "subtotal": subtotal, "thumb": thumb})
    return rows, total

@app.route("/cart")
def cart_view():
    items, total = _cart_items()
    return render_template("cart.html", items=items, total=total,
                           user=current_user if current_user.is_authenticated else None)

@app.route("/cart/add", methods=["POST"])
def cart_add():
    pid = request.form.get("product_id"); qty = request.form.get("qty", "1")
    try: pid = str(int(pid)); qty = max(int(qty), 1)
    except Exception:
        flash("Could not add to cart.", "error"); return redirect(request.referrer or url_for("shop"))
    if not get_by_id(Product, int(pid)):
        flash("Product not found.", "error"); return redirect(request.referrer or url_for("shop"))
    cart = _get_cart(); cart[pid] = {"qty": cart.get(pid, {}).get("qty", 0) + qty}; _save_cart(cart)
    flash("Added to cart.", "success")
    return redirect(url_for("cart_view"))  # go straight to cart

@app.route("/cart/update", methods=["POST"])
def cart_update():
    cart = _get_cart()
    for key, val in request.form.items():
        if key.startswith("qty_"):
            pid = key.replace("qty_", "")
            try: q = max(int(val), 0)
            except Exception: q = 1
            if q == 0: cart.pop(pid, None)
            else:
                if pid in cart: cart[pid]["qty"] = q
    _save_cart(cart); flash("Cart updated.", "success")
    return redirect(url_for("cart_view"))

@app.route("/cart/remove", methods=["POST"])
def cart_remove():
    pid = request.form.get("product_id"); cart = _get_cart(); cart.pop(str(pid), None)
    _save_cart(cart); flash("Removed item.", "success")
    return redirect(url_for("cart_view"))

@app.route("/checkout", methods=["GET", "POST"])
def checkout():
    items, total = _cart_items()
    if not items:
        flash("Your cart is empty.", "error"); return redirect(url_for("shop"))
    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        email = (request.form.get("email") or "").strip()
        phone = (request.form.get("phone") or "").strip()
        address = (request.form.get("address") or "").strip()
        city = (request.form.get("city") or "").strip()
        pincode = (request.form.get("pincode") or "").strip()
        if not (name and email and address and city and pincode):
            flash("Please fill all required fields.", "error"); return redirect(url_for("checkout"))
        order = Order(user_id=current_user.id if current_user.is_authenticated else None,
                      buyer_name=name, email=email, phone=phone, address=address,
                      city=city, pincode=pincode, total_amount=float(total), status="paid")
        db.session.add(order); db.session.flush()
        for row in items:
            db.session.add(OrderItem(order_id=order.id, product_id=row["id"],
                                     title=row["title"], price_each=row["price"], qty=row["qty"]))
        db.session.commit()  # simulate paid
        _save_cart({})  # clear
        return redirect(url_for("order_success", order_id=order.id))
    return render_template("checkout.html", items=items, total=total,
                           user=current_user if current_user.is_authenticated else None)

@app.route("/order/success/<int:order_id>")
def order_success(order_id):
    order = db.session.get(Order, order_id) or abort(404)
    items = OrderItem.query.filter_by(order_id=order.id).all()
    return render_template("order_success.html", order=order, items=items,
                           user=current_user if current_user.is_authenticated else None)

# ---------- Admin ----------
@app.route("/admin/login", methods=["GET","POST"])
def admin_login():
    if request.method == "POST":
        username = request.form.get("username",""); password = request.form.get("password","")
        if username == ADMIN_USER and check_admin_password(password):
            session["admin_logged_in"] = True; flash("Welcome, admin.", "success")
            return redirect(url_for("admin_sellers"))
        flash("Invalid credentials.", "error"); return redirect(url_for("admin_login"))
    return render_template("admin_login.html")

@app.route("/admin/logout")
def admin_logout():
    session.pop("admin_logged_in", None); flash("Logged out.", "success")
    return redirect(url_for("index"))

@app.route("/admin/sellers")
@admin_login_required
def admin_sellers():
    sellers = Seller.query.order_by(Seller.created_at.desc()).all()
    return render_template("admin_sellers.html", sellers=sellers)

@app.route("/admin/sellers/export.csv")
@admin_login_required
def admin_sellers_export():
    sellers = Seller.query.order_by(Seller.created_at.desc()).all()
    si = StringIO(); writer = csv.writer(si)
    writer.writerow(["id","name","brand","email","phone","note","approved","created_at"])
    for s in sellers:
        writer.writerow([s.id, s.name, s.brand, s.email, s.phone, s.note, s.approved, s.created_at.isoformat()])
    output = si.getvalue().encode("utf-8")
    return Response(output, mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=sellers_export.csv"})

# ---------- SEO: robots.txt + sitemap.xml ----------
@app.route("/robots.txt")
def robots_txt():
    txt = "User-agent: *\nAllow: /\nSitemap: " + url_for('sitemap_xml', _external=True) + "\n"
    resp = make_response(txt, 200)
    resp.mimetype = "text/plain"
    return resp

@app.route("/sitemap.xml")
def sitemap_xml():
    base = request.url_root.rstrip('/')
    pages = [
        (f"{base}/", "1.0"),
        (f"{base}/shop", "0.9"),
        (f"{base}/seller", "0.5"),
    ]
    # add recent products (limit to 2000)
    for p in Product.query.order_by(Product.created_at.desc()).limit(2000):
        pages.append((f"{base}{url_for('product_detail', product_id=p.id)}", "0.8"))

    xml_lines = ['<?xml version="1.0" encoding="UTF-8"?>',
                 '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">']
    today = datetime.utcnow().date().isoformat()
    for loc, priority in pages:
        xml_lines += [
            "  <url>",
            f"    <loc>{loc}</loc>",
            f"    <lastmod>{today}</lastmod>",
            "    <changefreq>daily</changefreq>",
            f"    <priority>{priority}</priority>",
            "  </url>",
        ]
    xml_lines.append("</urlset>")
    resp = make_response("\n".join(xml_lines), 200)
    resp.mimetype = "application/xml"
    return resp
@app.route('/seed-demo', methods=['POST'])
def seed_demo_route():
    if app.config.get('ENV') != 'development' and not os.environ.get('ALLOW_DEMO_SEED'):
        return ('Not allowed', 403)
    # call the seed function from seed_demo.py or inline small seed here.
    try:
        from seed_demo import seed
        seed()
        return ('ok', 200)
    except Exception as e:
        print("seed error", e)
        return (str(e), 500)

# ---------- Run ----------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
