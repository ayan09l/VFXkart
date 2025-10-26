# -*- coding: utf-8 -*-
"""
VFXKart - Flask app with SQLite, admin, and seller accounts + products
"""
import os, json, csv
from datetime import datetime
from io import StringIO
from flask import (
    Flask, render_template, request, redirect, url_for, flash,
    session, Response, abort
)
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy

# Paths / config
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATE_DIR = os.path.join(BASE_DIR, "templates")
DATA_DIR = os.path.join(BASE_DIR, "data")
JSON_SELLERS = os.path.join(DATA_DIR, "sellers.json")
DB_PATH = os.environ.get("VFXKART_DB", os.path.join(BASE_DIR, "app.db"))



os.makedirs(DATA_DIR, exist_ok=True)
if not os.path.exists(JSON_SELLERS):
    with open(JSON_SELLERS, "w", encoding="utf-8") as f:
        json.dump([], f, ensure_ascii=False, indent=2)

app = Flask(__name__, template_folder=TEMPLATE_DIR)
app.secret_key = os.environ.get("VFXKART_SECRET", "dev-secret-key")
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{DB_PATH}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

# ---------------- Models ----------------
class Seller(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200))
    brand = db.Column(db.String(200))
    email = db.Column(db.String(200))
    phone = db.Column(db.String(100))
    note = db.Column(db.Text)
    approved = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class SellerUser(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(200), unique=True, nullable=False)
    password_hash = db.Column(db.String(300), nullable=False)
    seller_profile_id = db.Column(db.Integer, db.ForeignKey('seller.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def check_password(self, raw):
        return check_password_hash(self.password_hash, raw)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    seller_id = db.Column(db.Integer, db.ForeignKey('seller_user.id'), nullable=False)
    title = db.Column(db.String(250), nullable=False)
    price = db.Column(db.String(80), nullable=True)  # store as string for now (₹)
    description = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# ---------------- Admin auth (unchanged) ----------------
ADMIN_USER = os.environ.get("VFXKART_ADMIN_USER", "admin")
ADMIN_PASS = os.environ.get("VFXKART_ADMIN_PASS", "changeme")
ADMIN_PASS_HASH = os.environ.get("VFXKART_ADMIN_PASS_HASH", None)

def check_admin_password(password: str) -> bool:
    if ADMIN_PASS_HASH:
        return check_password_hash(ADMIN_PASS_HASH, password)
    return password == ADMIN_PASS

def admin_login_required(fn):
    from functools import wraps
    @wraps(fn)
    def wrapper(*a, **kw):
        if not session.get("admin_logged_in"):
            return redirect(url_for("admin_login", next=request.path))
        return fn(*a, **kw)
    return wrapper

# ---------------- Seller auth util ----------------
def seller_login_required(fn):
    from functools import wraps
    @wraps(fn)
    def wrapper(*a, **kw):
        if not session.get("seller_id"):
            return redirect(url_for("seller_login", next=request.path))
        return fn(*a, **kw)
    return wrapper

# ---------------- DB init + JSON import if needed ----------------
def import_json_to_db():
    db.create_all()
    # If Seller table is empty, import from JSON (as before)
    if Seller.query.count() == 0:
        try:
            with open(JSON_SELLERS, "r", encoding="utf-8") as f:
                items = json.load(f)
        except Exception:
            items = []
        for it in items:
            s = Seller(
                name = it.get("name",""),
                brand = it.get("brand",""),
                email = it.get("email",""),
                phone = it.get("phone",""),
                note = it.get("note",""),
                approved = it.get("approved", False)
            )
            db.session.add(s)
        db.session.commit()

with app.app_context():
    import_json_to_db()

# ---------------- Frontend routes ----------------
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/shop")
def shop():
    return render_template("shop.html")

# Seller signup (form that creates a SellerUser and Seller profile entry)
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

        # create Seller profile + user
        seller_profile = Seller(name=name, brand=brand, email=email, approved=False)
        db.session.add(seller_profile)
        db.session.flush()  # get id

        user = SellerUser(
            username=username,
            email=email,
            password_hash=generate_password_hash(password),
            seller_profile_id=seller_profile.id
        )
        db.session.add(user)
        db.session.commit()
        flash("Account created. Please log in.", "success")
        return redirect(url_for("seller_login"))

    return render_template("seller_register.html")

@app.route("/seller/login", methods=["GET","POST"])
def seller_login():
    if request.method == "POST":
        user_or_email = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        u = SellerUser.query.filter((SellerUser.username==user_or_email)|(SellerUser.email==user_or_email)).first()
        if u and u.check_password(password):
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

@app.route("/seller/dashboard", methods=["GET","POST"])
@seller_login_required
def seller_dashboard():
    user = SellerUser.query.get(session.get("seller_id"))
    if not user:
        flash("Session invalid.", "error")
        return redirect(url_for("seller_login"))
    # handle product create
    if request.method == "POST":
        title = (request.form.get("title") or "").strip()
        price = (request.form.get("price") or "").strip()
        desc = (request.form.get("description") or "").strip()
        if not title:
            flash("Product title required.", "error")
            return redirect(url_for("seller_dashboard"))
        p = Product(seller_id=user.id, title=title, price=price, description=desc)
        db.session.add(p)
        db.session.commit()
        flash("Product added.", "success")
        return redirect(url_for("seller_dashboard"))

    products = Product.query.filter_by(seller_id=user.id).order_by(Product.created_at.desc()).all()
    return render_template("seller_dashboard.html", user=user, products=products)

@app.route("/seller/product/delete/<int:product_id>", methods=["POST"])
@seller_login_required
def seller_product_delete(product_id):
    user = SellerUser.query.get(session.get("seller_id"))
    p = Product.query.get_or_404(product_id)
    if p.seller_id != user.id:
        abort(403)
    db.session.delete(p)
    db.session.commit()
    flash("Product deleted.", "success")
    return redirect(url_for("seller_dashboard"))

# ---------------- Admin routes (session-based) ----------------
@app.route("/admin/login", methods=["GET","POST"])
def admin_login():
    if request.method == "POST":
        username = request.form.get("username","")
        password = request.form.get("password","")
        if username == ADMIN_USER and check_admin_password(password):
            session["admin_logged_in"] = True
            flash("Welcome, admin.", "success")
            return redirect(url_for("admin_sellers"))
        flash("Invalid credentials.", "error")
        return redirect(url_for("admin_login"))
    return render_template("admin_login.html")

@app.route("/admin/logout")
def admin_logout():
    session.pop("admin_logged_in", None)
    flash("Logged out.", "success")
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
    si = StringIO()
    writer = csv.writer(si)
    writer.writerow(["id","name","brand","email","phone","note","approved","created_at"])
    for s in sellers:
        writer.writerow([s.id, s.name, s.brand, s.email, s.phone, s.note, s.approved, s.created_at.isoformat()])
    output = si.getvalue().encode("utf-8")
    return Response(output, mimetype="text/csv", headers={
        "Content-Disposition": "attachment; filename=sellers_export.csv"
    })

# ---------------- Run ----------------
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
