# -*- coding: utf-8 -*-
"""
VFXKart - Flask app (final merged version)
- index (landing)
- shop (placeholder)
- seller (save to data/sellers.json)
- admin_sellers (password protected via env var VFXKART_ADMIN_PWD)
"""
import os
import json
from flask import Flask, render_template, request, redirect, url_for, flash

# -----------------------
# Config / paths
# -----------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATE_DIR = os.path.join(BASE_DIR, "templates")
DATA_DIR = os.path.join(BASE_DIR, "data")
SELLERS_FILE = os.path.join(DATA_DIR, "sellers.json")

# ensure data folder & file exist (UTF-8)
os.makedirs(DATA_DIR, exist_ok=True)
if not os.path.exists(SELLERS_FILE):
    with open(SELLERS_FILE, "w", encoding="utf-8") as f:
        json.dump([], f, ensure_ascii=False, indent=2)

# Flask app
app = Flask(__name__, template_folder=TEMPLATE_DIR)
app.secret_key = os.environ.get("VFXKART_SECRET", "dev-secret-key")  # change for production

# -----------------------
# Routes
# -----------------------
@app.route("/")
def index():
    # show landing page (templates/index.html)
    try:
        return render_template("index.html")
    except Exception as e:
        # fallback if template missing
        return "<h1>Landing page missing</h1><p>Create templates/index.html</p>", 500


@app.route("/shop")
def shop():
    try:
        return render_template("shop.html")
    except Exception:
        return "<h2>Shop (placeholder)</h2><p>Create templates/shop.html to style this page.</p>"


@app.route("/seller", methods=["GET", "POST"])
def seller():
    """
    Seller signup form:
    - GET: show form
    - POST: validate minimal fields, append to data/sellers.json, and show confirmation
    """
    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        brand = (request.form.get("brand") or "").strip()
        email = (request.form.get("email") or "").strip()
        phone = (request.form.get("phone") or "").strip()
        note = (request.form.get("note") or "").strip()

        if not (name and brand and email):
            flash("Please fill name, brand and email.", "error")
            return redirect(url_for("seller"))

        # append submission
        try:
            with open(SELLERS_FILE, "r", encoding="utf-8") as f:
                sellers = json.load(f)
        except Exception:
            sellers = []

        sellers.append({
            "name": name,
            "brand": brand,
            "email": email,
            "phone": phone,
            "note": note
        })

        with open(SELLERS_FILE, "w", encoding="utf-8") as f:
            json.dump(sellers, f, ensure_ascii=False, indent=2)

        flash("Thanks! Your seller request was received.", "success")
        return render_template("seller.html", submitted=True, name=name, brand=brand, email=email)

    # GET
    return render_template("seller.html", submitted=False)


# -----------------------
# Admin: view saved sellers
# -----------------------
ADMIN_PASSWORD = os.environ.get("VFXKART_ADMIN_PWD", "changeme")  # change in env for production

@app.route("/admin/sellers")
def admin_sellers():
    """
    Simple admin page to list sellers saved in data/sellers.json.
    Protects access via ?pwd=PASSWORD or X-Admin-Pwd HTTP header.
    """
    pwd = request.args.get("pwd") or request.headers.get("X-Admin-Pwd")
    if not pwd or pwd != ADMIN_PASSWORD:
        return (
            "<h2>Admin — Sellers</h2>"
            "<p>Unauthorized. Provide ?pwd=YOURPASSWORD in URL or X-Admin-Pwd header.</p>"
        ), 401

    # load sellers file
    try:
        with open(SELLERS_FILE, "r", encoding="utf-8") as f:
            sellers = json.load(f)
    except Exception:
        sellers = []

    # prefer template, fallback to plain HTML table
    try:
        return render_template("admin_sellers.html", sellers=sellers)
    except Exception:
        rows = ""
        for i, s in enumerate(sellers, start=1):
            rows += "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
                i, s.get("name",""), s.get("brand",""), s.get("email",""), s.get("phone","")
            )
        html = f"""
        <html><head><meta charset='utf-8'><title>Admin Sellers</title></head>
        <body style='font-family:system-ui;background:#0b0710;color:#e6eef8;padding:20px'>
          <h1>Saved Sellers</h1>
          <table border="1" cellpadding="8" cellspacing="0">
            <thead><tr><th>#</th><th>Name</th><th>Brand</th><th>Email</th><th>Phone</th></tr></thead>
            <tbody>{rows if rows else '<tr><td colspan=5>No submissions</td></tr>'}</tbody>
          </table>
        </body></html>
        """
        return html


# -----------------------
# Run
# -----------------------
if __name__ == "__main__":
    # debug for dev; change in production
    app.run(host="127.0.0.1", port=5000, debug=True)
