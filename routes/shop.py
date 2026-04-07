from flask import Blueprint, render_template, request, redirect, url_for, flash, abort, session
from models import Product, SellerUser, ProductImage, Order, OrderItem, db
from datetime import datetime
from decimal import Decimal
import re
import os
from sqlalchemy import desc
from math import ceil
from utils import _parse_price_to_number, _price_to_float

shop_bp = Blueprint('shop_bp', __name__)

def _get_cart():
    return session.get("cart", {})

def _save_cart(cart):
    session["cart"] = cart
    session.modified = True

def _cart_items():
    cart = _get_cart()
    rows = []
    total = Decimal('0.0')
    ids = [int(pid) for pid in cart.keys()] if cart else []
    if not ids:
        return [], total
    products = {p.id: p for p in Product.query.filter(Product.id.in_(ids)).all()}
    for pid_s, meta in cart.items():
        pid = int(pid_s)
        p = products.get(pid)
        if not p: continue
        qty = max(int(meta.get("qty", 1)), 1)
        price = p.price or Decimal('0.0')
        subtotal = price * qty
        total += subtotal
        img = ProductImage.query.filter_by(product_id=p.id).first()
        thumb = url_for('static', filename=f'uploads/{img.thumb}') if img and img.thumb else None
        rows.append({"id": pid, "title": p.title, "price": price, "qty": qty, "subtotal": subtotal, "thumb": thumb})
    return rows, total

@shop_bp.route("/shop")
def shop():
    # Extracted shop logic (q, filter, paginate, sort)
    q = request.args.get("q", "").strip()
    seller_filter = request.args.get("seller", "").strip()
    page = max(int(request.args.get("page", 1)), 1)
    per_page = max(int(request.args.get("per_page", 12)), 1)
    # ... full logic from original
    # (abbrev for tool - full in final)
    return render_template("shop.html")

# Add other shop routes (/product/<id>, cart, checkout...)
# To be completed in next steps

