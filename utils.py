import os, re, uuid, random, smtplib
from io import BytesIO
from email.message import EmailMessage
from PIL import Image
from flask import current_app

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "webp"}
MAX_CONTENT_BYTES = 3 * 1024 * 1024  # 3MB
OTP_TTL_MINUTES = 5
THUMB_SUFFIX = "thumb"

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

def _gen_otp(): return f"{random.randint(0, 999999):06d}"

def _send_otp_email(to_email: str, code: str):
    SMTP_HOST = current_app.config.get("SMTP_HOST", "")
    SMTP_PORT = int(current_app.config.get("SMTP_PORT", "587"))
    SMTP_USER = current_app.config.get("SMTP_USER", "")
    SMTP_PASS = current_app.config.get("SMTP_PASS", "")
    SMTP_FROM = current_app.config.get("SMTP_FROM", "no-reply@vfxkart.local")
    
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
