import os
from sqlalchemy import create_all
from flask import Flask
from extensions import db
import models

app = Flask(__name__)
# Try the absolute path format that worked in raw sqlite3
db_abs_path = os.path.abspath("app.db").replace("\\", "/")
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{db_abs_path}"

db.init_app(app)

with app.app_context():
    try:
        # Just try to connect and list something
        res = db.session.execute(db.text("SELECT 1")).fetchall()
        print(f"SUCCESS: Connected to database at {db_abs_path}")
        print(f"Result: {res}")
    except Exception as e:
        print(f"FAILURE: Could not connect to database at {db_abs_path}")
        print(f"Error: {e}")
