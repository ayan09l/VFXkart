import os
from flask import Flask
from flask_migrate import Migrate
from dotenv import load_dotenv
from extensions import db, login_manager
import models  # Registers models
# Blueprints registered after creation

def create_app(config_name='development'):
    app = Flask(__name__)
    
    # Load .env
    load_dotenv()
    
    # Config from original + env
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or 'dev-secret-change-me!!'
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///instance/vfxkart.db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['UPLOAD_FOLDER'] = os.environ.get('UPLOAD_FOLDER', 'uploads')
    app.config['WTF_CSRF_ENABLED'] = True
    app.config['MAX_CONTENT_LENGTH'] = 3 * 1024 * 1024
    
    # Email
    app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER')
    app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT') or 587)
    app.config['MAIL_USE_TLS'] = app.config['MAIL_SERVER'] is not None
    app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
    app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
    app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', 'no-reply@vfxkart.local')
    
    # External
    app.config['GEMINI_API_KEY'] = os.environ.get('GEMINI_API_KEY')
    app.config['ADMIN_USER'] = os.environ.get('ADMIN_USER', 'admin')
    
    # Init
    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'  # Update later
    
    migrate = Migrate(app, db)
    
    # Context processor (cart)
    @app.context_processor
    def inject_cart():
        from routes.shop import _cart_items  # Temp
        items, total = _cart_items()
        return {'cart_items': items, 'cart_total': total, 'cart_count': len(items)}
    
    # Placeholder for BPs
    # from routes.shop import shop_bp; app.register_blueprint(shop_bp)
    
    # DB init
    with app.app_context():
        db.create_all()
    
    return app

