from extensions import db
from datetime import datetime
from decimal import Decimal
from sqlalchemy.dialects.sqlite import TIMESTAMP
from flask_login import UserMixin

class Seller(db.Model):
    __tablename__ = "seller"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    brand = db.Column(db.String(200))
    email = db.Column(db.String(200), unique=True)
    phone = db.Column(db.String(100))
    note = db.Column(db.Text)
    approved = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class SellerUser(db.Model):
    __tablename__ = "seller_user"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(200), unique=True, nullable=False)
    password_hash = db.Column(db.String(300), nullable=False)
    seller_profile_id = db.Column(db.Integer, db.ForeignKey('seller.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    def check_password(self, raw): 
        from werkzeug.security import check_password_hash
        return check_password_hash(self.password_hash, raw)

class User(db.Model, UserMixin):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(200), unique=True, nullable=False)
    password_hash = db.Column(db.String(300), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    def set_password(self, raw): 
        from werkzeug.security import generate_password_hash
        self.password_hash = generate_password_hash(raw)
    def check_password(self, raw): 
        from werkzeug.security import check_password_hash
        return check_password_hash(self.password_hash, raw)

class Product(db.Model):
    __tablename__ = "product"
    id = db.Column(db.Integer, primary_key=True)
    seller_id = db.Column(db.Integer, db.ForeignKey('seller_user.id'), nullable=False)
    title = db.Column(db.String(250), nullable=False)
    price = db.Column(db.Numeric(10,2), nullable=True)  # Improved: Decimal
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    seller = db.relationship('SellerUser', backref='products')

class ProductImage(db.Model):
    __tablename__ = "product_image"
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    filename = db.Column(db.String(300), nullable=False)
    thumb = db.Column(db.String(300), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    product = db.relationship('Product', backref='images')

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
    total_amount = db.Column(db.Numeric(10,2), default=Decimal('0.0'))
    status = db.Column(db.String(40), default="paid")
    user = db.relationship('User', backref='orders')
    items = db.relationship('OrderItem', backref='order', cascade='all, delete-orphan')

class OrderItem(db.Model):
    __tablename__ = "order_item"
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    title = db.Column(db.String(250))
    price_each = db.Column(db.Numeric(10,2), default=Decimal('0.0'))
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

class Internship(db.Model):
    __tablename__ = "internships"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    company = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    category = db.Column(db.String(50))
    skills = db.Column(db.String(200))
    location = db.Column(db.String(100))
    duration = db.Column(db.String(50))
    internship_type = db.Column(db.String(50))
    stipend = db.Column(db.String(50))
    paid = db.Column(db.Boolean, default=True)
    apply_url = db.Column(db.String(400))
    is_active = db.Column(db.Boolean, default=True)
    deadline = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, server_default=db.func.now())


# ═══════════════════════════════════════════════════
#  INTERNSHIP PROGRAM SYSTEM (NullClass / Jyesta style)
# ═══════════════════════════════════════════════════

class InternProgram(db.Model):
    """A training+internship program (e.g., 'Web Development Internship')"""
    __tablename__ = "intern_program"
    id = db.Column(db.Integer, primary_key=True)
    slug = db.Column(db.String(100), unique=True, nullable=False)        # "web-development"
    title = db.Column(db.String(200), nullable=False)                     # "Web Development Internship"
    domain = db.Column(db.String(100), nullable=False)                    # "web_dev"
    tagline = db.Column(db.String(300))                                    # Short marketing line
    description = db.Column(db.Text)                                       # Full description
    icon = db.Column(db.String(50), default="fas fa-code")                 # FontAwesome icon
    color = db.Column(db.String(20), default="#4F46E5")                    # Brand color
    duration_weeks = db.Column(db.Integer, default=4)
    price = db.Column(db.Integer, default=999)                             # INR
    max_seats = db.Column(db.Integer, default=100)
    skills_covered = db.Column(db.Text)                                    # "HTML, CSS, JS, React, Node.js"
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    modules = db.relationship('InternModule', backref='program', lazy=True, order_by='InternModule.week_number')
    tasks = db.relationship('InternTask', backref='program', lazy=True, order_by='InternTask.order')
    enrollments = db.relationship('InternEnrollment', backref='program', lazy=True)


class InternModule(db.Model):
    """Interactive AI-powered lesson module (Phase 1: Learn)"""
    __tablename__ = "intern_module"
    id = db.Column(db.Integer, primary_key=True)
    program_id = db.Column(db.Integer, db.ForeignKey('intern_program.id'), nullable=False)
    week_number = db.Column(db.Integer, nullable=False)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    video_url = db.Column(db.String(500))                                  # YouTube embed (branded shell)
    lesson_content = db.Column(db.Text)                                    # Quick notes below video
    lesson_type = db.Column(db.String(30), default="concept")
    duration_minutes = db.Column(db.Integer, default=15)
    resources_url = db.Column(db.String(500))


class InternTask(db.Model):
    """Project task that student must complete (Phase 2: Build)"""
    __tablename__ = "intern_task"
    id = db.Column(db.Integer, primary_key=True)
    program_id = db.Column(db.Integer, db.ForeignKey('intern_program.id'), nullable=False)
    order = db.Column(db.Integer, default=1)                               # Task order 1, 2, 3
    title = db.Column(db.String(200), nullable=False)                      # "Build a Portfolio Website"
    description = db.Column(db.Text)
    requirements = db.Column(db.Text)                                      # What to submit
    submission_type = db.Column(db.String(50), default="github_link")      # github_link / file_upload / url
    max_score = db.Column(db.Integer, default=100)
    deadline_days = db.Column(db.Integer, default=7)                       # Days to complete from unlock


class InternEnrollment(db.Model):
    """Tracks a student's enrollment in a program"""
    __tablename__ = "intern_enrollment"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    program_id = db.Column(db.Integer, db.ForeignKey('intern_program.id'), nullable=False)
    enrolled_at = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(30), default="active")                    # active / completed / dropped
    payment_id = db.Column(db.String(100))                                 # Razorpay payment ID
    training_completed = db.Column(db.Boolean, default=False)              # Phase 1 done?
    total_score = db.Column(db.Integer, default=0)
    certificate_id = db.Column(db.String(50))                              # "VFXK-INT-2026-XXXX"

    user = db.relationship('User', backref='intern_enrollments')
    submissions = db.relationship('TaskSubmission', backref='enrollment', lazy=True)


class TaskSubmission(db.Model):
    """Individual task submission by a student"""
    __tablename__ = "task_submission"
    id = db.Column(db.Integer, primary_key=True)
    enrollment_id = db.Column(db.Integer, db.ForeignKey('intern_enrollment.id'), nullable=False)
    task_id = db.Column(db.Integer, db.ForeignKey('intern_task.id'), nullable=False)
    submitted_at = db.Column(db.DateTime, default=datetime.utcnow)
    submission_url = db.Column(db.String(500))                              # GitHub link or file
    submission_notes = db.Column(db.Text)                                   # Student's notes
    score = db.Column(db.Integer)                                           # 0-100
    feedback = db.Column(db.Text)                                           # Mentor feedback
    status = db.Column(db.String(30), default="pending")                    # pending / reviewed / resubmit

    task = db.relationship('InternTask', backref='submissions')

class InternApplication(db.Model):
    """Application for a task-first, stipend-based internship (no training required)."""
    __tablename__ = "intern_application"
    id = db.Column(db.Integer, primary_key=True)
    program_id = db.Column(db.Integer, db.ForeignKey('intern_program.id'), nullable=False)
    # Applicant info
    full_name = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(200), nullable=False)
    phone = db.Column(db.String(30))
    college = db.Column(db.String(300))
    year_of_study = db.Column(db.String(20))          # "1st", "2nd", "3rd", "4th", "Graduate"
    branch = db.Column(db.String(100))                 # "CSE", "ECE", "MBA", etc.
    github_url = db.Column(db.String(400))
    linkedin_url = db.Column(db.String(400))
    portfolio_url = db.Column(db.String(400))
    skills = db.Column(db.Text)                        # comma-separated skills they have
    why_apply = db.Column(db.Text)                     # "Why do you want this internship?"
    experience = db.Column(db.Text)                    # Any past experience / projects
    availability = db.Column(db.String(50))            # "Full-time", "Part-time", "Weekends"
    # Status
    status = db.Column(db.String(30), default="pending")  # pending / shortlisted / selected / rejected
    stipend_amount = db.Column(db.String(50))          # e.g. "₹3,000/month" — assigned after selection
    task_assigned = db.Column(db.Boolean, default=False)
    applied_at = db.Column(db.DateTime, default=datetime.utcnow)
    reviewed_at = db.Column(db.DateTime)
    admin_notes = db.Column(db.Text)

    program = db.relationship('InternProgram', backref='applications')

