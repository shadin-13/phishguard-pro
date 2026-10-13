"""
SQLite models: User + ScanHistory (per-user isolation)
"""
import os
import secrets
from datetime import datetime, timedelta
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    name = db.Column(db.String(120), nullable=True)
    role = db.Column(db.String(20), default="user")
    is_verified = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)
    verify_token = db.Column(db.String(64), nullable=True, index=True)
    verify_token_expires = db.Column(db.DateTime, nullable=True)
    reset_token = db.Column(db.String(64), nullable=True, index=True)
    reset_token_expires = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)

    scans = db.relationship("ScanHistory", backref="user", lazy="dynamic")

    def set_password(self, password: str):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    def generate_verify_token(self, hours=48):
        self.verify_token = secrets.token_urlsafe(32)
        self.verify_token_expires = datetime.utcnow() + timedelta(hours=hours)
        return self.verify_token

    def clear_verify_token(self):
        self.verify_token = None
        self.verify_token_expires = None

    def generate_reset_token(self, hours=2):
        self.reset_token = secrets.token_urlsafe(32)
        self.reset_token_expires = datetime.utcnow() + timedelta(hours=hours)
        return self.reset_token

    def clear_reset_token(self):
        self.reset_token = None
        self.reset_token_expires = None


class ScanHistory(db.Model):
    __tablename__ = "scan_history"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True, index=True)
    scan_type = db.Column(db.String(30), nullable=False)
    target = db.Column(db.Text, nullable=False)
    label = db.Column(db.String(120), nullable=True)
    is_threat = db.Column(db.Boolean, default=False)
    risk_score = db.Column(db.Integer, default=0)
    result_json = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)


def init_db(app):
    db_path = os.path.join(app.root_path, "data", "phishguard.db")
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    app.config.setdefault("SQLALCHEMY_DATABASE_URI", f"sqlite:///{db_path}")
    app.config.setdefault("SQLALCHEMY_TRACK_MODIFICATIONS", False)
    db.init_app(app)
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(role="admin").first():
            admin_email = os.environ.get("ADMIN_EMAIL", "admin@phishguard.local")
            admin_pass = os.environ.get("ADMIN_PASSWORD", "ChangeMeAdmin#2026")
            admin = User(
                email=admin_email,
                name="Administrator",
                role="admin",
                is_verified=True,
                is_active=True,
            )
            admin.set_password(admin_pass)
            db.session.add(admin)
            db.session.commit()
            print("=" * 60)
            print("  [SETUP] Admin created — change password after first login")
            print(f"  Email: {admin_email}")
            print("=" * 60)
