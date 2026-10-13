"""
PhishGuard Pro — Publish-ready security platform
"""
import os
import json
import time
import csv
import io
from collections import defaultdict
from datetime import datetime
from functools import wraps

from flask import (
    Flask, render_template, request, jsonify, redirect, url_for,
    flash, session, abort, make_response, Response
)
from flask_login import (
    LoginManager, login_user, logout_user, login_required, current_user
)
from email_validator import validate_email, EmailNotValidError
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from models_db import db, User, ScanHistory, init_db
from scanner.phishing_detector import PhishingDetector
from scanner.spam_detector import SpamDetector
from scanner.vuln_scanner import VulnerabilityScanner

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY") or "dev-only-change-me-phishguard-pro-2026"
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
if os.environ.get("PRODUCTION"):
    app.config["SESSION_COOKIE_SECURE"] = True
    app.config["PREFERRED_URL_SCHEME"] = "https"

init_db(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.login_message = "Sign in required for the vulnerability scanner."
login_manager.login_message_category = "warning"

phishing_engine = PhishingDetector()
spam_engine = SpamDetector()

_rate_buckets = defaultdict(list)
RATE_LIMIT = int(os.environ.get("RATE_LIMIT", "40"))
RATE_WINDOW = 60


def rate_limit_ok(key: str) -> bool:
    now = time.time()
    bucket = _rate_buckets[key]
    _rate_buckets[key] = [t for t in bucket if now - t < RATE_WINDOW]
    if len(_rate_buckets[key]) >= RATE_LIMIT:
        return False
    _rate_buckets[key].append(now)
    return True


@login_manager.user_loader
def load_user(user_id):
    try:
        return db.session.get(User, int(user_id))
    except Exception:
        return None


def admin_required(f):
    @wraps(f)
    @login_required
    def wrapped(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != "admin":
            abort(403)
        return f(*args, **kwargs)
    return wrapped


def verified_user_required(f):
    @wraps(f)
    @login_required
    def wrapped(*args, **kwargs):
        if not current_user.is_active:
            flash("Your account has been blocked.", "danger")
            logout_user()
            return redirect(url_for("login"))
        if not current_user.is_verified:
            flash("Verify your email to use the vulnerability scanner.", "warning")
            return redirect(url_for("verify_pending"))
        return f(*args, **kwargs)
    return wrapped


def save_scan(scan_type, target, label, is_threat, risk_score, result_obj, user_id=None):
    row = ScanHistory(
        user_id=user_id,
        scan_type=scan_type,
        target=(target or "")[:2000],
        label=label,
        is_threat=bool(is_threat),
        risk_score=int(risk_score or 0),
        result_json=json.dumps(result_obj) if result_obj is not None else None,
    )
    db.session.add(row)
    db.session.commit()
    return row


# ---------- Public pages ----------

@app.route("/")
def home():
    return render_template("home.html")


@app.route("/url-threat")
def url_threat_page():
    return render_template("url_threat.html")


@app.route("/spam-scanner")
def spam_scanner_page():
    return render_template("spam_scanner.html")


# ---------- Auth ----------

@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        name = (request.form.get("name") or "").strip()
        password = request.form.get("password") or ""
        confirm = request.form.get("confirm") or ""
        try:
            validate_email(email, check_deliverability=False)
        except EmailNotValidError:
            flash("Invalid email address.", "danger")
            return render_template("register.html")
        if len(password) < 8:
            flash("Password must be at least 8 characters.", "danger")
            return render_template("register.html")
        if password != confirm:
            flash("Passwords do not match.", "danger")
            return render_template("register.html")
        if User.query.filter_by(email=email).first():
            flash("Email already registered.", "danger")
            return render_template("register.html")
        user = User(email=email, name=name or email.split("@")[0], role="user",
                    is_verified=False, is_active=True)
        user.set_password(password)
        token = user.generate_verify_token()
        db.session.add(user)
        db.session.commit()
        verify_url = url_for("verify_email", token=token, _external=True)
        session["pending_verify_url"] = verify_url
        session["pending_email"] = email
        flash("Account created. Verify your email to enable the vulnerability scanner.", "success")
        return redirect(url_for("verify_pending"))
    return render_template("register.html")


@app.route("/verify-pending")
def verify_pending():
    return render_template(
        "verify_pending.html",
        verify_url=session.get("pending_verify_url"),
        email=session.get("pending_email"),
    )


@app.route("/verify/<token>")
def verify_email(token):
    user = User.query.filter_by(verify_token=token).first()
    if not user:
        flash("Invalid or expired verification link.", "danger")
        return redirect(url_for("login"))
    if user.verify_token_expires and user.verify_token_expires < datetime.utcnow():
        flash("Verification link expired.", "danger")
        return redirect(url_for("login"))
    user.is_verified = True
    user.clear_verify_token()
    db.session.commit()
    session.pop("pending_verify_url", None)
    session.pop("pending_email", None)
    flash("Email verified. You can sign in now.", "success")
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""
        user = User.query.filter_by(email=email).first()
        if not user or not user.check_password(password):
            flash("Invalid email or password.", "danger")
            return render_template("login.html")
        if not user.is_active:
            flash("Account blocked.", "danger")
            return render_template("login.html")
        user.last_login = datetime.utcnow()
        db.session.commit()
        login_user(user, remember=bool(request.form.get("remember")))
        flash("Logged in successfully.", "success")
        nxt = request.args.get("next")
        if nxt and nxt.startswith("/"):
            return redirect(nxt)
        return redirect(url_for("dashboard"))
    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out.", "info")
    return redirect(url_for("home"))


@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    if not current_user.is_active:
        logout_user()
        flash("Account blocked.", "danger")
        return redirect(url_for("login"))
    if request.method == "POST":
        current = request.form.get("current_password") or ""
        password = request.form.get("password") or ""
        confirm = request.form.get("confirm") or ""
        if not current_user.check_password(current):
            flash("Current password is incorrect.", "danger")
            return render_template("change_password.html")
        if len(password) < 8:
            flash("New password must be at least 8 characters.", "danger")
            return render_template("change_password.html")
        if password != confirm:
            flash("New passwords do not match.", "danger")
            return render_template("change_password.html")
        if current_user.check_password(password):
            flash("New password must be different from the current password.", "danger")
            return render_template("change_password.html")
        current_user.set_password(password)
        db.session.commit()
        flash("Password updated successfully.", "success")
        return redirect(url_for("dashboard"))
    return render_template("change_password.html")


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        user = User.query.filter_by(email=email).first()
        # Always show same message (no email enumeration)
        flash("If that email exists, a reset link was generated.", "info")
        if user and user.is_active:
            token = user.generate_reset_token()
            db.session.commit()
            reset_url = url_for("reset_password", token=token, _external=True)
            session["pending_reset_url"] = reset_url
            session["pending_reset_email"] = email
            return redirect(url_for("reset_pending"))
        return redirect(url_for("login"))
    return render_template("forgot_password.html")


@app.route("/reset-pending")
def reset_pending():
    return render_template(
        "reset_pending.html",
        reset_url=session.get("pending_reset_url"),
        email=session.get("pending_reset_email"),
    )


@app.route("/reset/<token>", methods=["GET", "POST"])
def reset_password(token):
    user = User.query.filter_by(reset_token=token).first()
    if not user or (user.reset_token_expires and user.reset_token_expires < datetime.utcnow()):
        flash("Invalid or expired reset link.", "danger")
        return redirect(url_for("forgot_password"))
    if request.method == "POST":
        password = request.form.get("password") or ""
        confirm = request.form.get("confirm") or ""
        if len(password) < 8:
            flash("Password must be at least 8 characters.", "danger")
            return render_template("reset_password.html", token=token)
        if password != confirm:
            flash("Passwords do not match.", "danger")
            return render_template("reset_password.html", token=token)
        user.set_password(password)
        user.clear_reset_token()
        db.session.commit()
        session.pop("pending_reset_url", None)
        session.pop("pending_reset_email", None)
        flash("Password updated. Please sign in.", "success")
        return redirect(url_for("login"))
    return render_template("reset_password.html", token=token)


# ---------- User dashboard ----------

@app.route("/dashboard")
@login_required
def dashboard():
    if not current_user.is_active:
        logout_user()
        flash("Account blocked.", "danger")
        return redirect(url_for("login"))
    q = ScanHistory.query.filter_by(user_id=current_user.id)
    history = q.order_by(ScanHistory.created_at.desc()).limit(25).all()
    return render_template(
        "dashboard.html",
        history=history,
        total_scans=q.count(),
        vuln_scans=q.filter_by(scan_type="vuln").count(),
        threat_count=q.filter_by(is_threat=True).count(),
    )


@app.route("/vuln-scanner")
@verified_user_required
def vuln_scanner_page():
    return render_template("vuln_scanner.html")


@app.route("/scan/<int:scan_id>")
@login_required
def scan_detail(scan_id):
    row = db.session.get(ScanHistory, scan_id)
    if not row:
        abort(404)
    if current_user.role != "admin" and row.user_id != current_user.id:
        abort(403)
    result = {}
    if row.result_json:
        try:
            result = json.loads(row.result_json)
        except Exception:
            result = {}
    return render_template("scan_detail.html", scan=row, result=result)


@app.route("/scan/<int:scan_id>/report")
@login_required
def scan_report(scan_id):
    row = db.session.get(ScanHistory, scan_id)
    if not row:
        abort(404)
    if current_user.role != "admin" and row.user_id != current_user.id:
        abort(403)
    result = {}
    if row.result_json:
        try:
            result = json.loads(row.result_json)
        except Exception:
            pass
    html = render_template("report.html", scan=row, result=result, generated=datetime.utcnow())
    resp = make_response(html)
    resp.headers["Content-Disposition"] = f"attachment; filename=phishguard-report-{scan_id}.html"
    return resp


@app.route("/dashboard/export.csv")
@login_required
def export_csv():
    rows = (
        ScanHistory.query.filter_by(user_id=current_user.id)
        .order_by(ScanHistory.created_at.desc())
        .limit(500)
        .all()
    )
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["id", "time", "type", "target", "label", "is_threat", "risk_score"])
    for r in rows:
        w.writerow([
            r.id,
            r.created_at.isoformat() if r.created_at else "",
            r.scan_type,
            r.target,
            r.label,
            r.is_threat,
            r.risk_score,
        ])
    return Response(
        buf.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=my-scans.csv"},
    )


# ---------- Admin ----------

@app.route("/admin")
@admin_required
def admin_panel():
    users = User.query.order_by(User.created_at.desc()).all()
    recent = ScanHistory.query.order_by(ScanHistory.created_at.desc()).limit(40).all()
    model_info = {
        "phishing_dataset": "30,000 labeled URL samples",
        "spam_dataset": "23,000+ labeled message samples",
        "phishing_model": "RandomForest",
        "spam_model": "TF-IDF + GradientBoosting",
        "note": "Hold-out metrics are reported for the packaged training set. Retrain on organization-specific or live threat feeds for production use.",
    }
    return render_template(
        "admin.html",
        users=users,
        total_scans=ScanHistory.query.count(),
        total_users=User.query.filter(User.role != "admin").count(),
        blocked=User.query.filter_by(is_active=False).count(),
        recent=recent,
        model_info=model_info,
    )


@app.route("/admin/user/<int:user_id>/toggle-block", methods=["POST"])
@admin_required
def admin_toggle_block(user_id):
    user = db.session.get(User, user_id)
    if not user or user.role == "admin":
        flash("Cannot modify this user.", "danger")
        return redirect(url_for("admin_panel"))
    user.is_active = not user.is_active
    db.session.commit()
    flash(f"{user.email} is now {'active' if user.is_active else 'blocked'}.", "success")
    return redirect(url_for("admin_panel"))


@app.route("/admin/user/<int:user_id>/verify", methods=["POST"])
@admin_required
def admin_verify_user(user_id):
    user = db.session.get(User, user_id)
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for("admin_panel"))
    user.is_verified = True
    user.clear_verify_token()
    db.session.commit()
    flash(f"Verified {user.email}.", "success")
    return redirect(url_for("admin_panel"))


# ---------- APIs ----------

@app.route("/api/url-threat", methods=["POST"])
def api_url_threat():
    ip = request.remote_addr or "unknown"
    if not rate_limit_ok(f"url:{ip}"):
        return jsonify({"error": "Rate limit exceeded."}), 429
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()
    if not url or len(url) > 2048:
        return jsonify({"error": "Valid URL required (max 2048 chars)."}), 400
    result = phishing_engine.predict(url)
    uid = current_user.id if current_user.is_authenticated else None
    row = save_scan("phishing", url, result.get("label"), result.get("is_phishing"),
                    result.get("risk_score"), result, user_id=uid)
    result["scan_id"] = row.id
    return jsonify(result)


@app.route("/api/spam", methods=["POST"])
def api_spam():
    ip = request.remote_addr or "unknown"
    if not rate_limit_ok(f"spam:{ip}"):
        return jsonify({"error": "Rate limit exceeded."}), 429
    data = request.get_json(silent=True) or {}
    text = (data.get("text") or "").strip()
    if not text or len(text) > 10000:
        return jsonify({"error": "Text required (max 10000 chars)."}), 400
    result = spam_engine.predict(text)
    uid = current_user.id if current_user.is_authenticated else None
    row = save_scan("spam", text[:500], result.get("label"), result.get("is_spam"),
                    result.get("risk_score"), result, user_id=uid)
    result["scan_id"] = row.id
    return jsonify(result)


@app.route("/api/vuln-scan", methods=["POST"])
@verified_user_required
def api_vuln_scan():
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()
    if not url or len(url) > 2048:
        return jsonify({"error": "Valid URL required."}), 400
    if not data.get("acknowledge_authorized"):
        return jsonify({"error": "Authorization confirmation required."}), 400
    scanner = VulnerabilityScanner(max_pages=8, timeout=6)
    result = scanner.scan(url)
    n = len(result.get("vulnerabilities") or [])
    row = save_scan(
        "vuln", url, f"{n} issues", n > 0,
        (result.get("summary") or {}).get("high", 0) * 25,
        result, user_id=current_user.id,
    )
    result["scan_id"] = row.id
    return jsonify(result)


@app.route("/api/health")
def api_health():
    return jsonify({
        "status": "ok",
        "service": "PhishGuard Pro",
        "version": "1.0.0",
        "public_modules": ["url-threat", "spam"],
        "auth_required": ["vuln-scanner"],
    })


@app.errorhandler(403)
def forbidden(e):
    flash("Access denied.", "danger")
    return redirect(url_for("home")), 403


@app.errorhandler(404)
def not_found(e):
    return render_template("home.html"), 404


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = not os.environ.get("PRODUCTION")
    print("=" * 60)
    print("  PhishGuard Pro")
    print(f"  http://0.0.0.0:{port}")
    print("=" * 60)
    app.run(debug=debug, host="0.0.0.0", port=port)
