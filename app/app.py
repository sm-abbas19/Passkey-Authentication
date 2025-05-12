import os
from functools import wraps
from flask import Flask, render_template, jsonify, redirect, url_for, flash
from flask_login import LoginManager, current_user, login_required
from flask_migrate import Migrate

from models import db, User, AdminSettings, PasskeyOperationLog, WebAuthnCredential
from auth.views import auth

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")

# Email configuration
app.config["MAIL_USERNAME"] = os.getenv("MAIL_USERNAME")
app.config["MAIL_PASSWORD"] = os.getenv("MAIL_PASSWORD")
app.config["MAIL_SERVER"] = os.getenv("MAIL_SERVER")
app.config["MAIL_PORT"] = int(os.getenv("MAIL_PORT"))
app.config["MAIL_FROM"] = os.getenv("MAIL_FROM")


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "auth.login"

db.init_app(app)
Migrate(app, db)

app.register_blueprint(auth, url_prefix="/auth")

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('auth.login'))
        
        allowed_emails = AdminSettings.get_allowed_emails()
        if current_user.email not in allowed_emails:
            flash('Access denied. Admin privileges required.', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def passkey_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash('You need to login first.', 'error')
            return redirect(url_for('auth.login'))
        
        # Check if the user has at least one registered credential
        if not current_user.credentials or len(current_user.credentials) == 0:
            flash('You need to register a passkey before accessing this page.', 'error')
            return redirect(url_for('auth.user_profile'))
            
        return f(*args, **kwargs)
    return decorated_function

@app.route("/admin/dashboard")
@login_required
@admin_required
def admin_dashboard():
    # Get recent operation logs
    operation_logs = PasskeyOperationLog.query.order_by(PasskeyOperationLog.timestamp.desc()).limit(50).all()
    
    # Calculate statistics
    total_passkeys = WebAuthnCredential.query.count()
    active_users = User.query.filter(User.credentials.any()).count()
    success_count = PasskeyOperationLog.query.filter_by(status='success').count()
    total_ops = PasskeyOperationLog.query.count()
    success_rate = (success_count / total_ops * 100) if total_ops > 0 else 0
    
    stats = {
        'total_passkeys': total_passkeys,
        'active_users': active_users,
        'success_rate': success_rate
    }
    
    return render_template("admin/dashboard.html", operation_logs=operation_logs, stats=stats)

@app.route("/admin/refresh-logs")
@login_required
@admin_required
def refresh_logs():
    logs = PasskeyOperationLog.query.order_by(PasskeyOperationLog.timestamp.desc()).limit(50).all()
    return jsonify({'logs': [log.to_dict() for log in logs]})

@login_manager.user_loader
def load_user(user_uid):
    return User.query.filter_by(uid=user_uid).first()

@app.route("/")
def index():
    """The main homepage. This is a stub since it's a demo project."""
    return render_template("index.html")

@app.context_processor
def inject_global_variables():
    is_admin = False
    has_passkey = False
    
    if hasattr(current_user, 'is_authenticated') and current_user.is_authenticated:
        # Check admin status
        allowed_emails = AdminSettings.get_allowed_emails()
        if current_user.email in allowed_emails:
            is_admin = True
        
        # Check if user has registered passkeys
        if hasattr(current_user, 'credentials') and current_user.credentials and len(current_user.credentials) > 0:
            has_passkey = True
    
    return dict(
        is_admin=is_admin,
        has_passkey=has_passkey
    )

@app.route("/protected-content")
@login_required
@passkey_required
def protected_content():
    """A page that requires both login and a registered passkey to access."""
    # Log the successful access to protected content
    from auth.views import log_passkey_operation
    log_passkey_operation(
        current_user.email,
        'protected_content_access',
        'success',
        f'User {current_user.username} accessed protected content'
    )
    return render_template("protected_content.html")
