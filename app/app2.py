import os
import sys
from urllib.parse import urlparse

from flask import Flask, render_template, request
from flask_login import LoginManager
from flask_migrate import Migrate

from models import db, User
from auth.views import auth

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")

login_manager = LoginManager()
login_manager.init_app(app)

login_manager.login_view = "auth.login"

db.init_app(app)
Migrate(app, db)

# Add HTTPS verification middleware
@app.before_request
def verify_https():
    """Verify the application is being served over HTTPS, which is required for WebAuthn."""
    # Skip check for localhost development
    hostname = urlparse(request.url).hostname
    if hostname in ('localhost', '127.0.0.1'):
        return
        
    # Check for HTTPS
    if not request.is_secure:
        app.logger.error("WebAuthn requires HTTPS! Application is being served over HTTP.")
        return """
        <h1>HTTPS Required</h1>
        <p>This application implements WebAuthn, which requires HTTPS.</p>
        <p>You are currently accessing it via HTTP. Please use HTTPS instead.</p>
        <p>Try using ngrok as described in the README.md file.</p>
        """, 400

app.register_blueprint(auth, url_prefix="/auth")


@login_manager.user_loader
def load_user(user_uid):
    return User.query.filter_by(uid=user_uid).first()


@app.route("/")
def index():
    """The main homepage. This is a stub since it's a demo project."""
    return render_template("index.html")


# Add a startup check to verify HTTPS configuration
if __name__ == "__main__":
    # Check if we're running with HTTPS
    if not os.getenv("HTTPS_ENABLED") and not os.getenv("NGROK_URL"):
        print("WARNING: WebAuthn requires HTTPS! Make sure you're using ngrok or another HTTPS solution.")
        print("See README.md for instructions on setting up ngrok for development.")
    
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)))