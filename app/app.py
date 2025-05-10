import os

from flask import Flask, render_template, flash
from flask_login import LoginManager
from flask_migrate import Migrate

from models import db, User
from auth.views import auth
from auth import init_oauth

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")

# OAuth configuration
app.config['GOOGLE_CLIENT_ID'] = os.getenv("GOOGLE_CLIENT_ID")
app.config['GOOGLE_CLIENT_SECRET'] = os.getenv("GOOGLE_CLIENT_SECRET")
app.config['GITHUB_CLIENT_ID'] = os.getenv("GITHUB_CLIENT_ID")
app.config['GITHUB_CLIENT_SECRET'] = os.getenv("GITHUB_CLIENT_SECRET")

# Initialize extensions
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "auth.login"

db.init_app(app)
Migrate(app, db)

# Initialize OAuth
init_oauth(app)

# Register blueprints
app.register_blueprint(auth, url_prefix="/auth")

# Flash message categories for Bootstrap
app.config['BOOTSTRAP_SERVE_LOCAL'] = True


@login_manager.user_loader
def load_user(user_uid):
    return User.query.filter_by(uid=user_uid).first()


@app.route("/")
def index():
    """The main homepage. This is a stub since it's a demo project."""
    return render_template("index.html")


# Enable Jinja2 to access flash messages in templates
@app.context_processor
def inject_flashes():
    return dict(flashed_messages=flash)


if __name__ == "__main__":
    app.run(debug=True)