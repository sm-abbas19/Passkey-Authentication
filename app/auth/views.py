import datetime

from flask import (
    Blueprint,
    render_template,
    request,
    make_response,
    session,
    abort,
    url_for,
    redirect,
)
from flask_login import login_user, login_required, current_user, logout_user
from sqlalchemy import or_, func
from sqlalchemy.exc import IntegrityError
from webauthn.helpers.exceptions import (
    InvalidRegistrationResponse,
    InvalidAuthenticationResponse,
)
from webauthn.helpers.structs import RegistrationCredential, AuthenticationCredential

from auth import security, util
from models import User, db, PasskeyOperationLog

auth = Blueprint("auth", __name__, template_folder="templates")


import random

@auth.route("/register")
def register():
    """Show the form for new users to register with a random math CAPTCHA"""
    # Generate two random numbers for the CAPTCHA (1-9)
    num1 = random.randint(1, 9)
    num2 = random.randint(1, 9)
    captcha_answer = num1 + num2
    
    # Store the answer in session for validation later
    session["captcha_answer"] = str(captcha_answer)
    
    # Pass the question to the template
    captcha_question = f"What is {num1} + {num2}?"
    
    return render_template("auth/register.html", captcha_question=captcha_question, error=None)


def log_passkey_operation(user_email, operation_type, status, details=None):
    log = PasskeyOperationLog(
        user_email=user_email,
        operation_type=operation_type,
        status=status,
        details=details
    )
    db.session.add(log)
    db.session.commit()

@auth.route("/create-user", methods=["POST"])
def create_user():
    """Handle creation of new users from the user creation form."""
    # Dynamic math CAPTCHA validation
    captcha_answer = request.form.get("captcha_answer")
    expected_answer = session.get("captcha_answer")
    
    # Clear the session captcha to prevent replay attacks
    session.pop("captcha_answer", None)
    
    if not expected_answer or captcha_answer != expected_answer:
        # If validation fails, generate a new CAPTCHA
        num1 = random.randint(1, 9)
        num2 = random.randint(1, 9)
        session["captcha_answer"] = str(num1 + num2)
        captcha_question = f"What is {num1} + {num2}?"
        
        return render_template(
            "auth/register.html",
            captcha_question=captcha_question,
            error="Security check failed. Please try again."
        )
    
    # Continue with existing user creation code...
    name = request.form.get("name")
    username = request.form.get("username")
    email = request.form.get("email")

    try:
        user = User(name=name, username=username, email=email)
        db.session.add(user)
        db.session.commit()
        
        log_passkey_operation(
            email,
            'user_created',
            'success',
            f'User {username} created successfully'
        )
        
        login_user(user)
        pcco_json = security.prepare_credential_creation(user)
        
        log_passkey_operation(
            email,
            'challenge_sent',
            'success',
            f'Registration challenge generated for {username}'
        )
        
        return make_response(
            render_template(
                "auth/_partials/register_credential.html",
                public_credential_creation_options=pcco_json,
            )
        )
    except IntegrityError:
        log_passkey_operation(
            email,
            'user_creation',
            'failed',
            'Username or email already in use'
        )
        return render_template(
            "auth/_partials/user_creation_form.html",
            error="That username or email address is already in use. "
            "Please enter a different one.",
        )


@auth.route("/add-credential", methods=["POST"])
@login_required
def add_credential():
    """Receive a newly registered credentials to validate and save."""
    registration_credential = RegistrationCredential.parse_raw(request.get_data())
    try:
        security.verify_and_save_credential(current_user, registration_credential)
        session["registration_user_uid"] = None
        
        log_passkey_operation(
            current_user.email,
            'public_key_created',
            'success',
            f'Passkey registered for {current_user.username}'
        )
        
        res = util.make_json_response(
            {"verified": True, "next": url_for("auth.user_profile")}
        )
        res.set_cookie(
            "user_uid",
            current_user.uid,
            httponly=True,
            secure=True,
            samesite="strict",
            max_age=datetime.timedelta(days=30),
        )
        return res
    except InvalidRegistrationResponse as e:
        log_passkey_operation(
            current_user.email,
            'public_key_creation',
            'failed',
            str(e)
        )
        abort(make_response('{"verified": false}', 400))


@auth.route("/login", methods=["GET"])
def login():
    """Prepare to log in the user with biometric authentication"""
    user_uid = request.cookies.get("user_uid")
    user = User.query.filter_by(uid=user_uid).first()

    # If the user is not remembered from a previous session, we'll need to get
    # their username.
    if not user:
        return render_template("auth/login.html", username=None, auth_options=None)

    # If they are remembered, we can skip directly to biometrics.
    auth_options = security.prepare_login_with_credential(user)

    # Set the user uid on the session to get when we are authenticating
    session["login_user_uid"] = user.uid
    return render_template(
        "auth/login.html", username=user.username, auth_options=auth_options
    )


@auth.route("/prepare-login", methods=["POST"])
def prepare_login():
    """Prepare login options for a user based on their username or email"""
    username_or_email = request.form.get("username_email", "").lower()
    user = User.query.filter(
        or_(
            func.lower(User.username) == username_or_email,
            func.lower(User.email) == username_or_email,
        )
    ).first()

    if not user:
        log_passkey_operation(
            username_or_email,
            'login_attempt',
            'failed',
            'No matching user found'
        )
        return render_template(
            "auth/_partials/username_form.html", error="No matching user found"
        )

    try:
        auth_options = security.prepare_login_with_credential(user)
        
        log_passkey_operation(
            user.email,
            'auth_challenge_sent',
            'success',
            f'Authentication challenge sent to {user.username}'
        )
        
        res = make_response(
            render_template(
                "auth/_partials/select_login.html",
                auth_options=auth_options,
                username=user.username,
            )
        )
        session["login_user_uid"] = user.uid
        res.set_cookie(
            "user_uid",
            user.uid,
            httponly=True,
            secure=True,
            samesite="strict",
            max_age=datetime.timedelta(days=30),
        )
        return res
    except Exception as e:
        log_passkey_operation(
            user.email,
            'auth_challenge',
            'failed',
            str(e)
        )
        return render_template(
            "auth/_partials/username_form.html",
            error="Error preparing login. Please try again."
        )


@auth.route("/login-switch-user")
def login_switch_user():
    """Remove a remembered user and show the username form again."""
    session["login_user_uid"] = None
    res = make_response(redirect(url_for("auth.login")))
    res.delete_cookie("user_uid")
    return res


@auth.route("/verify-login-credential", methods=["POST"])
def verify_login_credential():
    """Log in a user with a submitted credential"""
    user_uid = session.get("login_user_uid")
    user = User.query.filter_by(uid=user_uid).first()
    if not user:
        log_passkey_operation(
            'unknown',
            'login_verification',
            'failed',
            'No user found in session'
        )
        abort(make_response('{"verified": false}', 400))

    authentication_credential = AuthenticationCredential.parse_raw(request.get_data())
    try:
        security.verify_authentication_credential(user, authentication_credential)
        login_user(user)
        
        log_passkey_operation(
            user.email,
            'authentication_complete',
            'success',
            f'User {user.username} authenticated successfully'
        )
        
        next_ = request.args.get("next")
        if not next_ or not util.is_safe_url(next_):
            next_ = url_for("auth.user_profile")
        return util.make_json_response({"verified": True, "next": next_})
    except InvalidAuthenticationResponse as e:
        log_passkey_operation(
            user.email,
            'authentication',
            'failed',
            str(e)
        )
        abort(make_response('{"verified": false}', 400))


@auth.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("index"))


@auth.route("/user-profile")
@login_required
def user_profile():
    pcco_json = security.prepare_credential_creation(current_user)
    return render_template("auth/user_profile.html", public_credential_creation_options=pcco_json)
