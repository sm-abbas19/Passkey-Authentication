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
from models import User, db

auth = Blueprint("auth", __name__, template_folder="templates")


@auth.route("/register")
def register():
    """Show the form for new users to register"""
    return render_template("auth/register.html")


@auth.route("/create-user", methods=["POST"])
def create_user():
    """Handle creation of new users from the user creation form."""
    name = request.form.get("name")
    username = request.form.get("username")
    email = request.form.get("email")

    user = User(name=name, username=username, email=email)
    try:
        db.session.add(user)
        db.session.commit()
    except IntegrityError:
        return render_template(
            "auth/_partials/user_creation_form.html",
            error="That username or email address is already in use. "
            "Please enter a different one.",
        )

    login_user(user)
    pcco_json = security.prepare_credential_creation(user)
    return make_response(
        render_template(
            "auth/_partials/register_credential.html",
            public_credential_creation_options=pcco_json,
        )
    )


@auth.route("/add-credential", methods=["POST"])
@login_required
def add_credential():
    """Receive a newly registered credentials to validate and save."""
    registration_credential = RegistrationCredential.parse_raw(request.get_data())
    try:
        security.verify_and_save_credential(current_user, registration_credential)
        session["registration_user_uid"] = None
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
    except InvalidRegistrationResponse:
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
    # The lower function just does case insensitivity for our.
    user = User.query.filter(
        or_(
            func.lower(User.username) == username_or_email,
            func.lower(User.email) == username_or_email,
        )
    ).first()

    # if no user matches, send back the form with an error message
    if not user:
        return render_template(
            "auth/_partials/username_form.html", error="No matching user found"
        )

    auth_options = security.prepare_login_with_credential(user)

    res = make_response(
        render_template(
            "auth/_partials/select_login.html",
            auth_options=auth_options,
            username=user.username,
        )
    )

    # set the user uid on the session to get when we are authenticating later.
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
        abort(make_response('{"verified": false}', 400))

    authentication_credential = AuthenticationCredential.parse_raw(request.get_data())
    try:
        security.verify_authentication_credential(user, authentication_credential)
        login_user(user)

        next_ = request.args.get("next")
        if not next_ or not util.is_safe_url(next_):
            next_ = url_for("auth.user_profile")
        return util.make_json_response({"verified": True, "next": next_})
    except InvalidAuthenticationResponse:
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


# Add these new routes to your existing views.py

from flask import session, redirect, url_for
from sqlalchemy.exc import IntegrityError
from datetime import datetime
from auth import oauth
from models import User, ThirdPartyAccount, db

# Google OAuth login
@auth.route('/login/google')
def login_google():
    redirect_uri = url_for('auth.google_callback', _external=True)
    return oauth.google.authorize_redirect(redirect_uri)

@auth.route('/login/callback/google')
def google_callback():
    token = oauth.google.authorize_access_token()
    user_info = oauth.google.parse_id_token(token)
    
    # Check if this Google account is already linked to a user
    third_party_account = ThirdPartyAccount.query.filter_by(
        provider='google',
        provider_user_id=user_info['sub']
    ).first()
    
    if third_party_account:
        # Existing connection - log the user in
        user = third_party_account.user
        third_party_account.last_login_at = datetime.utcnow()
        db.session.commit()
        login_user(user)
        return redirect(url_for('auth.user_profile'))
    else:
        # No existing connection - check if email exists
        email = user_info.get('email')
        user = User.query.filter_by(email=email).first() if email else None
        
        if user:
            # Link to existing user
            third_party_account = ThirdPartyAccount(
                user=user,
                provider='google',
                provider_user_id=user_info['sub'],
                email=email,
                name=user_info.get('name')
            )
            db.session.add(third_party_account)
            db.session.commit()
            login_user(user)
            return redirect(url_for('auth.user_profile'))
        else:
            # Create new user
            user = User(
                name=user_info.get('name', 'Google User'),
                username=email.split('@')[0] if email else f"google_{user_info['sub']}",
                email=email
            )
            
            try:
                db.session.add(user)
                db.session.flush()  # Get the user ID without committing
                
                # Create third-party account link
                third_party_account = ThirdPartyAccount(
                    user=user,
                    provider='google',
                    provider_user_id=user_info['sub'],
                    email=email,
                    name=user_info.get('name')
                )
                db.session.add(third_party_account)
                db.session.commit()
                login_user(user)
                return redirect(url_for('auth.user_profile'))
            except IntegrityError:
                db.session.rollback()
                # Handle username collision
                return render_template(
                    "auth/register.html",
                    error="A user with this email or username already exists. Please log in instead."
                )

# GitHub OAuth login
@auth.route('/login/github')
def login_github():
    redirect_uri = url_for('auth.github_callback', _external=True)
    return oauth.github.authorize_redirect(redirect_uri)

@auth.route('/login/callback/github')
def github_callback():
    token = oauth.github.authorize_access_token()
    resp = oauth.github.get('user', token=token)
    user_info = resp.json()
    
    # Get email (GitHub might not provide email directly)
    if 'email' not in user_info or not user_info['email']:
        emails_resp = oauth.github.get('user/emails', token=token)
        emails = emails_resp.json()
        primary_email = next((email['email'] for email in emails if email['primary']), None)
        if primary_email:
            user_info['email'] = primary_email
    
    # Similar logic as Google callback - check for existing connections,
    # link to existing users by email, or create new users...
    # (Implementation similar to Google callback)
    
    # For brevity, detailed implementation not shown
    # Return appropriate response based on logic
    return redirect(url_for('auth.user_profile'))

# Add these new routes to your existing views.py file

@auth.route('/disconnect/google')
@login_required
def disconnect_google():
    # Check if user has other authentication methods before allowing disconnect
    has_passkey = len(current_user.credentials) > 0
    has_other_providers = ThirdPartyAccount.query.filter(
        ThirdPartyAccount.user_id == current_user.id,
        ThirdPartyAccount.provider != 'google'
    ).count() > 0
    
    if not has_passkey and not has_other_providers:
        flash("Cannot disconnect your only authentication method", "error")
        return redirect(url_for('auth.user_profile'))
    
    # Delete the Google connection
    ThirdPartyAccount.query.filter_by(
        user_id=current_user.id,
        provider='google'
    ).delete()
    db.session.commit()
    
    flash("Google account disconnected successfully", "success")
    return redirect(url_for('auth.user_profile'))


@auth.route('/disconnect/github')
@login_required
def disconnect_github():
    # Check if user has other authentication methods before allowing disconnect
    has_passkey = len(current_user.credentials) > 0
    has_other_providers = ThirdPartyAccount.query.filter(
        ThirdPartyAccount.user_id == current_user.id,
        ThirdPartyAccount.provider != 'github'
    ).count() > 0
    
    if not has_passkey and not has_other_providers:
        flash("Cannot disconnect your only authentication method", "error")
        return redirect(url_for('auth.user_profile'))
    
    # Delete the GitHub connection
    ThirdPartyAccount.query.filter_by(
        user_id=current_user.id,
        provider='github'
    ).delete()
    db.session.commit()
    
    flash("GitHub account disconnected successfully", "success")
    return redirect(url_for('auth.user_profile'))