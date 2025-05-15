@auth.route("/verify-otp", methods=["POST"])
def verify_otp():
    """Verify OTP and complete user registration"""
    name = request.form.get("name")
    username = request.form.get("username")
    email = request.form.get("email")
    otp = request.form.get("otp")
    
    # Verify OTP
    if not util.verify_otp(email, otp):
        log_passkey_operation(
            email,
            'otp_verification',
            'failed',
            'Invalid or expired OTP'
        )
        return render_template(
            "auth/verify_otp.html",
            name=name,
            username=username,
            email=email,
            error="Invalid or expired verification code. Please try again."
        )
    
    # OTP verified, create user account
    try:
        user = User(name=name, username=username, email=email)
        db.session.add(user)
        db.session.commit()
        
        log_passkey_operation(
            email,
            'user_created',
            'success',
            f'User {username} created successfully after OTP verification'
        )
        
        login_user(user)
        session['used_webauthn'] = False
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
            "auth/verify_otp.html",
            name=name,
            username=username,
            email=email,
            error="That username or email address is already in use. Please try again with a different one."
        )


@auth.route("/resend-otp", methods=["POST"])
def resend_otp():
    """Resend OTP to user's email"""
    name = request.form.get("name")
    username = request.form.get("username")
    email = request.form.get("email")
    
    # Generate new OTP
    otp = util.generate_otp()
    util.store_otp(email, otp)
    
    # Send OTP via email
    email_subject = "Your Registration Verification Code"
    email_body = f"""
Hello {name},

Your verification code for registering at SecurePass is:

{otp}

This code is valid for 10 minutes.

If you didn't request this code, please ignore this email.

Best regards,
SecurePass Team
"""
    
    util.send_email(email, email_subject, email_body)
    
    log_passkey_operation(
        email,
        'otp_resent',
        'success',
        f'OTP resent to {email} for verification'
    )
    
    return "", 204  # Return empty response with "No Content" status
