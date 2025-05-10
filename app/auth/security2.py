import datetime
import json
import os
import secrets
import hashlib
import hmac
from urllib.parse import urlparse

import webauthn
from flask import request
from redis import Redis
from webauthn.helpers.structs import PublicKeyCredentialDescriptor

from models import WebAuthnCredential, db

REDIS_HOST = os.getenv("REDIS_HOST")
REDIS_PORT = os.getenv("REDIS_PORT")
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD")
# Add a server-side secret key (ideally from environment variable)
CHALLENGE_KEY_SECRET = os.getenv("CHALLENGE_KEY_SECRET", secrets.token_hex(32))

REGISTRATION_CHALLENGES = Redis(
    host=REDIS_HOST, port=REDIS_PORT, db=0, password=REDIS_PASSWORD
)
AUTHENTICATION_CHALLENGES = Redis(
    host=REDIS_HOST, port=REDIS_PORT, db=1, password=REDIS_PASSWORD
)

# Store the mapping between the secure key and the user
REGISTRATION_CHALLENGE_KEYS = {}
AUTHENTICATION_CHALLENGE_KEYS = {}


def _hostname():
    return str(urlparse(request.base_url).hostname)


def _generate_secure_challenge_key(user_uid, purpose="generic"):
    """Generate a secure, unpredictable key for storing challenges."""
    # Create a timestamp component for uniqueness
    timestamp = str(datetime.datetime.now().timestamp())
    # Use HMAC to create a secure derived key that can't be reverse-engineered
    # Using SHA3-256 (post-quantum resistant) instead of SHA-256
    h = hmac.new(
        CHALLENGE_KEY_SECRET.encode(),
        f"{user_uid}:{timestamp}:{purpose}".encode(),
        hashlib.sha3_256  # Changed from hashlib.sha256 to sha3_256 for post-quantum resistance
    )
    # Return a hex digest of the HMAC
    return f"challenge:{purpose}:{h.hexdigest()}"


def prepare_credential_creation(user):
    """Generate the configuration needed by the client to start registering a new
    WebAuthn credential."""
    public_credential_creation_options = webauthn.generate_registration_options(
        rp_id=_hostname(),
        rp_name="Flask WebAuthn Demo",
        user_id=user.uid,
        user_name=user.username,
        authenticator_selection={
            "userVerification": "required",  # Explicitly require biometric/PIN verification
            "residentKey": "required",       # Ensure credential is stored on device (for passwordless)
            "authenticatorAttachment": "platform"  # Prefer platform authenticators (like TouchID, FaceID, Windows Hello)
        },
    )

    # Generate a secure key for this challenge
    secure_key = _generate_secure_challenge_key(user.uid, "registration")
    
    # Store the secure key mapping
    REGISTRATION_CHALLENGE_KEYS[user.uid] = secure_key
    
    # Store in Redis with the secure key instead of user.uid
    REGISTRATION_CHALLENGES.set(secure_key, public_credential_creation_options.challenge)
    REGISTRATION_CHALLENGES.expire(secure_key, datetime.timedelta(minutes=3))  # Reduced time

    return webauthn.options_to_json(public_credential_creation_options)


def verify_and_save_credential(user, registration_credential):
    """Verify that a new credential is valid for the"""
    # Get the secure key from our mapping
    secure_key = REGISTRATION_CHALLENGE_KEYS.get(user.uid)
    if not secure_key:
        raise ValueError("Challenge expired or invalid")
        
    # Get the challenge from Redis
    expected_challenge = REGISTRATION_CHALLENGES.get(secure_key)
    
    # Immediately delete the challenge from Redis (single-use)
    REGISTRATION_CHALLENGES.delete(secure_key)
    
    # Also remove from our mapping
    if user.uid in REGISTRATION_CHALLENGE_KEYS:
        del REGISTRATION_CHALLENGE_KEYS[user.uid]
    
    if not expected_challenge:
        raise ValueError("Challenge expired or already used")

    # If the credential is somehow invalid (i.e. the challenge is wrong),
    # this will raise an exception. It's easier to handle that in the view
    # since we can send back an error message directly.
    auth_verification = webauthn.verify_registration_response(
        credential=registration_credential,
        expected_challenge=expected_challenge,
        expected_origin=f"https://{_hostname()}",
        expected_rp_id=_hostname(),
    )

    # At this point verification has succeeded and we can save the credential
    credential = WebAuthnCredential(
        user=user,
        credential_public_key=auth_verification.credential_public_key,
        credential_id=auth_verification.credential_id,
    )

    db.session.add(credential)
    db.session.commit()


def prepare_login_with_credential(user):
    """
    Prepare the authentication options for a user trying to log in.
    """
    allowed_credentials = [
        PublicKeyCredentialDescriptor(id=credential.credential_id)
        for credential in user.credentials
    ]

    authentication_options = webauthn.generate_authentication_options(
        rp_id=_hostname(),
        allow_credentials=allowed_credentials,
        user_verification="required",  # Added to require biometric/PIN verification during login
    )

    # Generate a secure key for this challenge
    secure_key = _generate_secure_challenge_key(user.uid, "authentication")
    
    # Store the secure key mapping
    AUTHENTICATION_CHALLENGE_KEYS[user.uid] = secure_key
    
    # Store in Redis with the secure key instead of user.uid
    AUTHENTICATION_CHALLENGES.set(secure_key, authentication_options.challenge)
    AUTHENTICATION_CHALLENGES.expire(secure_key, datetime.timedelta(minutes=3))  # Reduced time

    return json.loads(webauthn.options_to_json(authentication_options))


def verify_authentication_credential(user, authentication_credential):
    """
    Verify a submitted credential against a credential in the database and the
    challenge stored in redis.
    """
    # Get the secure key from our mapping
    secure_key = AUTHENTICATION_CHALLENGE_KEYS.get(user.uid)
    if not secure_key:
        raise ValueError("Challenge expired or invalid")
        
    # Get the challenge from Redis
    expected_challenge = AUTHENTICATION_CHALLENGES.get(secure_key)
    
    # Immediately delete the challenge from Redis (single-use)
    AUTHENTICATION_CHALLENGES.delete(secure_key)
    
    # Also remove from our mapping
    if user.uid in AUTHENTICATION_CHALLENGE_KEYS:
        del AUTHENTICATION_CHALLENGE_KEYS[user.uid]
    
    if not expected_challenge:
        raise ValueError("Challenge expired or already used")
        
    stored_credential = (
        WebAuthnCredential.query.with_parent(user)
        .filter_by(
            credential_id=webauthn.base64url_to_bytes(authentication_credential.id)
        )
        .first()
    )

    # This will raise if the credential does not authenticate
    # It seems that safari doesn't track credential sign count correctly, so we just
    # have to leave it on zero so that it will authenticate
    webauthn.verify_authentication_response(
        credential=authentication_credential,
        expected_challenge=expected_challenge,
        expected_origin=f"https://{_hostname()}",
        expected_rp_id=_hostname(),
        credential_public_key=stored_credential.credential_public_key,
        credential_current_sign_count=0
    )

    # Update the credential sign count after using, then save it back to the database.
    # This is mainly for reference since we can't use it because of Safari's weirdness.
    stored_credential.current_sign_count += 1
    db.session.add(stored_credential)
    db.session.commit()