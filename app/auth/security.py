import datetime
import json
import os
import secrets
import hashlib
from urllib.parse import urlparse

import webauthn
from flask import request
from redis import Redis
from webauthn.helpers.structs import PublicKeyCredentialDescriptor

from models import WebAuthnCredential, db

REDIS_HOST = os.getenv("REDIS_HOST")
REDIS_PORT = os.getenv("REDIS_PORT")
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD")

REGISTRATION_CHALLENGES = Redis(
    host=REDIS_HOST, port=REDIS_PORT, db=0, password=REDIS_PASSWORD
)
AUTHENTICATION_CHALLENGES = Redis(
    host=REDIS_HOST, port=REDIS_PORT, db=1, password=REDIS_PASSWORD
)

def _hostname():
    return str(urlparse(request.base_url).hostname)

def _challenge_key(user):
    # Use a hash of the user.uid and a random salt to make the Redis key unpredictable
    salt = os.getenv("CHALLENGE_SALT", "default_salt")
    return hashlib.shake_256(f"{user.uid}{salt}".encode()).hexdigest(32)

def _generate_post_quantum_challenge(length=64):
    # Use secrets.token_bytes for strong randomness, then hash with SHAKE256 for post-quantum resistance
    random_bytes = secrets.token_bytes(length)
    return hashlib.shake_256(random_bytes).digest(64)

def prepare_credential_creation(user):
    """Generate the configuration needed by the client to start registering a new WebAuthn credential."""
    public_credential_creation_options = webauthn.generate_registration_options(
        rp_id=_hostname(),
        rp_name="Flask WebAuthn Demo",
        user_id=user.uid,
        user_name=user.username,
        challenge=_generate_post_quantum_challenge()
    )

    challenge_key = _challenge_key(user)
    REGISTRATION_CHALLENGES.set(challenge_key, public_credential_creation_options.challenge)
    REGISTRATION_CHALLENGES.expire(challenge_key, datetime.timedelta(minutes=3))  # Reduced expiration

    return webauthn.options_to_json(public_credential_creation_options)

def verify_and_save_credential(user, registration_credential):
    """Verify that a new credential is valid for the user."""
    challenge_key = _challenge_key(user)
    expected_challenge = REGISTRATION_CHALLENGES.get(challenge_key)

    auth_verification = webauthn.verify_registration_response(
        credential=registration_credential,
        expected_challenge=expected_challenge,
        expected_origin=f"https://{_hostname()}",
        expected_rp_id=_hostname(),
    )

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
        challenge=_generate_post_quantum_challenge()
    )

    challenge_key = _challenge_key(user)
    AUTHENTICATION_CHALLENGES.set(challenge_key, authentication_options.challenge)
    AUTHENTICATION_CHALLENGES.expire(challenge_key, datetime.timedelta(minutes=3))  # Reduced expiration

    return json.loads(webauthn.options_to_json(authentication_options))

def verify_authentication_credential(user, authentication_credential):
    """
    Verify a submitted credential against a credential in the database and the
    challenge stored in redis.
    """
    challenge_key = _challenge_key(user)
    expected_challenge = AUTHENTICATION_CHALLENGES.get(challenge_key)
    stored_credential = (
        WebAuthnCredential.query.with_parent(user)
        .filter_by(
            credential_id=webauthn.base64url_to_bytes(authentication_credential.id)
        )
        .first()
    )

    webauthn.verify_authentication_response(
        credential=authentication_credential,
        expected_challenge=expected_challenge,
        expected_origin=f"https://{_hostname()}",
        expected_rp_id=_hostname(),
        credential_public_key=stored_credential.credential_public_key,
        credential_current_sign_count=0
    )
    AUTHENTICATION_CHALLENGES.expire(challenge_key, datetime.timedelta(seconds=1))

    stored_credential.current_sign_count += 1
    db.session.add(stored_credential)
    db.session.commit()