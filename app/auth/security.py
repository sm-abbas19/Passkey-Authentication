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
# Server-side secret key for challenge key generation (defaults to secure random if not set)
CHALLENGE_KEY_SECRET = os.getenv("CHALLENGE_KEY_SECRET", secrets.token_hex(32))

REGISTRATION_CHALLENGES = Redis(
    host=REDIS_HOST, port=REDIS_PORT, db=0, password=REDIS_PASSWORD
)
AUTHENTICATION_CHALLENGES = Redis(
    host=REDIS_HOST, port=REDIS_PORT, db=1, password=REDIS_PASSWORD
)

# In-memory mapping between user IDs and secure challenge keys
# This is needed to maintain compatibility with existing code
REGISTRATION_KEYS_MAP = {}
AUTHENTICATION_KEYS_MAP = {}


def _generate_secure_challenge_key(user_uid, purpose="challenge"):
    """Generate a secure, post-quantum resistant key for storing challenges.
    
    Uses HMAC-SHA3-256 (quantum-resistant) with a server secret, user ID, 
    timestamp and random nonce to create an unpredictable key.
    """
    timestamp = datetime.datetime.now().timestamp()
    nonce = secrets.token_hex(16)  # Additional entropy
    
    # Create a composite message with all entropy sources
    message = f"{user_uid}:{timestamp}:{nonce}:{purpose}"
    
    # Use SHA3-256 (post-quantum resistant) for the HMAC
    h = hmac.new(
        CHALLENGE_KEY_SECRET.encode(),
        message.encode(),
        hashlib.sha3_256
    )
    
    # Return a prefixed hex digest to identify the purpose
    return f"pq_challenge:{purpose}:{h.hexdigest()}"


def _hostname():
    """Get hostname from the request"""
    # Handle proxies/load balancers that might change the hostname
    forwarded_host = request.headers.get('X-Forwarded-Host')
    if forwarded_host:
        return str(forwarded_host)
    return str(urlparse(request.base_url).hostname)


def _origin():
    """Get origin with proper protocol"""
    host = _hostname()
    if request.headers.get('X-Forwarded-Proto') == 'https':
        return f"https://{host}"
    elif request.is_secure:
        return f"https://{host}"
    else:
        return f"http://{host}"


def prepare_credential_creation(user):
    """Generate the configuration needed by the client to start registering a new
    WebAuthn credential."""
    # Generate WebAuthn options
    public_credential_creation_options = webauthn.generate_registration_options(
        rp_id=_hostname(),
        rp_name="Flask WebAuthn Demo",
        user_id=user.uid,
        user_name=user.username,
    )

    # Generate a secure, post-quantum resistant challenge key
    secure_key = _generate_secure_challenge_key(user.uid, "registration")
    
    # Store the mapping for later retrieval
    REGISTRATION_KEYS_MAP[user.uid] = secure_key
    
    # Store in Redis with the secure key instead of user.uid
    REGISTRATION_CHALLENGES.set(secure_key, public_credential_creation_options.challenge)
    # Reduce expiration from 10 minutes to 5 minutes for better security
    REGISTRATION_CHALLENGES.expire(secure_key, datetime.timedelta(minutes=5))

    return webauthn.options_to_json(public_credential_creation_options)


def verify_and_save_credential(user, registration_credential):
    """Verify that a new credential is valid for the user"""
    # Get the secure key from our mapping
    secure_key = REGISTRATION_KEYS_MAP.get(user.uid)
    if not secure_key:
        raise ValueError("Challenge mapping not found")
        
    # Get the challenge from Redis using the secure key
    expected_challenge = REGISTRATION_CHALLENGES.get(secure_key)
    
    # Immediately delete the challenge to prevent replay attacks (one-time use)
    REGISTRATION_CHALLENGES.delete(secure_key)
    
    # Clean up our mapping
    if user.uid in REGISTRATION_KEYS_MAP:
        del REGISTRATION_KEYS_MAP[user.uid]
    
    if not expected_challenge:
        raise ValueError("Challenge expired or already used")

    # Verify the registration
    auth_verification = webauthn.verify_registration_response(
        credential=registration_credential,
        expected_challenge=expected_challenge,
        expected_origin=_origin(),
        expected_rp_id=_hostname(),
    )

    # Save the credential
    credential = WebAuthnCredential(
        user=user,
        credential_public_key=auth_verification.credential_public_key,
        credential_id=auth_verification.credential_id,
    )

    db.session.add(credential)
    db.session.commit()


def prepare_login_with_credential(user):
    """Prepare the authentication options for a user trying to log in."""
    allowed_credentials = [
        PublicKeyCredentialDescriptor(id=credential.credential_id)
        for credential in user.credentials
    ]

    authentication_options = webauthn.generate_authentication_options(
        rp_id=_hostname(),
        allow_credentials=allowed_credentials,
    )

    # Generate a secure, post-quantum resistant challenge key
    secure_key = _generate_secure_challenge_key(user.uid, "authentication")
    
    # Store the mapping for later retrieval
    AUTHENTICATION_KEYS_MAP[user.uid] = secure_key
    
    # Store in Redis with the secure key instead of user.uid
    AUTHENTICATION_CHALLENGES.set(secure_key, authentication_options.challenge)
    # Reduce expiration from 10 minutes to 5 minutes for better security
    AUTHENTICATION_CHALLENGES.expire(secure_key, datetime.timedelta(minutes=5))

    return json.loads(webauthn.options_to_json(authentication_options))


def verify_authentication_credential(user, authentication_credential):
    """Verify a submitted credential against a credential in the database and the
    challenge stored in redis."""
    # Get the secure key from our mapping
    secure_key = AUTHENTICATION_KEYS_MAP.get(user.uid)
    if not secure_key:
        raise ValueError("Challenge mapping not found")
        
    # Get the challenge from Redis using the secure key
    expected_challenge = AUTHENTICATION_CHALLENGES.get(secure_key)
    
    # Immediately delete the challenge to prevent replay attacks (one-time use)
    AUTHENTICATION_CHALLENGES.delete(secure_key)
    
    # Clean up our mapping
    if user.uid in AUTHENTICATION_KEYS_MAP:
        del AUTHENTICATION_KEYS_MAP[user.uid]
    
    if not expected_challenge:
        raise ValueError("Challenge expired or already used")
    
    stored_credential = (
        WebAuthnCredential.query.with_parent(user)
        .filter_by(
            credential_id=webauthn.base64url_to_bytes(authentication_credential.id)
        )
        .first()
    )

    # Verify the authentication
    webauthn.verify_authentication_response(
        credential=authentication_credential,
        expected_challenge=expected_challenge,
        expected_origin=_origin(),
        expected_rp_id=_hostname(),
        credential_public_key=stored_credential.credential_public_key,
        credential_current_sign_count=0
    )

    # Update the credential sign count after using, then save it back to the database.
    stored_credential.current_sign_count += 1
    db.session.add(stored_credential)
    db.session.commit()