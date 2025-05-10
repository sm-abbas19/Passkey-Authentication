import time
import os
import requests
from functools import wraps
from flask import request, render_template
import redis

# Use the existing Redis connection parameters from security.py
from auth.security import REDIS_HOST, REDIS_PORT, REDIS_PASSWORD

# Create a separate Redis connection for rate limiting
RATE_LIMIT_REDIS = redis.Redis(
    host=REDIS_HOST, 
    port=REDIS_PORT, 
    db=2,  # Use a different db than the existing ones
    password=REDIS_PASSWORD
)

# Configuration
MAX_REGISTRATION_ATTEMPTS = 5  # Max attempts per time window
REGISTRATION_WINDOW = 60 * 60  # 1 hour (in seconds)
COOLDOWN_PERIOD = 60 * 60 * 24  # 24 hours (in seconds)
CAPTCHA_SITE_KEY = os.getenv("RECAPTCHA_SITE_KEY", "6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI")  # Test key
CAPTCHA_SECRET_KEY = os.getenv("RECAPTCHA_SECRET_KEY", "6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe")  # Test key

def get_remote_address():
    """Get the IP address of the client, handling proxies properly."""
    if request.headers.get('X-Forwarded-For'):
        # If behind a proxy (like ngrok), get real IP
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    return request.remote_addr

def is_rate_limited(key_prefix):
    """Check if the current IP address is rate limited."""
    ip = get_remote_address()
    key = f"{key_prefix}:{ip}"
    
    # Get the current count and timestamp of first request
    pipe = RATE_LIMIT_REDIS.pipeline()
    pipe.get(f"{key}:count")
    pipe.get(f"{key}:first")
    pipe.get(f"{key}:blocked_until")
    count, first_timestamp, blocked_until = pipe.execute()
    
    current_time = time.time()
    
    # Check if in cooldown period
    if blocked_until and float(blocked_until) > current_time:
        # IP is blocked, calculate remaining time
        remaining = int(float(blocked_until) - current_time)
        return True, remaining
        
    # Initialize if this is the first request
    if not count:
        pipe.set(f"{key}:count", 1)
        pipe.set(f"{key}:first", current_time)
        pipe.expire(f"{key}:count", REGISTRATION_WINDOW)
        pipe.expire(f"{key}:first", REGISTRATION_WINDOW)
        pipe.execute()
        return False, 0
    
    # Check if window has expired
    if first_timestamp and float(first_timestamp) + REGISTRATION_WINDOW < current_time:
        # Reset counters
        pipe.set(f"{key}:count", 1)
        pipe.set(f"{key}:first", current_time)
        pipe.expire(f"{key}:count", REGISTRATION_WINDOW)
        pipe.expire(f"{key}:first", REGISTRATION_WINDOW)
        pipe.execute()
        return False, 0
    
    # Increment count and check against limit
    count = int(count)
    if count >= MAX_REGISTRATION_ATTEMPTS:
        # Too many attempts, set cooldown period
        RATE_LIMIT_REDIS.set(f"{key}:blocked_until", current_time + COOLDOWN_PERIOD)
        RATE_LIMIT_REDIS.expire(f"{key}:blocked_until", COOLDOWN_PERIOD)
        return True, COOLDOWN_PERIOD
    
    # Increment attempt counter
    RATE_LIMIT_REDIS.incr(f"{key}:count")
    
    # Calculate delay for exponential backoff
    if count > 1:
        delay = min(2 ** (count - 1), 30)  # Max delay of 30 seconds
        return False, delay
    
    return False, 0

def rate_limit(key_prefix):
    """Decorator to rate limit a route."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            is_limited, delay = is_rate_limited(key_prefix)
            
            if is_limited:
                # IP is in cooldown period
                return render_template(
                    "auth/_partials/rate_limited.html", 
                    cooldown_minutes=int(delay / 60)
                ), 429
            
            if delay > 0:
                # Apply exponential backoff
                time.sleep(delay)
                
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def verify_recaptcha(response):
    """Verify a reCAPTCHA response."""
    # Skip verification in development if no key is provided
    if not response:
        return False
        
    data = {
        'secret': CAPTCHA_SECRET_KEY,
        'response': response
    }
    
    r = requests.post(
        'https://www.google.com/recaptcha/api/siteverify',
        data=data
    )
    
    result = r.json()
    return result.get('success', False)