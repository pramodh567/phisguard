from datetime import datetime, timedelta, timezone
from jose import jwt, JWTError
import bcrypt

# In production, replace this with a secure random string (e.g., from `openssl rand -hex 32`)
SECRET_KEY = "phishguard-super-secret-development-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # Tokens last 1 week

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies a plain password against the hashed version in the database."""
    # bcrypt requires bytes, so we encode the strings to utf-8 first
    return bcrypt.checkpw(
        plain_password.encode('utf-8'), 
        hashed_password.encode('utf-8')
    )

def get_password_hash(password: str) -> str:
    """Hashes a password securely using bcrypt."""
    salt = bcrypt.gensalt()
    hashed_bytes = bcrypt.hashpw(password.encode('utf-8'), salt)
    # Decode back to a normal string so it can be saved in the database
    return hashed_bytes.decode('utf-8')

def create_access_token(data: dict) -> str:
    """Generates the JWT for authenticated sessions."""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    
    # Sign the token using our secret key
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt