import os
import time
from datetime import datetime, timedelta
from typing import Optional, Dict, Any

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field, EmailStr, ConfigDict
from jose import JWTError, jwt
from passlib.context import CryptContext
from dotenv import load_dotenv
from fastapi.responses import JSONResponse

# NOTE: Using pymongo (sync) for simplicity and compatibility with the existing requirements file set.
from pymongo import MongoClient, ReturnDocument
from bson import ObjectId

# Load environment variables
load_dotenv()

# App metadata and tags for OpenAPI
app = FastAPI(
    title="Signup Backend API",
    description="REST APIs for multi-step signup, authentication, and onboarding tracking. Includes JWT-based auth and placeholders for social login.",
    version="1.0.0",
    openapi_tags=[
        {"name": "Health", "description": "Health check for service monitoring."},
        {"name": "Auth", "description": "User registration, login, tokens, and social sign-in placeholders."},
        {"name": "Onboarding", "description": "Multi-step onboarding progress tracking."},
    ],
)

# CORS (adjust as needed via environment variables)
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ALLOW_ORIGINS", "*").split(",") if os.getenv("CORS_ALLOW_ORIGINS") else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# SECURITY AND CONFIG
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "CHANGE_ME_IN_ENV")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
JWT_ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", "60"))

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
bearer_scheme = HTTPBearer(auto_error=False)

# DATABASE CONFIG
MONGODB_URL = os.getenv("MONGODB_URL")
MONGODB_DB = os.getenv("MONGODB_DB")

if not MONGODB_URL or not MONGODB_DB:
    # We do not raise at import time to avoid breaking docs; we will raise on first DB usage with a clear message.
    pass

mongo_client: Optional[MongoClient] = None
db = None
users_col = None

def _connect_db():
    global mongo_client, db, users_col
    if mongo_client is None:
        if not MONGODB_URL or not MONGODB_DB:
            raise RuntimeError("Missing MongoDB configuration. Please set MONGODB_URL and MONGODB_DB in the .env file.")
        mongo_client = MongoClient(MONGODB_URL)
        db = mongo_client[MONGODB_DB]
        users_col = db["users"]
    return users_col

# HELPERS
def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(password: str, hashed: str) -> bool:
    return pwd_context.verify(password, hashed)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta if expires_delta else timedelta(minutes=JWT_ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

def decode_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")

def get_current_user(credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme)) -> dict:
    """
    Dependency to retrieve current user from Authorization: Bearer <token>.
    """
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    token = credentials.credentials
    payload = decode_token(token)
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload")
    col = _connect_db()
    user = col.find_one({"_id": ObjectId(user_id)})
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    return user

# Pydantic Models
class TokenResponse(BaseModel):
    access_token: str = Field(..., description="JWT bearer access token")
    token_type: str = Field("bearer", description="Token type")

class RegisterRequest(BaseModel):
    email: EmailStr = Field(..., description="User email")
    password: str = Field(..., min_length=8, description="Password (min 8 chars)")
    full_name: Optional[str] = Field(None, description="User full name, optional")

class LoginRequest(BaseModel):
    email: EmailStr = Field(..., description="User email")
    password: str = Field(..., description="Password")

class SocialSignInRequest(BaseModel):
    provider: str = Field(..., description="Social provider identifier, e.g., google, apple")
    id_token: Optional[str] = Field(None, description="ID Token issued by the provider")
    access_token: Optional[str] = Field(None, description="Access token issued by the provider")
    # In a real system, you'd verify this token with the provider's certs.

class OnboardingStepUpdate(BaseModel):
    step: str = Field(..., description="Onboarding step key, e.g., 'profile', 'preferences', 'verification'")
    status: str = Field(..., description="Status value for the step, e.g., 'pending' | 'completed' | 'skipped'")
    data: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Arbitrary data captured for this step")

class UserPublic(BaseModel):
    id: str = Field(..., description="User ID")
    email: EmailStr = Field(..., description="User email")
    full_name: Optional[str] = Field(None, description="Full name")
    onboarding: Dict[str, Any] = Field(default_factory=dict, description="Onboarding progress map")

    model_config = ConfigDict(from_attributes=True)

def _user_to_public(user_doc: dict) -> UserPublic:
    return UserPublic(
        id=str(user_doc["_id"]),
        email=user_doc["email"],
        full_name=user_doc.get("full_name"),
        onboarding=user_doc.get("onboarding", {}),
    )

# ROUTES

# PUBLIC_INTERFACE
@app.get("/", tags=["Health"], summary="Health Check")
def health_check():
    """Simple health check endpoint."""
    return {"message": "Healthy", "ts": int(time.time())}

# PUBLIC_INTERFACE
@app.post("/auth/register", response_model=UserPublic, tags=["Auth"], summary="Register a new user")
def register_user(payload: RegisterRequest):
    """
    Create a new user with email/password. Password is hashed before storage.

    Request body:
    - email: Email
    - password: String, min 8 chars
    - full_name: Optional

    Returns:
    - UserPublic (id, email, full_name, onboarding)
    """
    col = _connect_db()
    existing = col.find_one({"email": payload.email.lower()})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    user_doc = {
        "email": payload.email.lower(),
        "password_hash": hash_password(payload.password),
        "full_name": payload.full_name,
        "onboarding": {
            # Define initial onboarding steps and statuses as needed
            "profile": {"status": "pending", "data": {}},
            "preferences": {"status": "pending", "data": {}},
            "verification": {"status": "pending", "data": {}},
        },
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow(),
        "auth_provider": "password",
    }
    result = col.insert_one(user_doc)
    user_doc["_id"] = result.inserted_id
    return _user_to_public(user_doc)

# PUBLIC_INTERFACE
@app.post("/auth/login", response_model=TokenResponse, tags=["Auth"], summary="Login with email and password")
def login_user(payload: LoginRequest):
    """
    Authenticate a user using email and password and return a JWT token.

    Request body:
    - email: Email
    - password: String

    Returns:
    - TokenResponse with access_token (JWT) and token_type=bearer
    """
    col = _connect_db()
    user = col.find_one({"email": payload.email.lower()})
    if not user or not verify_password(payload.password, user.get("password_hash", "")):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    token = create_access_token({"sub": str(user["_id"]), "email": user["email"]})
    return TokenResponse(access_token=token)

# PUBLIC_INTERFACE
@app.get("/auth/me", response_model=UserPublic, tags=["Auth"], summary="Get current user profile")
def get_me(current_user: dict = Depends(get_current_user)):
    """
    Get the profile of the currently authenticated user.

    Authorization:
    - Bearer token is required

    Returns:
    - UserPublic
    """
    return _user_to_public(current_user)

# PUBLIC_INTERFACE
@app.post("/auth/social", response_model=TokenResponse, tags=["Auth"], summary="Social sign-in (Google/Apple placeholder)")
def social_sign_in(payload: SocialSignInRequest):
    """
    Social sign-in endpoint placeholder. In production, verify the id_token/access_token with the provider
    (Google/Apple) using their public keys. If valid, upsert a user, then return a JWT.

    Request body:
    - provider: 'google' | 'apple'
    - id_token or access_token: Provided by the social provider

    Returns:
    - TokenResponse with access_token (JWT)
    """
    if payload.provider not in ("google", "apple"):
        raise HTTPException(status_code=400, detail="Unsupported provider")

    # IMPORTANT: This is a simplified placeholder.
    # You should validate the token with Google's or Apple's verification endpoints and extract a verified email.
    # For now, we accept an email-like id within id_token/access_token for demo.
    fake_email = None
    if payload.id_token and "@" in payload.id_token:
        fake_email = payload.id_token.lower()
    elif payload.access_token and "@" in payload.access_token:
        fake_email = payload.access_token.lower()

    if not fake_email:
        raise HTTPException(status_code=400, detail="Unable to infer email from social token (placeholder validation).")

    col = _connect_db()
    user = col.find_one({"email": fake_email})
    if not user:
        # Create new social user
        doc = {
            "email": fake_email,
            "password_hash": None,
            "full_name": None,
            "onboarding": {
                "profile": {"status": "pending", "data": {}},
                "preferences": {"status": "pending", "data": {}},
                "verification": {"status": "pending", "data": {}},
            },
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow(),
            "auth_provider": payload.provider,
        }
        res = col.insert_one(doc)
        doc["_id"] = res.inserted_id
        user = doc
    token = create_access_token({"sub": str(user["_id"]), "email": user["email"], "provider": user.get("auth_provider")})
    return TokenResponse(access_token=token)

# PUBLIC_INTERFACE
@app.get("/onboarding/progress", response_model=Dict[str, Any], tags=["Onboarding"], summary="Get onboarding progress")
def get_onboarding_progress(current_user: dict = Depends(get_current_user)):
    """
    Retrieve current user's onboarding progress map.

    Returns:
    - Onboarding progress as a dict: { step: {status, data}, ... }
    """
    return current_user.get("onboarding", {})

# PUBLIC_INTERFACE
@app.post("/onboarding/step", response_model=Dict[str, Any], tags=["Onboarding"], summary="Update an onboarding step")
def update_onboarding_step(update: OnboardingStepUpdate, current_user: dict = Depends(get_current_user)):
    """
    Update a specific onboarding step with status and optional data.

    Request body:
    - step: Step key (e.g., 'profile', 'preferences', 'verification')
    - status: 'pending' | 'completed' | 'skipped'
    - data: Optional dict of data captured in the step

    Returns:
    - Updated onboarding map
    """
    if update.status not in ("pending", "completed", "skipped"):
        raise HTTPException(status_code=400, detail="Invalid status value")

    col = _connect_db()
    onboarding = current_user.get("onboarding", {})
    step = onboarding.get(update.step, {"status": "pending", "data": {}})
    step["status"] = update.status
    if update.data:
        step["data"] = update.data
    onboarding[update.step] = step

    updated = col.find_one_and_update(
        {"_id": current_user["_id"]},
        {"$set": {"onboarding": onboarding, "updated_at": datetime.utcnow()}},
        return_document=ReturnDocument.AFTER,
    )
    return updated.get("onboarding", {})

# PUBLIC_INTERFACE
@app.get("/docs/websocket-usage", tags=["Health"], summary="WebSocket usage note")
def websocket_usage_note():
    """
    Usage note for real-time connections.

    This project currently does not expose WebSocket endpoints. If you add one for real-time onboarding updates,
    please document it here and register it in the OpenAPI schema with tags and operation_id.
    """
    return JSONResponse(
        {
            "message": "No WebSocket endpoints currently. Add FastAPI WebSocket routes here if needed.",
            "websocket_example": "wss://your-host/ws",
        }
    )

