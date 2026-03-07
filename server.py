from fastapi import FastAPI, APIRouter, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, EmailStr
from typing import List, Optional
import uuid
from datetime import datetime, timedelta
import jwt
from passlib.context import CryptContext
import base64

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# JWT Config - Usiamo una chiave più corta per evitare errori di buffer
SECRET_KEY = os.environ.get('JWT_SECRET', 'elektro3f-secret-2026')
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_HOURS = 24

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Create the main app
app = FastAPI()

# ==================== CONFIGURAZIONE CORS ====================
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://frontend-elektro3-iny-paninis-projects.vercel.app",
        "https://frontend-elektro3.vercel.app",
        "http://localhost:19006",
        "http://localhost:8081",
        "*"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

api_router = APIRouter(prefix="/api")
security = HTTPBearer()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ==================== MODELS ====================

class UserBase(BaseModel):
    email: EmailStr
    name: str
    role: str = "employee"
    profile_picture: Optional[str] = None
    language: str = "it"

class UserCreate(BaseModel):
    email: EmailStr
    name: str
    password: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class UserResponse(BaseModel):
    id: str
    email: str
    name: str
    role: str
    profile_picture: Optional[str] = None
    language: str
    created_at: datetime

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse

class ShiftAction(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    action_type: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    address: Optional[str] = None
    notes: Optional[str] = None

class ShiftActionCreate(BaseModel):
    action_type: str
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    address: Optional[str] = None
    notes: Optional[str] = None

# ==================== HELPER FUNCTIONS ====================

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        token = credentials.credentials
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        user = await db.users.find_one({"id": user_id})
        if user is None:
            raise HTTPException(status_code=401, detail="User not found")
        return user
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

async def get_admin_user(current_user: dict = Depends(get_current_user)):
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user

# ==================== SEED ADMIN ACCOUNTS ====================

async def seed_admin_accounts():
    admin_accounts = [
        {"email": "info@elektro3f.it", "name": "Admin Info"},
        {"email": "elektro3fbz@gmail.com", "name": "Admin BZ"}
    ]
    # MODIFICA CHIRURGICA: Password più corta e senza simboli per evitare i 72 byte
    default_password = "Elektro2026" 
    
    for admin in admin_accounts:
        existing = await db.users.find_one({"email": admin["email"]})
        if not existing:
            user_data = {
                "id": str(uuid.uuid4()),
                "email": admin["email"],
                "name": admin["name"],
                "password": hash_password(default_password),
                "role": "admin",
                "profile_picture": None,
                "language": "it",
                "created_at": datetime.utcnow()
            }
            await db.users.insert_one(user_data)
            logger.info(f"Created admin account: {admin['email']}")

@app.on_event("startup")
async def startup_event():
    await seed_admin_accounts()
    await db.users.create_index("email", unique=True)
    await db.users.create_index("id", unique=True)
    logger.info("Database indexes created and system ready")

# ==================== AUTH ROUTES ====================

@api_router.post("/auth/register", response_model=TokenResponse)
async def register(user: UserCreate):
    existing = await db.users.find_one({"email": user.email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    user_data = {
        "id": str(uuid.uuid4()),
        "email": user.email,
        "name": user.name,
        "password": hash_password(user.password),
        "role": "employee",
        "profile_picture": None,
        "language": "it",
        "created_at": datetime.utcnow()
    }
    await db.users.insert_one(user_data)
    token = create_access_token({"sub": user_data["id"]})
    return TokenResponse(
        access_token=token, 
        user=UserResponse(
            id=user_data["id"],
            email=user_data["email"],
            name=user_data["name"],
            role=user_data["role"],
            language=user_data["language"],
            created_at=user_data["created_at"]
        )
    )

@api_router.post("/auth/login", response_model=TokenResponse)
async def login(credentials: UserLogin):
    user = await db.users.find_one({"email": credentials.email})
    if not user or not verify_password(credentials.password, user["password"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    token = create_access_token({"sub": user["id"]})
    return TokenResponse(
        access_token=token, 
        user=UserResponse(
            id=user["id"], 
            email=user["email"], 
            name=user["name"], 
            role=user["role"], 
            profile_picture=user.get("profile_picture"), 
            language=user.get("language", "it"), 
            created_at=user["created_at"]
        )
    )

# ==================== HEALTH CHECK ====================

@api_router.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}

app.include_router(api_router)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()