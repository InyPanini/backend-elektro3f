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
mongo_url = os.environ.get('MONGO_URL')
db_name = os.environ.get('DB_NAME')

if not mongo_url or not db_name:
    raise RuntimeError("MONGO_URL or DB_NAME environment variables are missing!")

client = AsyncIOMotorClient(mongo_url)
db = client[db_name]

# JWT Config
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

# ==================== HELPER FUNCTIONS ====================

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except Exception:
        return False

def hash_password(password: str) -> str:
    # Forza la password a stringa e tronca se necessario per sicurezza bcrypt
    safe_password = str(password)[:71]
    return pwd_context.hash(safe_password)

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

# ==================== SEED ADMIN ACCOUNTS ====================

async def seed_admin_accounts():
    try:
        admin_accounts = [
            {"email": "info@elektro3f.it", "name": "Admin Info"},
            {"email": "elektro3fbz@gmail.com", "name": "Admin BZ"}
        ]
        # Password di default sicura e corta
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
                logger.info(f"Account admin creato: {admin['email']}")
            else:
                logger.info(f"Admin già presente: {admin['email']}")
    except Exception as e:
        logger.error(f"Errore durante il seeding: {e}")

@app.on_event("startup")
async def startup_event():
    await seed_admin_accounts()
    await db.users.create_index("email",
