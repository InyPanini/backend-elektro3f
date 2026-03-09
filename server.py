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

class UserCreate(BaseModel):
    email: EmailStr
    name: str
    password: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

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
    safe_password = str(password)[:71]
    return pwd_context.hash(safe_password)

# ==================== SEED ADMIN ACCOUNTS ====================

async def seed_admin_accounts():
    try:
        admin_accounts = [
            {"email": "info@elektro3f.it", "name": "Admin Info"},
            {"email": "elektro3fbz@gmail.com", "name": "Admin BZ"}
        ]
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
    # Qui c'era l'errore della parentesi, ora è sistemato:
    await db.users.create_index("email", unique=True)
    await db.users.create_index("id", unique=True)
    logger.info("Database pronto e sistema online")

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

@api_router.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}

app.include_router(api_router)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
