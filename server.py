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

# JWT Config
SECRET_KEY = os.environ.get('JWT_SECRET', 'elektro3f-super-secret-key-2025')
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_HOURS = 24

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Create the main app
app = FastAPI()
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
    role: str = "employee"  # "admin" or "employee"
    profile_picture: Optional[str] = None
    language: str = "it"  # Default Italian

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
    action_type: str  # "start", "end", "pause_start", "pause_end"
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

class DailyShiftSummary(BaseModel):
    date: str
    user_id: str
    user_name: str
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    breaks: List[dict] = []
    total_work_minutes: int = 0
    total_break_minutes: int = 0
    notes: Optional[str] = None
    start_location: Optional[dict] = None
    end_location: Optional[dict] = None

class MonthlyReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    user_name: str
    month: int
    year: int
    total_hours: float
    days_worked: int
    daily_summaries: List[dict]
    employee_signature: Optional[str] = None
    employee_signed_at: Optional[datetime] = None
    admin_signature: Optional[str] = None
    admin_signed_at: Optional[datetime] = None
    admin_id: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)

class SignatureSubmit(BaseModel):
    signature: str  # base64 encoded signature

class PasswordResetRequest(BaseModel):
    email: EmailStr

class PasswordResetConfirm(BaseModel):
    email: EmailStr
    reset_code: str
    new_password: str

class ProfileUpdate(BaseModel):
    name: Optional[str] = None
    language: Optional[str] = None
    profile_picture: Optional[str] = None

class PasswordChange(BaseModel):
    current_password: str
    new_password: str

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
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

async def get_admin_user(current_user: dict = Depends(get_current_user)):
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user

# ==================== SEED ADMIN ACCOUNTS ====================

async def seed_admin_accounts():
    """Create pre-defined admin accounts if they don't exist"""
    admin_accounts = [
        {"email": "info@elektro3f.it", "name": "Admin Info"},
        {"email": "elektro3fbz@gmail.com", "name": "Admin BZ"}
    ]
    default_password = "Elektro3F2026!"
    
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
    # Create indexes
    await db.users.create_index("email", unique=True)
    await db.users.create_index("id", unique=True)
    await db.shift_actions.create_index("user_id")
    await db.shift_actions.create_index("timestamp")
    await db.monthly_reports.create_index([("user_id", 1), ("month", 1), ("year", 1)])
    logger.info("Database indexes created")

# ==================== AUTH ROUTES ====================

@api_router.post("/auth/register", response_model=TokenResponse)
async def register(user: UserCreate):
    """Register a new employee account"""
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
            profile_picture=user_data["profile_picture"],
            language=user_data["language"],
            created_at=user_data["created_at"]
        )
    )

@api_router.post("/auth/login", response_model=TokenResponse)
async def login(credentials: UserLogin):
    """Login with email and password"""
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

@api_router.post("/auth/forgot-password")
async def forgot_password(request: PasswordResetRequest):
    """Request password reset (MOCKED - no actual email sent)"""
    user = await db.users.find_one({"email": request.email})
    if not user:
        # Don't reveal if email exists
        return {"message": "If an account exists with this email, a reset code has been sent"}
    
    # Generate reset code (in production, this would be sent via email)
    reset_code = str(uuid.uuid4())[:8].upper()
    await db.password_resets.update_one(
        {"email": request.email},
        {"$set": {"code": reset_code, "created_at": datetime.utcnow()}},
        upsert=True
    )
    
    # MOCKED: Return the code directly (in production, send via email)
    return {
        "message": "Reset code generated (MOCKED - in production this would be sent via email)",
        "reset_code": reset_code  # ONLY for demo purposes
    }

@api_router.post("/auth/reset-password")
async def reset_password(request: PasswordResetConfirm):
    """Confirm password reset with code"""
    reset_record = await db.password_resets.find_one({"email": request.email})
    if not reset_record or reset_record["code"] != request.reset_code:
        raise HTTPException(status_code=400, detail="Invalid reset code")
    
    # Check if code is expired (30 minutes)
    if datetime.utcnow() - reset_record["created_at"] > timedelta(minutes=30):
        raise HTTPException(status_code=400, detail="Reset code expired")
    
    # Update password
    await db.users.update_one(
        {"email": request.email},
        {"$set": {"password": hash_password(request.new_password)}}
    )
    await db.password_resets.delete_one({"email": request.email})
    
    return {"message": "Password updated successfully"}

# ==================== USER ROUTES ====================

@api_router.get("/users/me", response_model=UserResponse)
async def get_me(current_user: dict = Depends(get_current_user)):
    """Get current user profile"""
    return UserResponse(
        id=current_user["id"],
        email=current_user["email"],
        name=current_user["name"],
        role=current_user["role"],
        profile_picture=current_user.get("profile_picture"),
        language=current_user.get("language", "it"),
        created_at=current_user["created_at"]
    )

@api_router.put("/users/me", response_model=UserResponse)
async def update_profile(update: ProfileUpdate, current_user: dict = Depends(get_current_user)):
    """Update current user profile"""
    update_data = {}
    if update.name:
        update_data["name"] = update.name
    if update.language:
        update_data["language"] = update.language
    if update.profile_picture is not None:
        update_data["profile_picture"] = update.profile_picture
    
    if update_data:
        await db.users.update_one({"id": current_user["id"]}, {"$set": update_data})
    
    updated_user = await db.users.find_one({"id": current_user["id"]})
    return UserResponse(
        id=updated_user["id"],
        email=updated_user["email"],
        name=updated_user["name"],
        role=updated_user["role"],
        profile_picture=updated_user.get("profile_picture"),
        language=updated_user.get("language", "it"),
        created_at=updated_user["created_at"]
    )

@api_router.put("/users/me/password")
async def change_password(data: PasswordChange, current_user: dict = Depends(get_current_user)):
    """Change current user password"""
    if not verify_password(data.current_password, current_user["password"]):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    
    await db.users.update_one(
        {"id": current_user["id"]},
        {"$set": {"password": hash_password(data.new_password)}}
    )
    return {"message": "Password changed successfully"}

# ==================== SHIFT ROUTES ====================

@api_router.post("/shifts/action", response_model=ShiftAction)
async def record_shift_action(action: ShiftActionCreate, current_user: dict = Depends(get_current_user)):
    """Record a shift action (start, end, pause_start, pause_end)"""
    action_data = {
        "id": str(uuid.uuid4()),
        "user_id": current_user["id"],
        "action_type": action.action_type,
        "timestamp": datetime.utcnow(),
        "latitude": action.latitude,
        "longitude": action.longitude,
        "address": action.address,
        "notes": action.notes
    }
    await db.shift_actions.insert_one(action_data)
    return ShiftAction(**action_data)

@api_router.get("/shifts/today")
async def get_today_shifts(current_user: dict = Depends(get_current_user)):
    """Get today's shift actions for current user"""
    today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    today_end = today_start + timedelta(days=1)
    
    actions = await db.shift_actions.find({
        "user_id": current_user["id"],
        "timestamp": {"$gte": today_start, "$lt": today_end}
    }).sort("timestamp", 1).to_list(100)
    
    return [{**a, "_id": str(a["_id"])} for a in actions]

@api_router.get("/shifts/current-status")
async def get_current_shift_status(current_user: dict = Depends(get_current_user)):
    """Get current shift status (in_shift, on_break, etc.)"""
    today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    today_end = today_start + timedelta(days=1)
    
    actions = await db.shift_actions.find({
        "user_id": current_user["id"],
        "timestamp": {"$gte": today_start, "$lt": today_end}
    }).sort("timestamp", 1).to_list(100)
    
    status = {
        "in_shift": False,
        "on_break": False,
        "shift_started_at": None,
        "current_break_started_at": None,
        "actions": [{**a, "_id": str(a["_id"])} for a in actions]
    }
    
    for action in actions:
        if action["action_type"] == "start":
            status["in_shift"] = True
            status["shift_started_at"] = action["timestamp"].isoformat()
        elif action["action_type"] == "end":
            status["in_shift"] = False
            status["on_break"] = False
        elif action["action_type"] == "pause_start":
            status["on_break"] = True
            status["current_break_started_at"] = action["timestamp"].isoformat()
        elif action["action_type"] == "pause_end":
            status["on_break"] = False
            status["current_break_started_at"] = None
    
    return status

@api_router.get("/shifts/history")
async def get_shift_history(days: int = 30, current_user: dict = Depends(get_current_user)):
    """Get shift history for the past N days"""
    start_date = datetime.utcnow() - timedelta(days=days)
    
    actions = await db.shift_actions.find({
        "user_id": current_user["id"],
        "timestamp": {"$gte": start_date}
    }).sort("timestamp", -1).to_list(1000)
    
    # Group by date
    daily_data = {}
    for action in actions:
        date_key = action["timestamp"].strftime("%Y-%m-%d")
        if date_key not in daily_data:
            daily_data[date_key] = []
        daily_data[date_key].append({**action, "_id": str(action["_id"])})
    
    return daily_data

@api_router.get("/shifts/daily-summary/{date}")
async def get_daily_summary(date: str, current_user: dict = Depends(get_current_user)):
    """Get daily summary for a specific date"""
    try:
        target_date = datetime.strptime(date, "%Y-%m-%d")
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid date format. Use YYYY-MM-DD")
    
    day_start = target_date.replace(hour=0, minute=0, second=0, microsecond=0)
    day_end = day_start + timedelta(days=1)
    
    actions = await db.shift_actions.find({
        "user_id": current_user["id"],
        "timestamp": {"$gte": day_start, "$lt": day_end}
    }).sort("timestamp", 1).to_list(100)
    
    summary = {
        "date": date,
        "user_id": current_user["id"],
        "user_name": current_user["name"],
        "start_time": None,
        "end_time": None,
        "breaks": [],
        "total_work_minutes": 0,
        "total_break_minutes": 0,
        "notes": None,
        "start_location": None,
        "end_location": None,
        "actions": [{**a, "_id": str(a["_id"])} for a in actions]
    }
    
    current_break_start = None
    
    for action in actions:
        if action["action_type"] == "start":
            summary["start_time"] = action["timestamp"].isoformat()
            summary["start_location"] = {
                "latitude": action.get("latitude"),
                "longitude": action.get("longitude"),
                "address": action.get("address")
            }
        elif action["action_type"] == "end":
            summary["end_time"] = action["timestamp"].isoformat()
            summary["notes"] = action.get("notes")
            summary["end_location"] = {
                "latitude": action.get("latitude"),
                "longitude": action.get("longitude"),
                "address": action.get("address")
            }
        elif action["action_type"] == "pause_start":
            current_break_start = action["timestamp"]
        elif action["action_type"] == "pause_end" and current_break_start:
            break_minutes = int((action["timestamp"] - current_break_start).total_seconds() / 60)
            summary["breaks"].append({
                "start": current_break_start.isoformat(),
                "end": action["timestamp"].isoformat(),
                "minutes": break_minutes
            })
            summary["total_break_minutes"] += break_minutes
            current_break_start = None
    
    # Calculate total work time
    if summary["start_time"] and summary["end_time"]:
        start = datetime.fromisoformat(summary["start_time"])
        end = datetime.fromisoformat(summary["end_time"])
        total_minutes = int((end - start).total_seconds() / 60)
        summary["total_work_minutes"] = total_minutes - summary["total_break_minutes"]
    
    return summary

# ==================== MONTHLY REPORT ROUTES ====================

@api_router.get("/reports/monthly/{year}/{month}")
async def get_monthly_report(year: int, month: int, current_user: dict = Depends(get_current_user)):
    """Get or generate monthly report for current user"""
    # Check if report already exists
    existing_report = await db.monthly_reports.find_one({
        "user_id": current_user["id"],
        "month": month,
        "year": year
    })
    
    if existing_report:
        # Properly serialize the report
        serialized = {
            "id": existing_report["id"],
            "user_id": existing_report["user_id"],
            "user_name": existing_report["user_name"],
            "month": existing_report["month"],
            "year": existing_report["year"],
            "total_hours": existing_report["total_hours"],
            "days_worked": existing_report["days_worked"],
            "daily_summaries": existing_report["daily_summaries"],
            "employee_signature": existing_report.get("employee_signature"),
            "employee_signed_at": existing_report.get("employee_signed_at").isoformat() if existing_report.get("employee_signed_at") else None,
            "admin_signature": existing_report.get("admin_signature"),
            "admin_signed_at": existing_report.get("admin_signed_at").isoformat() if existing_report.get("admin_signed_at") else None,
            "admin_id": existing_report.get("admin_id"),
            "created_at": existing_report["created_at"].isoformat() if existing_report.get("created_at") else None
        }
        return serialized
    
    # Generate new report
    start_date = datetime(year, month, 1)
    if month == 12:
        end_date = datetime(year + 1, 1, 1)
    else:
        end_date = datetime(year, month + 1, 1)
    
    actions = await db.shift_actions.find({
        "user_id": current_user["id"],
        "timestamp": {"$gte": start_date, "$lt": end_date}
    }).sort("timestamp", 1).to_list(1000)
    
    # Group actions by day and calculate summaries
    daily_summaries = {}
    current_break_start = None
    
    for action in actions:
        date_key = action["timestamp"].strftime("%Y-%m-%d")
        if date_key not in daily_summaries:
            daily_summaries[date_key] = {
                "date": date_key,
                "start_time": None,
                "end_time": None,
                "breaks": [],
                "total_break_minutes": 0,
                "notes": None
            }
        
        summary = daily_summaries[date_key]
        
        if action["action_type"] == "start":
            summary["start_time"] = action["timestamp"].strftime("%H:%M")
        elif action["action_type"] == "end":
            summary["end_time"] = action["timestamp"].strftime("%H:%M")
            summary["notes"] = action.get("notes")
        elif action["action_type"] == "pause_start":
            current_break_start = action["timestamp"]
        elif action["action_type"] == "pause_end" and current_break_start:
            break_minutes = int((action["timestamp"] - current_break_start).total_seconds() / 60)
            summary["breaks"].append({
                "start": current_break_start.strftime("%H:%M"),
                "end": action["timestamp"].strftime("%H:%M"),
                "minutes": break_minutes
            })
            summary["total_break_minutes"] += break_minutes
            current_break_start = None
    
    # Calculate work hours for each day
    total_minutes = 0
    days_worked = 0
    
    for date_key, summary in daily_summaries.items():
        if summary["start_time"] and summary["end_time"]:
            start = datetime.strptime(f"{date_key} {summary['start_time']}", "%Y-%m-%d %H:%M")
            end = datetime.strptime(f"{date_key} {summary['end_time']}", "%Y-%m-%d %H:%M")
            day_minutes = int((end - start).total_seconds() / 60) - summary["total_break_minutes"]
            summary["work_minutes"] = max(0, day_minutes)
            summary["work_hours"] = round(day_minutes / 60, 2)
            total_minutes += day_minutes
            days_worked += 1
    
    report = {
        "id": str(uuid.uuid4()),
        "user_id": current_user["id"],
        "user_name": current_user["name"],
        "month": month,
        "year": year,
        "total_hours": round(total_minutes / 60, 2),
        "days_worked": days_worked,
        "daily_summaries": list(daily_summaries.values()),
        "employee_signature": None,
        "employee_signed_at": None,
        "admin_signature": None,
        "admin_signed_at": None,
        "admin_id": None,
        "created_at": datetime.utcnow()
    }
    
    await db.monthly_reports.insert_one(report)
    
    # Return with serialized datetime
    return {
        **report,
        "created_at": report["created_at"].isoformat()
    }

@api_router.post("/reports/monthly/{year}/{month}/sign")
async def sign_monthly_report(year: int, month: int, signature: SignatureSubmit, current_user: dict = Depends(get_current_user)):
    """Employee signs their monthly report"""
    report = await db.monthly_reports.find_one({
        "user_id": current_user["id"],
        "month": month,
        "year": year
    })
    
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    
    await db.monthly_reports.update_one(
        {"id": report["id"]},
        {"$set": {
            "employee_signature": signature.signature,
            "employee_signed_at": datetime.utcnow()
        }}
    )
    
    return {"message": "Report signed successfully"}

# ==================== ADMIN ROUTES ====================

@api_router.get("/admin/employees")
async def get_all_employees(admin: dict = Depends(get_admin_user)):
    """Get all employees (admin only)"""
    employees = await db.users.find({"role": "employee"}).to_list(1000)
    return [
        {
            "id": e["id"],
            "email": e["email"],
            "name": e["name"],
            "profile_picture": e.get("profile_picture"),
            "created_at": e["created_at"].isoformat()
        }
        for e in employees
    ]

@api_router.get("/admin/employees/{employee_id}/shifts")
async def get_employee_shifts(employee_id: str, days: int = 30, admin: dict = Depends(get_admin_user)):
    """Get employee shift history (admin only)"""
    start_date = datetime.utcnow() - timedelta(days=days)
    
    actions = await db.shift_actions.find({
        "user_id": employee_id,
        "timestamp": {"$gte": start_date}
    }).sort("timestamp", -1).to_list(1000)
    
    return [{**a, "_id": str(a["_id"])} for a in actions]

@api_router.get("/admin/employees/{employee_id}/locations")
async def get_employee_locations(employee_id: str, date: str = None, admin: dict = Depends(get_admin_user)):
    """Get employee GPS locations for a specific date (admin only)"""
    if date:
        try:
            target_date = datetime.strptime(date, "%Y-%m-%d")
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid date format")
        day_start = target_date.replace(hour=0, minute=0, second=0, microsecond=0)
        day_end = day_start + timedelta(days=1)
        query = {"user_id": employee_id, "timestamp": {"$gte": day_start, "$lt": day_end}}
    else:
        query = {"user_id": employee_id}
    
    actions = await db.shift_actions.find(query).sort("timestamp", -1).to_list(100)
    
    locations = []
    for action in actions:
        if action.get("latitude") and action.get("longitude"):
            locations.append({
                "action_type": action["action_type"],
                "timestamp": action["timestamp"].isoformat(),
                "latitude": action["latitude"],
                "longitude": action["longitude"],
                "address": action.get("address")
            })
    
    return locations

@api_router.get("/admin/reports/unsigned")
async def get_unsigned_reports(admin: dict = Depends(get_admin_user)):
    """Get all reports pending admin signature"""
    reports = await db.monthly_reports.find({
        "employee_signature": {"$ne": None},
        "admin_signature": None
    }).to_list(100)
    
    result = []
    for report in reports:
        user = await db.users.find_one({"id": report["user_id"]})
        result.append({
            **report,
            "_id": str(report["_id"]),
            "user_email": user["email"] if user else None
        })
    
    return result

@api_router.get("/admin/reports/{report_id}")
async def get_report_details(report_id: str, admin: dict = Depends(get_admin_user)):
    """Get specific report details (admin only)"""
    report = await db.monthly_reports.find_one({"id": report_id})
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    
    user = await db.users.find_one({"id": report["user_id"]})
    return {
        **report,
        "_id": str(report["_id"]),
        "user_email": user["email"] if user else None
    }

@api_router.post("/admin/reports/{report_id}/countersign")
async def countersign_report(report_id: str, signature: SignatureSubmit, admin: dict = Depends(get_admin_user)):
    """Admin counter-signs an employee's monthly report"""
    report = await db.monthly_reports.find_one({"id": report_id})
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    
    if not report.get("employee_signature"):
        raise HTTPException(status_code=400, detail="Employee must sign first")
    
    await db.monthly_reports.update_one(
        {"id": report_id},
        {"$set": {
            "admin_signature": signature.signature,
            "admin_signed_at": datetime.utcnow(),
            "admin_id": admin["id"]
        }}
    )
    
    return {"message": "Report counter-signed successfully"}

@api_router.get("/admin/today-activity")
async def get_today_activity(admin: dict = Depends(get_admin_user)):
    """Get today's activity across all employees"""
    today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    today_end = today_start + timedelta(days=1)
    
    actions = await db.shift_actions.find({
        "timestamp": {"$gte": today_start, "$lt": today_end}
    }).sort("timestamp", -1).to_list(1000)
    
    # Group by user
    user_activity = {}
    for action in actions:
        user_id = action["user_id"]
        if user_id not in user_activity:
            user = await db.users.find_one({"id": user_id})
            user_activity[user_id] = {
                "user_id": user_id,
                "user_name": user["name"] if user else "Unknown",
                "user_email": user["email"] if user else "Unknown",
                "actions": []
            }
        user_activity[user_id]["actions"].append({
            **action,
            "_id": str(action["_id"])
        })
    
    return list(user_activity.values())

# ==================== HEALTH CHECK ====================

@api_router.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}

# Include router
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
