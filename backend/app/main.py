from dotenv import load_dotenv, find_dotenv
load_dotenv(find_dotenv())

from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import socketio
import os
import bcrypt
import jwt

from .db import connect_to_mongo, close_mongo_connection, get_db
from .models import Message, User, UserCreate, UserLogin, UserResponse, LabAccessRequest, PostEditAnalysisRequest, PostEditAnalysisResult, TranslateWithAnalysisRequest, TranslateWithAnalysisResponse, PersonalProfileResponse
from .translation import translate_message, translate_with_profile
from .analysis import analyze_post_edits
from datetime import datetime, timedelta
from typing import Optional
import json

from datetime import datetime
from bson import ObjectId

def serialize_message_doc(doc):
    ts = doc.get("timestamp")
    ts_str = ts.isoformat() if isinstance(ts, datetime) else str(ts)
    return {
        "_id": str(doc.get("_id")) if doc.get("_id") else None,
        "sender": doc.get("sender"),
        "timestamp": ts_str,
        "original_text": doc.get("original_text"),
        "original_language": doc.get("original_language"),
        "text_en": doc.get("text_en"),
        "text_ko": doc.get("text_ko"),
        "text_es": doc.get("text_es"),
        "text_ur": doc.get("text_ur"),
    }

# JWT Configuration
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-change-this-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Lab Access Password
LAB_ACCESS_PASSWORD = os.getenv("LAB_ACCESS_PASSWORD", "cstl+northeastern2025")

# Initialize FastAPI app
app = FastAPI()

# Security
security = HTTPBearer()

# Authentication functions
def hash_password(password: str) -> str:
    """Hash a password using bcrypt."""
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')

def verify_password(password: str, hashed_password: str) -> bool:
    """Verify a password against its hash."""
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """Create a JWT access token."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Get the current user from JWT token."""
    try:
        token = credentials.credentials
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return username
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

# Initialize Socket.IO with wildcard CORS for development
sio = socketio.AsyncServer(
    async_mode='asgi',
    cors_allowed_origins="*",
    logger=True,
    engineio_logger=True
)
socket_app = socketio.ASGIApp(sio)

# CORS configuration
cors_origins = os.getenv("CORS_ORIGINS", "http://localhost:3000,http://localhost:3001").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount Socket.IO
app.mount("/socket.io", socket_app)

# Socket.IO event handlers
@sio.event
async def connect(sid, environ):
    print(f"Client {sid} connected")
    # try:
    db = get_db()
    messages_collection = db.messages
    # oldest -> newest
    docs = list(messages_collection.find().sort("timestamp", 1).limit(200))
    history = [serialize_message_doc(d) for d in docs]
    await sio.emit('message_history', history, room=sid)
    # except Exception as e:
    #     print(f"Error sending message history: {e}")

@sio.event
async def disconnect(sid):
    print(f"Client {sid} disconnected")

@sio.event
async def authenticate(sid, data):
    try:
        token = data.get('token')
        if not token:
            await sio.emit('auth_error', {'message': 'No token provided'}, room=sid)
            return

        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if not username:
            await sio.emit('auth_error', {'message': 'Invalid token'}, room=sid)
            return

        # 🔽 fetch user to grab preferred_language
        db = get_db()
        user = db.users.find_one({"username": username})
        preferred_language = (user or {}).get("preferred_language", "en")

        # 🔽 store both on the socket session
        await sio.save_session(sid, {
            'username': username,
            'preferred_language': preferred_language,
        })
        await sio.emit('auth_success', {'username': username}, room=sid)

    except jwt.PyJWTError:
        await sio.emit('auth_error', {'message': 'Invalid token'}, room=sid)
    except Exception as e:
        print(f"Authentication error: {e}")
        await sio.emit('auth_error', {'message': 'Authentication failed'}, room=sid)


@sio.event
async def send_message(sid, data):
    try:
        session = await sio.get_session(sid)
        username = session.get('username')
        user_lang = session.get('preferred_language', 'en')  # 🔽 from session

        if not username:
            await sio.emit('error', {'message': 'Not authenticated'}, room=sid)
            return

        db = get_db()
        messages_collection = db.messages
        profiles_collection = db.personal_profiles

        # Check if user has an active personal profile
        active_profile = profiles_collection.find_one({
            "username": username,
            "is_active": True
        })

        # Use personalized translation if profile exists and is active
        if active_profile and active_profile.get("analysis_count", 0) > 0:
            # Build profile data from observed patterns
            profile_data = {
                "observed_patterns": active_profile.get("observed_patterns", []),
                "user_priorities": active_profile.get("user_priorities", []),
                "change_motivations": active_profile.get("change_motivations", []),
                "profile_summary": active_profile.get("profile_summary", "")
            }

            # Translate to all languages using personal profile
            translations = {
                'text_en': translate_with_profile(data['text'], user_lang, profile_data, "en") if user_lang != "en" else data['text'],
                'text_ko': translate_with_profile(data['text'], user_lang, profile_data, "ko") if user_lang != "ko" else data['text'],
                'text_es': translate_with_profile(data['text'], user_lang, profile_data, "es") if user_lang != "es" else data['text'],
                'text_ur': translate_with_profile(data['text'], user_lang, profile_data, "ur") if user_lang != "ur" else data['text'],
            }
        else:
            translations = translate_message(data['text'], user_lang)

        message_doc = {
            'sender': username,
            'timestamp': datetime.utcnow(),
            'original_text': data['text'],
            'original_language': user_lang,  # 🔽 what you asked for
            'text_en': translations.get('text_en', data['text']),
            'text_ko': translations.get('text_ko', data['text']),
            'text_es': translations.get('text_es', data['text']),
            'text_ur': translations.get('text_ur', data['text']),
        }

        result = messages_collection.insert_one(message_doc)
        message_doc['_id'] = result.inserted_id
        await sio.emit('new_message', serialize_message_doc(message_doc))

    except Exception as e:
        import traceback
        print("Error handling message:", e)
        traceback.print_exc()
        await sio.emit('server_error', {'message': 'Failed to send message'}, room=sid)


# API endpoints
@app.get("/health")
async def health_check():
    """Health check endpoint for validating backend connectivity."""
    try:
        db = get_db()
        # Quick DB connection test
        db.command('ping')
        return {
            "status": "healthy",
            "service": "multilingual-chat-backend",
            "database": "connected"
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Service unhealthy: {str(e)}"
        )

@app.get("/")
async def root():
    return {"message": "Global Chat API is running"}

# Lab access verification endpoint
@app.post("/auth/verify-lab-access")
async def verify_lab_access(access_request: LabAccessRequest):
    """Verify lab access password."""
    if access_request.password == LAB_ACCESS_PASSWORD:
        return {"message": "Access granted", "success": True}
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid lab access password"
        )

# Authentication endpoints
@app.post("/auth/register", response_model=UserResponse)
async def register_user(user_data: UserCreate):
    """Register a new user."""
    try:
        db = get_db()
        users_collection = db.users
        
        # Check if user already exists
        existing_user = users_collection.find_one({"username": user_data.username})
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username already registered"
            )
        
        # Hash password and create user
        hashed_password = hash_password(user_data.password)
        user_doc = {
            "username": user_data.username,
            "password_hash": hashed_password,
            "preferred_language": user_data.preferred_language,
            "created_at": datetime.utcnow(),
            "last_login": None
        }
        
        result = users_collection.insert_one(user_doc)
        user_doc["_id"] = str(result.inserted_id)
        
        # Return user without password
        return UserResponse(
            username=user_doc["username"],
            preferred_language=user_doc["preferred_language"],
            created_at=user_doc["created_at"],
            last_login=user_doc["last_login"]
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Registration failed: {str(e)}"
        )

@app.post("/auth/login")
async def login_user(user_data: UserLogin):
    """Login user and return access token."""
    try:
        db = get_db()
        users_collection = db.users
        
        # Find user
        user = users_collection.find_one({"username": user_data.username})
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password"
            )
        
        # Verify password
        if not verify_password(user_data.password, user["password_hash"]):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password"
            )
        
        # Update last login
        users_collection.update_one(
            {"_id": user["_id"]},
            {"$set": {"last_login": datetime.utcnow()}}
        )
        
        # Create access token
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": user["username"]}, 
            expires_delta=access_token_expires
        )
        
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "user": UserResponse(
                username=user["username"],
                preferred_language=user["preferred_language"],
                created_at=user["created_at"],
                last_login=datetime.utcnow()
            )
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Login failed: {str(e)}"
        )

@app.get("/auth/me", response_model=UserResponse)
async def get_current_user_info(current_user: str = Depends(get_current_user)):
    """Get current user information."""
    try:
        db = get_db()
        users_collection = db.users

        user = users_collection.find_one({"username": current_user})
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )

        return UserResponse(
            username=user["username"],
            preferred_language=user["preferred_language"],
            created_at=user["created_at"],
            last_login=user["last_login"]
        )

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get user info: {str(e)}"
        )


# Post-Editing Analysis Endpoints
@app.post("/analysis/post-edits", response_model=PostEditAnalysisResult)
async def analyze_edits(
    request: PostEditAnalysisRequest,
    # current_user: str = Depends(get_current_user)
):
    """
    Analyze post-editing patterns between machine translation and user-edited version.

    Identifies user preferences and communication style from their editing behavior.
    """
    current_user = "default_user"  # Temporary: no auth
    try:
        # Perform post-editing analysis
        analysis_result = analyze_post_edits(
            mt_version=request.mt_version,
            edited_version=request.edited_version
        )

        # Save to database for future profile building
        db = get_db()
        post_edit_analyses_collection = db.post_edit_analyses

        analysis_doc = {
            "username": current_user,
            "mt_version": request.mt_version,
            "edited_version": request.edited_version,
            "analysis_result": analysis_result,
            "created_at": datetime.utcnow()
        }

        post_edit_analyses_collection.insert_one(analysis_doc)

        return PostEditAnalysisResult(**analysis_result)

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to analyze post-edits: {str(e)}"
        )


@app.post("/translation/with-analysis", response_model=TranslateWithAnalysisResponse)
async def translate_with_preferences(
    request: TranslateWithAnalysisRequest,
    # current_user: str = Depends(get_current_user)
):
    """
    Translate text while applying user preferences from post-edit analysis.

    Uses the preferences and style patterns from analysis to produce
    translations that match the user's communication style.
    """
    current_user = "default_user"  # Temporary: no auth
    try:
        # Default target language to English if not specified
        target_lang = request.post_edit_analysis.get("target_language", "en")

        translated_text = translate_with_profile(
            text=request.text,
            source_lang=request.source_lang,
            profile_data=request.post_edit_analysis,
            target_language=target_lang
        )

        return TranslateWithAnalysisResponse(
            translated_text=translated_text,
            target_language=target_lang,
            preferences_applied=True
        )

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to translate with preferences: {str(e)}"
        )


@app.get("/analysis/history")
async def get_analysis_history(
    # current_user: str = Depends(get_current_user),
    limit: int = 10
):
    """
    Get the user's post-editing analysis history.

    Returns past analyses that can be used for profile building or review.
    """
    current_user = "default_user"  # Temporary: no auth
    try:
        db = get_db()
        post_edit_analyses_collection = db.post_edit_analyses

        analyses = list(
            post_edit_analyses_collection.find({"username": current_user})
            .sort("created_at", -1)
            .limit(limit)
        )

        # Convert ObjectId to string for JSON serialization
        result = []
        for analysis in analyses:
            analysis["_id"] = str(analysis["_id"])
            analysis["created_at"] = analysis["created_at"].isoformat()
            result.append(analysis)

        return result

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve analysis history: {str(e)}"
        )


# Personal Profile Endpoints
@app.get("/profile/personal", response_model=PersonalProfileResponse)
async def get_personal_profile(
    # current_user: str = Depends(get_current_user)
):
    """
    Get the user's personal profile built from post-editing analyses.

    Aggregates preferences from all past analyses to build
    a comprehensive communication style profile.
    """
    current_user = "default_user"  # Temporary: no auth
    try:
        db = get_db()
        profiles_collection = db.personal_profiles

        # Check if profile already exists
        profile = profiles_collection.find_one({"username": current_user})

        if profile:
            return PersonalProfileResponse(
                observed_patterns=profile.get("observed_patterns", []),
                user_priorities=profile.get("user_priorities", []),
                change_motivations=profile.get("change_motivations", []),
                profile_summary=profile.get("profile_summary", ""),
                analysis_count=profile.get("analysis_count", 0),
                last_updated=profile.get("last_updated"),
                is_active=profile.get("is_active", True)
            )

        # Return empty profile if none exists
        return PersonalProfileResponse()

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get personal profile: {str(e)}"
        )


@app.post("/profile/build", response_model=PersonalProfileResponse)
async def build_personal_profile(
    # current_user: str = Depends(get_current_user)
):
    """
    Build or update personal profile from all post-editing analyses.

    Aggregates patterns from all past analyses to create a comprehensive
    communication style profile.
    """
    current_user = "default_user"  # Temporary: no auth
    try:
        db = get_db()
        post_edit_analyses_collection = db.post_edit_analyses
        profiles_collection = db.personal_profiles

        # Get all post-edit analyses for the user
        analyses = list(post_edit_analyses_collection.find({"username": current_user}))

        if not analyses:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No analyses found. Please analyze some translations first."
            )

        # Aggregate patterns from all analyses (exploratory approach)
        all_patterns = []
        all_priorities = []
        all_motivations = []
        all_implications = []

        for analysis in analyses:
            result = analysis.get("analysis_result", {})

            # Collect emerging patterns
            if result.get("emerging_patterns"):
                all_patterns.append(result["emerging_patterns"])

            # Collect user priorities
            if result.get("user_priorities"):
                all_priorities.append(result["user_priorities"])

            # Collect change motivations from observed changes
            for change in result.get("observed_changes", []):
                if isinstance(change, dict) and change.get("possible_motivation"):
                    all_motivations.append(change["possible_motivation"])

            # Collect implications
            if result.get("implications"):
                all_implications.append(result["implications"])

        # Keep unique patterns (limit to most recent/relevant)
        unique_patterns = list(dict.fromkeys(all_patterns))[:10]
        unique_priorities = list(dict.fromkeys(all_priorities))[:10]
        unique_motivations = list(dict.fromkeys(all_motivations))[:15]

        # Create aggregate summary
        profile_summary = f"Based on {len(analyses)} exploratory analyses: "

        if unique_patterns:
            profile_summary += f"Observed patterns include: {unique_patterns[0]}. "

        if unique_priorities:
            profile_summary += f"User priorities: {unique_priorities[0]}. "

        if all_implications:
            profile_summary += f"Implications: {all_implications[0]}"

        # Build profile document
        profile_doc = {
            "username": current_user,
            "observed_patterns": unique_patterns,
            "user_priorities": unique_priorities,
            "change_motivations": unique_motivations,
            "profile_summary": profile_summary.strip(),
            "analysis_count": len(analyses),
            "last_updated": datetime.utcnow(),
            "is_active": True
        }

        # Upsert the profile
        profiles_collection.update_one(
            {"username": current_user},
            {"$set": profile_doc},
            upsert=True
        )

        return PersonalProfileResponse(
            observed_patterns=profile_doc["observed_patterns"],
            user_priorities=profile_doc["user_priorities"],
            change_motivations=profile_doc["change_motivations"],
            profile_summary=profile_doc["profile_summary"],
            analysis_count=profile_doc["analysis_count"],
            last_updated=profile_doc["last_updated"],
            is_active=profile_doc["is_active"]
        )

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to build personal profile: {str(e)}"
        )


@app.put("/profile/toggle-active")
async def toggle_profile_active(
    # current_user: str = Depends(get_current_user)
):
    """Toggle the personal profile active state."""
    current_user = "default_user"  # Temporary: no auth
    try:
        db = get_db()
        profiles_collection = db.personal_profiles

        profile = profiles_collection.find_one({"username": current_user})
        if not profile:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No personal profile found"
            )

        new_state = not profile.get("is_active", True)
        profiles_collection.update_one(
            {"username": current_user},
            {"$set": {"is_active": new_state}}
        )

        return {"is_active": new_state, "message": f"Profile {'activated' if new_state else 'deactivated'}"}

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to toggle profile: {str(e)}"
        )


@app.delete("/profile/personal")
async def delete_personal_profile(
    # current_user: str = Depends(get_current_user)
):
    """
    Delete the user's personal profile and all analysis history.
    """
    current_user = "default_user"  # Temporary: no auth
    try:
        db = get_db()
        profiles_collection = db.personal_profiles
        post_edit_analyses_collection = db.post_edit_analyses

        # Delete profile
        profile_result = profiles_collection.delete_one({"username": current_user})

        # Delete all analysis history
        analyses_result = post_edit_analyses_collection.delete_many({"username": current_user})

        return {
            "message": "Profile and analysis history deleted successfully",
            "profile_deleted": profile_result.deleted_count > 0,
            "analyses_deleted": analyses_result.deleted_count
        }

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete profile: {str(e)}"
        )


# Anonymous Translation Endpoints (No Auth Required)
from pydantic import BaseModel
from typing import Dict, Any

class AnonymousTranslateRequest(BaseModel):
    text: str
    source_lang: str
    target_lang: str
    use_profile: bool = False
    profile_data: Optional[Dict[str, Any]] = None

class AnonymousTranslateResponse(BaseModel):
    translated_text: str
    source_lang: str
    target_lang: str
    used_profile: bool

class AnonymousGapAnalysisRequest(BaseModel):
    mt_version: str
    edited_version: str

@app.post("/translate", response_model=AnonymousTranslateResponse)
async def anonymous_translate(request: AnonymousTranslateRequest):
    """
    Translate text without authentication.
    Optionally uses a personal profile passed from client-side localStorage.
    """
    try:
        if request.use_profile and request.profile_data:
            # Use personalized translation with profile
            profile_data = {
                "observed_patterns": request.profile_data.get("observed_patterns", []),
                "user_priorities": request.profile_data.get("user_priorities", []),
                "change_motivations": request.profile_data.get("change_motivations", []),
                "profile_summary": request.profile_data.get("profile_summary", "")
            }
            translated_text = translate_with_profile(
                text=request.text,
                source_lang=request.source_lang,
                profile_data=profile_data,
                target_language=request.target_lang
            )
            used_profile = True
        else:
            # Standard translation
            translations = translate_message(request.text, request.source_lang)
            lang_key = f"text_{request.target_lang}"
            translated_text = translations.get(lang_key, request.text)
            used_profile = False

        return AnonymousTranslateResponse(
            translated_text=translated_text,
            source_lang=request.source_lang,
            target_lang=request.target_lang,
            used_profile=used_profile
        )

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Translation failed: {str(e)}"
        )


@app.post("/analyze", response_model=PostEditAnalysisResult)
async def anonymous_analyze_edits(request: AnonymousGapAnalysisRequest):
    """
    Analyze post-edits without authentication.
    Results are returned to client for localStorage storage.
    """
    try:
        analysis_result = analyze_post_edits(
            mt_version=request.mt_version,
            edited_version=request.edited_version
        )
        return PostEditAnalysisResult(**analysis_result)

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to analyze post-edits: {str(e)}"
        )

