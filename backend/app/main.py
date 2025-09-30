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
from .models import Message, User, UserCreate, UserLogin, UserResponse, LabAccessRequest
from .translation import translate_message
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

# Initialize Socket.IO
sio = socketio.AsyncServer(async_mode='asgi', cors_allowed_origins="*")
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

        # 🔽 translate using the user's preferred language as the source
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

