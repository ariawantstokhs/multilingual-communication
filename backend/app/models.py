from datetime import datetime
from typing import Optional
from pydantic import BaseModel, EmailStr

class User(BaseModel):
    username: str
    password_hash: str
    preferred_language: str  # 'en', 'ko', 'es', 'ur'
    created_at: Optional[datetime] = None
    last_login: Optional[datetime] = None

class UserCreate(BaseModel):
    username: str
    password: str
    preferred_language: str = 'en'

class UserLogin(BaseModel):
    username: str
    password: str

class UserResponse(BaseModel):
    username: str
    preferred_language: str
    created_at: Optional[datetime] = None
    last_login: Optional[datetime] = None

class Message(BaseModel):
    sender: str
    timestamp: datetime
    original_text: str
    original_language: str
    text_en: str
    text_ko: str
    text_es: str
    text_ur: str

class LabAccessRequest(BaseModel):
    password: str

class TranslationProfile(BaseModel):
    username: str
    profile_name: str
    sample_texts: list[str]  # 3-5 sample texts showing user's writing style
    target_language: str  # Language to personalize (en, ko, es, ur)
    created_at: Optional[datetime] = None
    is_active: bool = False

class ProfileCreate(BaseModel):
    profile_name: str
    sample_texts: list[str]
    target_language: str

class ProfileResponse(BaseModel):
    profile_name: str
    sample_texts: list[str]
    target_language: str
    created_at: Optional[datetime] = None
    is_active: bool = False
