from datetime import datetime
from typing import Any, Optional
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


# Post-Editing Analysis Models (Based on Green et al. 2013)
class ObservedChange(BaseModel):
    """Individual change observed during post-editing analysis"""
    mt_text: str  # Original text from MT
    user_text: str  # User's edited version
    change_description: str  # Open description of what changed
    possible_motivation: str  # Why user might have made this change


class PostEditAnalysisRequest(BaseModel):
    mt_version: str
    edited_version: str


class PostEditAnalysisResult(BaseModel):
    observed_changes: list[ObservedChange] = []
    emerging_patterns: str = ""
    user_priorities: str = ""
    implications: str = ""


class TranslateWithAnalysisRequest(BaseModel):
    text: str
    source_lang: str = "ko"
    post_edit_analysis: dict[str, Any]


class TranslateWithAnalysisResponse(BaseModel):
    translated_text: str
    target_language: str
    preferences_applied: bool = True


# Personal Profile Models (built from post-editing analysis)
class PersonalProfile(BaseModel):
    username: str
    # Aggregated from exploratory analysis
    observed_patterns: list[str] = []  # Patterns that emerged across analyses
    user_priorities: list[str] = []  # What matters most to this user
    change_motivations: list[str] = []  # Common reasons for changes
    # Summary
    profile_summary: str = ""
    analysis_count: int = 0
    last_updated: Optional[datetime] = None
    is_active: bool = True


class PersonalProfileResponse(BaseModel):
    observed_patterns: list[str] = []
    user_priorities: list[str] = []
    change_motivations: list[str] = []
    profile_summary: str = ""
    analysis_count: int = 0
    last_updated: Optional[datetime] = None
    is_active: bool = True
