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


# CTI Gap Analysis Models (Based on Personal-Enacted Identity Gap Scale - Jung & Hecht 2004)
class Factor1Inauthenticity(BaseModel):
    """Factor 1: Where MT causes inauthentic expression (items 4,5,6,7,8,9,10)"""
    mt_issue: str
    user_fix: str
    scale_item: str  # "4", "5", "6", "7", "8", "9", or "10"
    explanation: str


class Factor2Authenticity(BaseModel):
    """Factor 2: Where user restores authentic expression (items 1,2,3,11)"""
    mt_failure: str
    user_restoration: str
    scale_item: str  # "1", "2", "3", or "11"
    explanation: str


class GapAnalysisRequest(BaseModel):
    mt_version: str
    edited_version: str


class GapAnalysisResult(BaseModel):
    factor1_inauthenticity: list[Factor1Inauthenticity] = []
    factor2_authenticity: list[Factor2Authenticity] = []
    summary: str = ""


class TranslateWithAnalysisRequest(BaseModel):
    text: str
    source_lang: str = "ko"
    gap_analysis: dict[str, Any]


class TranslateWithAnalysisResponse(BaseModel):
    translated_text: str
    target_language: str
    identity_preserved: bool = True


# Personal Profile Models (built from gap analyses using CTI two-factor structure)
class PersonalProfile(BaseModel):
    username: str
    # Factor 1: Common inauthenticity issues the user corrects (items 4,5,6,7,8,9,10)
    common_inauthenticity_fixes: list[str] = []  # Patterns user frequently fixes
    inauthenticity_scale_items: dict[str, int] = {}  # Count per scale item
    # Factor 2: Common authenticity restorations (items 1,2,3,11)
    common_authenticity_patterns: list[str] = []  # How user expresses authentically
    authenticity_scale_items: dict[str, int] = {}  # Count per scale item
    identity_summary: str = ""
    analysis_count: int = 0
    last_updated: Optional[datetime] = None
    is_active: bool = True


class PersonalProfileResponse(BaseModel):
    common_inauthenticity_fixes: list[str] = []
    inauthenticity_scale_items: dict[str, int] = {}
    common_authenticity_patterns: list[str] = []
    authenticity_scale_items: dict[str, int] = {}
    identity_summary: str = ""
    analysis_count: int = 0
    last_updated: Optional[datetime] = None
    is_active: bool = True
