from typing import Optional, Dict, Any, List
from pydantic import BaseModel


class LoginRequest(BaseModel):
    username: str
    password: str


class RestoreConfigRequest(BaseModel):
    config: Dict[str, str]


class IPBlacklistItem(BaseModel):
    ip: str
    description: Optional[str] = ""


class DomainBlacklistItem(BaseModel):
    domain: str
    description: Optional[str] = ""


class InternalAlert(BaseModel):
    event_type: str = 'unknown'
    message: str = 'No message'
    details: Dict[str, Any] = {}
    level: str = 'warning'


class ImportBlacklistRequest(BaseModel):
    type: str  # 'ip' or 'domain'
    url: Optional[str] = None
    content: Optional[str] = None


class ImportGeoBlacklistRequest(BaseModel):
    countries: List[str]


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


class SettingUpdate(BaseModel):
    value: str
