from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=128)
    password: str = Field(..., min_length=1, max_length=128)


class RestoreConfigRequest(BaseModel):
    config: Dict[str, str]


class IPBlacklistItem(BaseModel):
    ip: str = Field(..., min_length=1, max_length=50)
    description: Optional[str] = Field("", max_length=500)


class DomainBlacklistItem(BaseModel):
    domain: str = Field(..., min_length=1, max_length=253)  # RFC 1035 max
    description: Optional[str] = Field("", max_length=500)


class InternalAlert(BaseModel):
    event_type: str = Field('unknown', max_length=100)
    message: str = Field('No message', max_length=5000)
    details: Dict[str, Any] = {}
    level: str = Field('warning', max_length=20)


class ImportBlacklistRequest(BaseModel):
    type: str = Field(..., max_length=10)  # 'ip' or 'domain'
    url: Optional[str] = Field(None, max_length=2048)
    content: Optional[str] = Field(None, max_length=50_000_000)  # 50MB text max


class ImportGeoBlacklistRequest(BaseModel):
    countries: List[str] = Field(..., max_length=50)  # max 50 countries at once


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(..., min_length=1, max_length=128)
    new_password: str = Field(..., min_length=8, max_length=128)


class SettingUpdate(BaseModel):
    value: str = Field(..., max_length=10000)
