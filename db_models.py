from datetime import datetime
from typing import Optional, List, Dict, Any

from sqlmodel import SQLModel, Field, Column, JSON


class User(SQLModel, table=True):
    __tablename__ = "users"

    id: Optional[int] = Field(default=None, primary_key=True)
    username: str = Field(index=True, unique=True)
    hashed_password: str
    role: str = Field(default="user")  # ex: "admin" ou "user"
    created_at: datetime = Field(default_factory=datetime.utcnow)


class Device(SQLModel, table=True):
    __tablename__ = "devices"

    id: Optional[int] = Field(default=None, primary_key=True)
    ip_address: str = Field(index=True)
    mac_address: str = Field(index=True)
    vendor: Optional[str] = Field(default="Desconhecido")
    last_seen: datetime = Field(default_factory=datetime.utcnow)


class ScanReport(SQLModel, table=True):
    __tablename__ = "scan_reports"

    id: Optional[int] = Field(default=None, primary_key=True)
    target_ip: str = Field(index=True)
    open_ports: List[Dict[str, Any]] = Field(default_factory=list, sa_column=Column(JSON))
    mitre_tactics: List[Dict[str, Any]] = Field(default_factory=list, sa_column=Column(JSON))
    created_at: datetime = Field(default_factory=datetime.utcnow)


class SnifferLog(SQLModel, table=True):
    __tablename__ = "sniffer_logs"

    id: Optional[int] = Field(default=None, primary_key=True)
    source_ip: str
    destination_ip: str
    protocol: str
    alert_type: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
