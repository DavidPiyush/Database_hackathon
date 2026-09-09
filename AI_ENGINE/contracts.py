"""Stable input/output contracts for ThreatDetect AI_ENGINE."""

from __future__ import annotations

from typing import Any, TypedDict


class EmailInput(TypedDict, total=False):
    subject: str
    body: str
    sender: str
    recipient: str
    urls: list[str]
    ips: list[str]


class ModelResult(TypedDict, total=False):
    model: str
    model_version: str
    label: str
    probability: float
    score: float
    findings: list[str]
    details: dict[str, Any]


class AIResult(TypedDict):
    model_results: list[ModelResult]
    metadata: dict[str, Any]


def normalize_email_data(email_data: dict[str, Any]) -> EmailInput:
    if not isinstance(email_data, dict):
        raise TypeError("email_data must be a dictionary")

    urls = email_data.get("urls") or email_data.get("extracted_urls") or []
    ips = email_data.get("ips") or email_data.get("extracted_ips") or []

    if isinstance(urls, str):
        urls = [urls]
    if isinstance(ips, str):
        ips = [ips]

    return {
        "subject": str(email_data.get("subject") or ""),
        "body": str(email_data.get("body") or ""),
        "sender": str(email_data.get("sender") or email_data.get("sender_email") or ""),
        "recipient": str(
            email_data.get("recipient")
            or email_data.get("recipient_email")
            or email_data.get("to")
            or ""
        ),
        "urls": [str(x) for x in urls if x],
        "ips": [str(x) for x in ips if x],
    }
