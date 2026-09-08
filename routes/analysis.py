from __future__ import annotations

import asyncio
from typing import Any

from fastapi import APIRouter, HTTPException

from models.email import EmailAnalysisRequest
from services.email_parser import parse_email
from services.gmail_services import GmailService, GmailServiceError
from services.ip_intelligence import analyze_ips
from services.domain_intelligence import analyze_domains
from services.url_analyzer import analyze_urls
from services.threat_intel import enrich_iocs_async
from services.risk_engine import calculate_risk


router = APIRouter(
    prefix="/analysis",
    tags=["Analysis"],
)


def _safe_list(value: Any) -> list:
    if isinstance(value, list):
        return value
    if value is None:
        return []
    return [value]


def _get_authentication(parsed: dict) -> dict:
    authentication = parsed.get("authentication")

    if isinstance(authentication, dict):
        return authentication

    return {
        "spf": "unknown",
        "dkim": "unknown",
        "dmarc": "unknown",
        "headers": [],
    }


def _build_identity_analysis(parsed: dict) -> dict:
    identity = parsed.get("identity") or {}

    sender_email = identity.get("sender_email")
    sender_domain = identity.get("sender_domain")
    reply_to_email = identity.get("reply_to_email")
    reply_to_domain = identity.get("reply_to_domain")
    return_path_email = identity.get("return_path_email")
    return_path_domain = identity.get("return_path_domain")

    findings = []

    if (
        sender_domain
        and reply_to_domain
        and sender_domain.lower() != reply_to_domain.lower()
    ):
        findings.append(
            {
                "type": "reply_to_mismatch",
                "severity": "high",
                "description": (
                    "Reply-To domain differs from the sender domain."
                ),
                "evidence": {
                    "sender_email": sender_email,
                    "sender_domain": sender_domain,
                    "reply_to_email": reply_to_email,
                    "reply_to_domain": reply_to_domain,
                },
            }
        )

    if (
        sender_domain
        and return_path_domain
        and sender_domain.lower() != return_path_domain.lower()
    ):
        findings.append(
            {
                "type": "return_path_difference",
                "severity": "informational",
                "description": (
                    "Return-Path differs from the visible sender domain. "
                    "This can be normal for mailing and bounce infrastructure."
                ),
                "evidence": {
                    "sender_domain": sender_domain,
                    "return_path_domain": return_path_domain,
                },
            }
        )

    return {
        "sender": sender_email,
        "sender_domain": sender_domain,
        "reply_to": reply_to_email,
        "reply_to_domain": reply_to_domain,
        "return_path": return_path_email,
        "return_path_domain": return_path_domain,
        "findings": findings,
    }


def _analyze_behavior(parsed: dict) -> dict:
    body = str(parsed.get("body", "")).lower()
    subject = str(
        parsed.get("headers", {}).get("subject", "")
    ).lower()
    text = f"{subject} {body}"

    urgency_keywords = [
        "urgent",
        "immediately",
        "asap",
        "right away",
        "act now",
        "final notice",
        "within 24 hours",
    ]

    credential_keywords = [
        "password",
        "verify your account",
        "login",
        "sign in",
        "credentials",
        "authentication",
        "reset your password",
    ]

    payment_keywords = [
        "wire transfer",
        "bank transfer",
        "payment",
        "invoice",
        "bank account",
        "account number",
        "beneficiary",
        "transfer funds",
    ]

    executive_keywords = [
        "ceo",
        "cfo",
        "director",
        "executive",
        "management",
        "finance team",
    ]

    urgency_matches = [
        word for word in urgency_keywords if word in text
    ]

    credential_matches = [
        word for word in credential_keywords if word in text
    ]

    payment_matches = [
        word for word in payment_keywords if word in text
    ]

    executive_matches = [
        word for word in executive_keywords if word in text
    ]

    findings = []

    if urgency_matches:
        findings.append(
            {
                "type": "urgency_language",
                "severity": "medium",
                "description": (
                    "The message contains language designed to create urgency."
                ),
                "evidence": {
                    "matches": urgency_matches,
                },
            }
        )

    if credential_matches:
        findings.append(
            {
                "type": "credential_harvesting_language",
                "severity": "high",
                "description": (
                    "The message contains language associated with "
                    "credential harvesting."
                ),
                "evidence": {
                    "matches": credential_matches,
                },
            }
        )

    if payment_matches:
        findings.append(
            {
                "type": "payment_request_language",
                "severity": "high",
                "description": (
                    "The message contains financial or payment-related "
                    "request language."
                ),
                "evidence": {
                    "matches": payment_matches,
                },
            }
        )

    if executive_matches and payment_matches:
        findings.append(
            {
                "type": "bec_pattern",
                "severity": "critical",
                "description": (
                    "Executive impersonation indicators combined with "
                    "payment-related language match a potential BEC pattern."
                ),
                "evidence": {
                    "executive_terms": executive_matches,
                    "payment_terms": payment_matches,
                },
            }
        )

    if len(urgency_matches) >= 2 and credential_matches:
        findings.append(
            {
                "type": "social_engineering_pattern",
                "severity": "high",
                "description": (
                    "Urgency and credential-related language occur together."
                ),
                "evidence": {
                    "urgency": urgency_matches,
                    "credentials": credential_matches,
                },
            }
        )

    bec_level = "none"

    if any(
        finding["type"] == "bec_pattern"
        for finding in findings
    ):
        bec_level = "elevated"
    elif payment_matches or executive_matches:
        bec_level = "possible"

    return {
        "bec_level": bec_level,
        "urgency_matches": urgency_matches,
        "credential_matches": credential_matches,
        "payment_matches": payment_matches,
        "executive_matches": executive_matches,
        "findings": findings,
    }


async def _analyze_infrastructure(
    parsed: dict,
) -> dict:
    urls = _safe_list(parsed.get("urls"))
    domains = _safe_list(parsed.get("domains"))
    ips = _safe_list(parsed.get("ips"))

    try:
        url_results = analyze_urls(urls)
    except Exception as exc:
        url_results = [
            {
                "status": "error",
                "error": str(exc),
            }
        ]

    domain_task = asyncio.to_thread(
        analyze_domains,
        domains,
    )

    ip_task = asyncio.to_thread(
        analyze_ips,
        ips,
    )

    domain_results, ip_results = await asyncio.gather(
        domain_task,
        ip_task,
        return_exceptions=True,
    )

    if isinstance(domain_results, Exception):
        domain_results = [
            {
                "status": "error",
                "error": str(domain_results),
            }
        ]

    if isinstance(ip_results, Exception):
        ip_results = [
            {
                "status": "error",
                "error": str(ip_results),
            }
        ]

    return {
        "urls": url_results,
        "domains": domain_results,
        "ips": ip_results,
    }


async def _run_threat_intelligence(
    parsed: dict,
    infrastructure: dict,
) -> dict:
    try:
        return await enrich_iocs_async(
            ips=_safe_list(parsed.get("ips")),
            domains=_safe_list(parsed.get("domains")),
            urls=_safe_list(parsed.get("urls")),
        )
    except Exception as exc:
        return {
            "status": "error",
            "error": str(exc),
            "ips": [],
            "domains": [],
            "urls": [],
            "signals": [],
        }


def _calculate_final_risk(
    parsed: dict,
    identity: dict,
    behavior: dict,
    infrastructure: dict,
    threat_intel: dict,
) -> dict:
    authentication = _get_authentication(parsed)

    url_analysis = {
        "results": infrastructure.get("urls", []),
        "findings": [],
    }

    for result in infrastructure.get("urls", []):
        if isinstance(result, dict):
            url_analysis["findings"].extend(
                _safe_list(result.get("findings"))
            )

    attachments = _safe_list(
        parsed.get("attachments")
    )

    infrastructure_data = {
        "ips": infrastructure.get("ips", []),
        "domains": infrastructure.get("domains", []),
        "urls": infrastructure.get("urls", []),
    }

    if isinstance(threat_intel, dict):
        infrastructure_data["threat_intelligence"] = threat_intel
        infrastructure_data["signals"] = threat_intel.get(
            "signals",
            [],
        )

    return calculate_risk(
        findings=[],
        authentication=authentication,
        identity=identity,
        url_analysis=url_analysis,
        attachments=attachments,
        social_engineering=behavior,
        infrastructure=infrastructure_data,
    )


async def _analyze_raw_email(
    raw_email: bytes | str,
) -> dict:
    parsed = await asyncio.to_thread(
        parse_email,
        raw_email,
    )

    authentication = _get_authentication(parsed)
    identity = _build_identity_analysis(parsed)
    behavior = _analyze_behavior(parsed)

    infrastructure_task = asyncio.create_task(
        _analyze_infrastructure(parsed)
    )

    threat_intelligence_task = asyncio.create_task(
        _run_threat_intelligence(
            parsed,
            {},
        )
    )

    infrastructure, threat_intelligence = await asyncio.gather(
        infrastructure_task,
        threat_intelligence_task,
    )

    risk = _calculate_final_risk(
        parsed=parsed,
        identity=identity,
        behavior=behavior,
        infrastructure=infrastructure,
        threat_intel=threat_intelligence,
    )

    findings = []

    findings.extend(
        identity.get("findings", [])
    )

    findings.extend(
        behavior.get("findings", [])
    )

    for result in infrastructure.get("urls", []):
        if isinstance(result, dict):
            findings.extend(
                _safe_list(result.get("findings"))
            )

    if isinstance(threat_intelligence, dict):
        findings.extend(
            _safe_list(
                threat_intelligence.get("findings")
            )
        )

    return {
        "success": True,
        "email": parsed,
        "authentication": authentication,
        "identity_analysis": identity,
        "behavioral_analysis": behavior,
        "infrastructure": infrastructure,
        "threat_intelligence": threat_intelligence,
        "findings": findings,
        "risk": risk,
    }


@router.post("/email")
async def analyze_email(
    request: EmailAnalysisRequest,
):
    try:
        return await _analyze_raw_email(
            request.raw_email
        )
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Email analysis failed: {exc}",
        )


@router.post("/gmail/{message_id}")
async def analyze_gmail_message(
    message_id: str,
):
    try:
        gmail = GmailService()

        raw_email = await asyncio.to_thread(
            gmail.get_raw_message,
            message_id,
        )

        result = await _analyze_raw_email(
            raw_email
        )

        result["gmail"] = {
            "message_id": message_id,
        }

        return result

    except GmailServiceError as exc:
        raise HTTPException(
            status_code=401,
            detail=str(exc),
        )

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Gmail analysis failed: {exc}",
        )


@router.get("/status")
async def analysis_status():
    return {
        "success": True,
        "service": "email-analysis",
        "pipeline": [
            "email_parser",
            "authentication",
            "identity_analysis",
            "behavioral_analysis",
            "url_analysis",
            "domain_intelligence",
            "ip_intelligence",
            "threat_intelligence",
            "risk_engine",
        ],
        "status": "ready",
    }
