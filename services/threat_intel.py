from __future__ import annotations

import asyncio
import base64
import ipaddress
import os
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote, urlparse

import requests
from dotenv import load_dotenv

load_dotenv()

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
VIRUSTOTAL_IP_URL = "https://www.virustotal.com/api/v3/ip_addresses"
VIRUSTOTAL_DOMAIN_URL = "https://www.virustotal.com/api/v3/domains"
VIRUSTOTAL_URL_URL = "https://www.virustotal.com/api/v3/urls"

DEFAULT_TIMEOUT = 8
TI_CONCURRENCY = max(1, int(os.getenv("TI_CONCURRENCY", "5")))


class ThreatIntelError(Exception):
    pass


class ThreatIntelProviderError(ThreatIntelError):
    pass


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_ip(value: str) -> str | None:
    try:
        return str(ipaddress.ip_address(value.strip()))
    except (ValueError, AttributeError):
        return None


def is_public_ip(value: str) -> bool:
    normalized = normalize_ip(value)
    if not normalized:
        return False
    try:
        return ipaddress.ip_address(normalized).is_global
    except ValueError:
        return False


def normalize_domain(domain: str) -> str | None:
    if not domain:
        return None
    domain = domain.strip().lower().rstrip(".")
    if domain.startswith("@"):
        domain = domain[1:]
    return domain or None


def normalize_url(url: str) -> str | None:
    if not url:
        return None
    url = url.strip()
    if not url:
        return None
    try:
        parsed = urlparse(url)
    except ValueError:
        return None
    if parsed.scheme.lower() not in {"http", "https"}:
        return None
    if not parsed.hostname:
        return None
    return url


def extract_url_hostname(url: str) -> str | None:
    try:
        parsed = urlparse(url)
        if not parsed.hostname:
            return None
        return parsed.hostname.lower().rstrip(".")
    except Exception:
        return None


def build_evidence(
    *,
    provider: str,
    indicator_type: str,
    indicator: str,
    source_url: str | None = None,
) -> dict[str, Any]:
    return {
        "provider": provider,
        "indicator_type": indicator_type,
        "indicator": indicator,
        "source": source_url,
        "observed_at": utc_now(),
    }


def empty_ip_result(ip: str) -> dict[str, Any]:
    return {
        "indicator": ip,
        "indicator_type": "ip",
        "available": False,
        "reputation": "unknown",
        "threat_score": 0,
        "abuse_confidence": 0,
        "country": None,
        "country_code": None,
        "asn": None,
        "organization": None,
        "isp": None,
        "is_tor": False,
        "is_vpn": False,
        "is_proxy": False,
        "is_open_relay": False,
        "categories": [],
        "reports": 0,
        "evidence": [],
        "errors": [],
    }


def empty_domain_result(domain: str) -> dict[str, Any]:
    return {
        "indicator": domain,
        "indicator_type": "domain",
        "available": False,
        "reputation": "unknown",
        "threat_score": 0,
        "malicious": False,
        "suspicious": False,
        "categories": [],
        "registrar": None,
        "creation_date": None,
        "expiration_date": None,
        "name_servers": [],
        "resolutions": [],
        "evidence": [],
        "errors": [],
    }


def empty_url_result(url: str) -> dict[str, Any]:
    return {
        "indicator": url,
        "indicator_type": "url",
        "available": False,
        "reputation": "unknown",
        "threat_score": 0,
        "malicious": False,
        "suspicious": False,
        "categories": [],
        "final_url": None,
        "domain": extract_url_hostname(url),
        "evidence": [],
        "errors": [],
    }


def check_abuseipdb(
    ip: str,
    *,
    max_age_days: int = 90,
    timeout: int = DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    result = empty_ip_result(ip)
    normalized = normalize_ip(ip)

    if not normalized:
        result["errors"].append("Invalid IP address")
        return result

    if not is_public_ip(normalized):
        result["errors"].append("IP is not globally routable")
        return result

    if not ABUSEIPDB_API_KEY:
        result["errors"].append("ABUSEIPDB_API_KEY is not configured")
        return result

    try:
        response = requests.get(
            ABUSEIPDB_URL,
            headers={
                "Accept": "application/json",
                "Key": ABUSEIPDB_API_KEY,
            },
            params={
                "ipAddress": normalized,
                "maxAgeInDays": max_age_days,
                "verbose": "",
            },
            timeout=timeout,
        )
        response.raise_for_status()

        data = response.json().get("data", {})
        abuse_confidence = int(data.get("abuseConfidenceScore") or 0)
        reports = int(data.get("totalReports") or 0)

        result.update(
            {
                "available": True,
                "abuse_confidence": abuse_confidence,
                "reports": reports,
                "country": data.get("countryName"),
                "country_code": data.get("countryCode"),
                "isp": data.get("isp"),
                "organization": data.get("domain"),
                "is_tor": bool(data.get("isTor")),
                "categories": [data["usageType"]] if data.get("usageType") else [],
            }
        )

        if abuse_confidence >= 80:
            result["reputation"] = "malicious"
            result["threat_score"] = min(abuse_confidence, 100)
        elif abuse_confidence >= 50:
            result["reputation"] = "suspicious"
            result["threat_score"] = abuse_confidence
        elif abuse_confidence > 0:
            result["reputation"] = "low_risk"
            result["threat_score"] = abuse_confidence

        result["evidence"].append(
            build_evidence(
                provider="AbuseIPDB",
                indicator_type="ip",
                indicator=normalized,
                source_url=ABUSEIPDB_URL,
            )
        )
    except requests.RequestException as exc:
        result["errors"].append(f"AbuseIPDB request failed: {exc}")
    except (ValueError, TypeError) as exc:
        result["errors"].append(f"AbuseIPDB response parsing failed: {exc}")

    return result


def _virustotal_headers() -> dict[str, str] | None:
    if not VIRUSTOTAL_API_KEY:
        return None
    return {
        "x-apikey": VIRUSTOTAL_API_KEY,
        "Accept": "application/json",
    }


def _extract_vt_stats(attributes: dict[str, Any]) -> dict[str, int]:
    stats = attributes.get("last_analysis_stats") or {}
    return {
        "malicious": int(stats.get("malicious") or 0),
        "suspicious": int(stats.get("suspicious") or 0),
        "undetected": int(stats.get("undetected") or 0),
        "harmless": int(stats.get("harmless") or 0),
        "timeout": int(stats.get("timeout") or 0),
    }


def _calculate_vt_score(stats: dict[str, int]) -> int:
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total = sum(stats.values())

    if total <= 0:
        return 0

    return min(
        round((malicious / total) * 100 + (suspicious / total) * 30),
        100,
    )


def check_virustotal_ip(
    ip: str,
    *,
    timeout: int = DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    result = empty_ip_result(ip)
    normalized = normalize_ip(ip)

    if not normalized:
        result["errors"].append("Invalid IP address")
        return result

    if not is_public_ip(normalized):
        result["errors"].append("IP is not globally routable")
        return result

    headers = _virustotal_headers()

    if not headers:
        result["errors"].append("VIRUSTOTAL_API_KEY is not configured")
        return result

    endpoint = f"{VIRUSTOTAL_IP_URL}/{normalized}"

    try:
        response = requests.get(
            endpoint,
            headers=headers,
            timeout=timeout,
        )
        response.raise_for_status()

        attributes = (
            response.json()
            .get("data", {})
            .get("attributes", {})
        )

        stats = _extract_vt_stats(attributes)

        result.update(
            {
                "available": True,
                "threat_score": _calculate_vt_score(stats),
                "country": attributes.get("country"),
                "country_code": attributes.get("country"),
                "asn": attributes.get("asn"),
                "organization": attributes.get("as_owner"),
            }
        )

        if stats["malicious"] > 0:
            result["reputation"] = "malicious"
        elif stats["suspicious"] > 0:
            result["reputation"] = "suspicious"

        result["evidence"].append(
            build_evidence(
                provider="VirusTotal",
                indicator_type="ip",
                indicator=normalized,
                source_url=endpoint,
            )
        )
    except requests.RequestException as exc:
        result["errors"].append(f"VirusTotal IP request failed: {exc}")
    except (ValueError, TypeError) as exc:
        result["errors"].append(f"VirusTotal IP response parsing failed: {exc}")

    return result


def _merge_ip_provider_results(
    ip: str,
    providers: dict[str, Any],
) -> dict[str, Any]:
    result = empty_ip_result(ip)
    scores = []
    reputations = []

    for provider_result in providers.values():
        if provider_result.get("available"):
            scores.append(int(provider_result.get("threat_score") or 0))
            reputation = provider_result.get("reputation")
            if reputation:
                reputations.append(reputation)
            result["evidence"].extend(
                provider_result.get("evidence", [])
            )

        for field in (
            "country",
            "country_code",
            "asn",
            "organization",
            "isp",
        ):
            if not result.get(field) and provider_result.get(field):
                result[field] = provider_result[field]

        if provider_result.get("is_tor"):
            result["is_tor"] = True
        if provider_result.get("is_vpn"):
            result["is_vpn"] = True
        if provider_result.get("is_proxy"):
            result["is_proxy"] = True

    if scores:
        result["available"] = True
        result["threat_score"] = max(scores)

    if "malicious" in reputations:
        result["reputation"] = "malicious"
    elif "suspicious" in reputations:
        result["reputation"] = "suspicious"
    elif reputations:
        result["reputation"] = reputations[0]

    result["providers"] = providers
    return result


def enrich_ip(
    ip: str,
    *,
    use_abuseipdb: bool = True,
    use_virustotal: bool = True,
) -> dict[str, Any]:
    normalized = normalize_ip(ip)
    result = empty_ip_result(ip)

    if not normalized:
        result["errors"].append("Invalid IP address")
        return result

    if not is_public_ip(normalized):
        result["errors"].append("IP is not globally routable")
        return result

    providers = {}

    if use_abuseipdb:
        providers["abuseipdb"] = check_abuseipdb(normalized)

    if use_virustotal:
        providers["virustotal"] = check_virustotal_ip(normalized)

    return _merge_ip_provider_results(normalized, providers)


def check_virustotal_domain(
    domain: str,
    *,
    timeout: int = DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    result = empty_domain_result(domain)
    normalized = normalize_domain(domain)

    if not normalized:
        result["errors"].append("Invalid domain")
        return result

    headers = _virustotal_headers()

    if not headers:
        result["errors"].append("VIRUSTOTAL_API_KEY is not configured")
        return result

    endpoint = f"{VIRUSTOTAL_DOMAIN_URL}/{quote(normalized, safe='')}"

    try:
        response = requests.get(
            endpoint,
            headers=headers,
            timeout=timeout,
        )
        response.raise_for_status()

        attributes = (
            response.json()
            .get("data", {})
            .get("attributes", {})
        )

        stats = _extract_vt_stats(attributes)

        result.update(
            {
                "available": True,
                "threat_score": _calculate_vt_score(stats),
                "resolutions": attributes.get("last_dns_records", []),
            }
        )

        if stats["malicious"] > 0:
            result["malicious"] = True
            result["reputation"] = "malicious"
        elif stats["suspicious"] > 0:
            result["suspicious"] = True
            result["reputation"] = "suspicious"

        result["evidence"].append(
            build_evidence(
                provider="VirusTotal",
                indicator_type="domain",
                indicator=normalized,
                source_url=endpoint,
            )
        )
    except requests.RequestException as exc:
        result["errors"].append(f"VirusTotal domain request failed: {exc}")
    except (ValueError, TypeError) as exc:
        result["errors"].append(
            f"VirusTotal domain response parsing failed: {exc}"
        )

    return result


def enrich_domain(
    domain: str,
    *,
    use_virustotal: bool = True,
) -> dict[str, Any]:
    normalized = normalize_domain(domain)
    result = empty_domain_result(domain)

    if not normalized:
        result["errors"].append("Invalid domain")
        return result

    providers = {}

    if use_virustotal:
        providers["virustotal"] = check_virustotal_domain(normalized)

    scores = []
    reputations = []

    for provider_result in providers.values():
        if provider_result.get("available"):
            scores.append(int(provider_result.get("threat_score") or 0))
            reputations.append(
                provider_result.get("reputation", "unknown")
            )
            result["evidence"].extend(
                provider_result.get("evidence", [])
            )
            if provider_result.get("malicious"):
                result["malicious"] = True
            if provider_result.get("suspicious"):
                result["suspicious"] = True

    if scores:
        result["available"] = True
        result["threat_score"] = max(scores)

    if "malicious" in reputations:
        result["reputation"] = "malicious"
    elif "suspicious" in reputations:
        result["reputation"] = "suspicious"
    elif reputations:
        result["reputation"] = reputations[0]

    result["providers"] = providers
    return result


def check_virustotal_url(
    url: str,
    *,
    timeout: int = DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    result = empty_url_result(url)
    normalized = normalize_url(url)

    if not normalized:
        result["errors"].append("Invalid HTTP/HTTPS URL")
        return result

    headers = _virustotal_headers()

    if not headers:
        result["errors"].append("VIRUSTOTAL_API_KEY is not configured")
        return result

    encoded_url = (
        base64.urlsafe_b64encode(
            normalized.encode("utf-8")
        )
        .decode("utf-8")
        .rstrip("=")
    )

    endpoint = f"{VIRUSTOTAL_URL_URL}/{encoded_url}"

    try:
        response = requests.get(
            endpoint,
            headers=headers,
            timeout=timeout,
        )
        response.raise_for_status()

        attributes = (
            response.json()
            .get("data", {})
            .get("attributes", {})
        )

        stats = _extract_vt_stats(attributes)

        result.update(
            {
                "available": True,
                "threat_score": _calculate_vt_score(stats),
                "final_url": attributes.get("last_final_url"),
            }
        )

        if stats["malicious"] > 0:
            result["malicious"] = True
            result["reputation"] = "malicious"
        elif stats["suspicious"] > 0:
            result["suspicious"] = True
            result["reputation"] = "suspicious"

        result["evidence"].append(
            build_evidence(
                provider="VirusTotal",
                indicator_type="url",
                indicator=normalized,
                source_url=endpoint,
            )
        )
    except requests.RequestException as exc:
        result["errors"].append(f"VirusTotal URL request failed: {exc}")
    except (ValueError, TypeError) as exc:
        result["errors"].append(
            f"VirusTotal URL response parsing failed: {exc}"
        )

    return result


def enrich_url(
    url: str,
    *,
    use_virustotal: bool = True,
) -> dict[str, Any]:
    normalized = normalize_url(url)
    result = empty_url_result(url)

    if not normalized:
        result["errors"].append("Invalid HTTP/HTTPS URL")
        return result

    providers = {}

    if use_virustotal:
        providers["virustotal"] = check_virustotal_url(normalized)

    scores = []
    reputations = []

    for provider_result in providers.values():
        if provider_result.get("available"):
            scores.append(int(provider_result.get("threat_score") or 0))
            reputations.append(
                provider_result.get("reputation", "unknown")
            )
            result["evidence"].extend(
                provider_result.get("evidence", [])
            )
            if provider_result.get("malicious"):
                result["malicious"] = True
            if provider_result.get("suspicious"):
                result["suspicious"] = True

    if scores:
        result["available"] = True
        result["threat_score"] = max(scores)

    if "malicious" in reputations:
        result["reputation"] = "malicious"
    elif "suspicious" in reputations:
        result["reputation"] = "suspicious"
    elif reputations:
        result["reputation"] = reputations[0]

    result["providers"] = providers
    return result


async def _limited_call(function, *args, **kwargs):
    async with _TI_LIMITER:
        return await asyncio.to_thread(function, *args, **kwargs)


def _unique_normalized(values: list[str], normalizer) -> list[str]:
    result = []
    seen = set()

    for value in values:
        normalized = normalizer(value)
        if normalized and normalized not in seen:
            seen.add(normalized)
            result.append(normalized)

    return result


async def enrich_ip_async(
    ip: str,
    *,
    use_abuseipdb: bool = True,
    use_virustotal: bool = True,
) -> dict[str, Any]:
    normalized = normalize_ip(ip)

    if not normalized:
        result = empty_ip_result(ip)
        result["errors"].append("Invalid IP address")
        return result

    if not is_public_ip(normalized):
        result = empty_ip_result(ip)
        result["errors"].append("IP is not globally routable")
        return result

    tasks = []

    if use_abuseipdb:
        tasks.append(
            ("abuseipdb", _limited_call(check_abuseipdb, normalized))
        )

    if use_virustotal:
        tasks.append(
            ("virustotal", _limited_call(check_virustotal_ip, normalized))
        )

    if not tasks:
        return empty_ip_result(normalized)

    names = [name for name, _ in tasks]
    results = await asyncio.gather(
        *(task for _, task in tasks)
    )

    return _merge_ip_provider_results(
        normalized,
        dict(zip(names, results)),
    )


async def enrich_domain_async(
    domain: str,
    *,
    use_virustotal: bool = True,
) -> dict[str, Any]:
    normalized = normalize_domain(domain)

    if not normalized:
        result = empty_domain_result(domain)
        result["errors"].append("Invalid domain")
        return result

    if not use_virustotal:
        return empty_domain_result(normalized)

    return await _limited_call(
        enrich_domain,
        normalized,
        use_virustotal=True,
    )


async def enrich_url_async(
    url: str,
    *,
    use_virustotal: bool = True,
) -> dict[str, Any]:
    normalized = normalize_url(url)

    if not normalized:
        result = empty_url_result(url)
        result["errors"].append("Invalid HTTP/HTTPS URL")
        return result

    if not use_virustotal:
        return empty_url_result(normalized)

    return await _limited_call(
        enrich_url,
        normalized,
        use_virustotal=True,
    )


async def enrich_iocs_async(
    *,
    ips: list[str] | None = None,
    domains: list[str] | None = None,
    urls: list[str] | None = None,
) -> dict[str, Any]:
    unique_ips = _unique_normalized(ips or [], normalize_ip)
    unique_domains = _unique_normalized(domains or [], normalize_domain)
    unique_urls = _unique_normalized(urls or [], normalize_url)

    ip_results, domain_results, url_results = await asyncio.gather(
        asyncio.gather(
            *(enrich_ip_async(ip) for ip in unique_ips)
        ),
        asyncio.gather(
            *(enrich_domain_async(domain) for domain in unique_domains)
        ),
        asyncio.gather(
            *(enrich_url_async(url) for url in unique_urls)
        ),
    )

    all_results = (
        list(ip_results)
        + list(domain_results)
        + list(url_results)
    )

    return {
        "analyzed_at": utc_now(),
        "summary": {
            "ips": len(ip_results),
            "domains": len(domain_results),
            "urls": len(url_results),
            "malicious": sum(
                1
                for item in all_results
                if (
                    item.get("reputation") == "malicious"
                    or item.get("malicious") is True
                )
            ),
            "suspicious": sum(
                1
                for item in all_results
                if (
                    item.get("reputation") == "suspicious"
                    or item.get("suspicious") is True
                )
            ),
        },
        "ips": list(ip_results),
        "domains": list(domain_results),
        "urls": list(url_results),
    }


def enrich_iocs(
    *,
    ips: list[str] | None = None,
    domains: list[str] | None = None,
    urls: list[str] | None = None,
) -> dict[str, Any]:
    unique_ips = _unique_normalized(ips or [], normalize_ip)
    unique_domains = _unique_normalized(domains or [], normalize_domain)
    unique_urls = _unique_normalized(urls or [], normalize_url)

    ip_results = [enrich_ip(ip) for ip in unique_ips]
    domain_results = [
        enrich_domain(domain)
        for domain in unique_domains
    ]
    url_results = [
        enrich_url(url)
        for url in unique_urls
    ]

    all_results = (
        ip_results
        + domain_results
        + url_results
    )

    return {
        "analyzed_at": utc_now(),
        "summary": {
            "ips": len(ip_results),
            "domains": len(domain_results),
            "urls": len(url_results),
            "malicious": sum(
                1
                for item in all_results
                if (
                    item.get("reputation") == "malicious"
                    or item.get("malicious") is True
                )
            ),
            "suspicious": sum(
                1
                for item in all_results
                if (
                    item.get("reputation") == "suspicious"
                    or item.get("suspicious") is True
                )
            ),
        },
        "ips": ip_results,
        "domains": domain_results,
        "urls": url_results,
    }


def build_infrastructure_signals(
    ti_results: dict[str, Any],
) -> list[dict[str, Any]]:
    signals = []

    all_results = (
        ti_results.get("ips", [])
        + ti_results.get("domains", [])
        + ti_results.get("urls", [])
    )

    for result in all_results:
        indicator = result.get("indicator")
        indicator_type = result.get("indicator_type")
        threat_score = int(result.get("threat_score") or 0)
        reputation = result.get("reputation", "unknown")

        if threat_score >= 80:
            signals.append(
                {
                    "type": "threat_intelligence_high_risk",
                    "severity": "critical",
                    "description": (
                        f"{indicator_type.upper()} {indicator} "
                        f"has a high threat-intelligence score "
                        f"({threat_score}/100)."
                    ),
                    "evidence": {
                        "indicator": indicator,
                        "indicator_type": indicator_type,
                        "threat_score": threat_score,
                        "reputation": reputation,
                    },
                }
            )
        elif threat_score >= 60:
            signals.append(
                {
                    "type": "threat_intelligence_suspicious",
                    "severity": "high",
                    "description": (
                        f"{indicator_type.upper()} {indicator} "
                        f"has a suspicious threat-intelligence "
                        f"score ({threat_score}/100)."
                    ),
                    "evidence": {
                        "indicator": indicator,
                        "indicator_type": indicator_type,
                        "threat_score": threat_score,
                        "reputation": reputation,
                    },
                }
            )

        if reputation == "malicious":
            signals.append(
                {
                    "type": "malicious_reputation",
                    "severity": "critical",
                    "description": (
                        f"{indicator_type.upper()} {indicator} "
                        "has malicious reputation evidence."
                    ),
                    "evidence": {
                        "indicator": indicator,
                        "indicator_type": indicator_type,
                        "reputation": reputation,
                    },
                }
            )
        elif reputation == "suspicious":
            signals.append(
                {
                    "type": "suspicious_reputation",
                    "severity": "high",
                    "description": (
                        f"{indicator_type.upper()} {indicator} "
                        "has suspicious reputation evidence."
                    ),
                    "evidence": {
                        "indicator": indicator,
                        "indicator_type": indicator_type,
                        "reputation": reputation,
                    },
                }
            )

        if result.get("is_tor"):
            signals.append(
                {
                    "type": "tor_infrastructure",
                    "severity": "medium",
                    "description": (
                        f"IP {indicator} is associated with "
                        "Tor infrastructure."
                    ),
                    "evidence": {
                        "indicator": indicator,
                        "indicator_type": indicator_type,
                        "is_tor": True,
                    },
                }
            )

        if result.get("is_vpn"):
            signals.append(
                {
                    "type": "vpn_infrastructure",
                    "severity": "low",
                    "description": (
                        f"IP {indicator} is associated with "
                        "VPN infrastructure."
                    ),
                    "evidence": {
                        "indicator": indicator,
                        "indicator_type": indicator_type,
                        "is_vpn": True,
                    },
                }
            )

    return signals


def get_threat_intel_status() -> dict[str, Any]:
    return {
        "service": "threat_intelligence",
        "status": "ready",
        "providers": {
            "abuseipdb": {
                "configured": bool(ABUSEIPDB_API_KEY),
            },
            "virustotal": {
                "configured": bool(VIRUSTOTAL_API_KEY),
            },
        },
        "concurrency": TI_CONCURRENCY,
    }


_TI_LIMITER = asyncio.Semaphore(TI_CONCURRENCY)


__all__ = [
    "ThreatIntelError",
    "ThreatIntelProviderError",
    "check_abuseipdb",
    "check_virustotal_ip",
    "check_virustotal_domain",
    "check_virustotal_url",
    "enrich_ip",
    "enrich_domain",
    "enrich_url",
    "enrich_iocs",
    "enrich_ip_async",
    "enrich_domain_async",
    "enrich_url_async",
    "enrich_iocs_async",
    "build_infrastructure_signals",
    "get_threat_intel_status",
]
