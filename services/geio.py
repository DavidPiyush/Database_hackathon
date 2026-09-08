"""
GeoIP Intelligence Service
--------------------------

Provides geographic and network metadata for IP addresses.

Primary source:
    MaxMind GeoLite2 / GeoIP2 local database

Design principles:
    - Evidence-first
    - Graceful failure
    - No exact attacker-location claims
    - Suitable for forensic investigations
"""

from __future__ import annotations

import ipaddress
import os
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

load_dotenv()


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent.parent

DEFAULT_CITY_DB = BASE_DIR / "data" / "GeoLite2-City.mmdb"
DEFAULT_ASN_DB = BASE_DIR / "data" / "GeoLite2-ASN.mmdb"

CITY_DB_PATH = Path(
    os.getenv("GEOLITE_CITY_DB", str(DEFAULT_CITY_DB))
)

ASN_DB_PATH = Path(
    os.getenv("GEOLITE_ASN_DB", str(DEFAULT_ASN_DB))
)


# ---------------------------------------------------------------------------
# Optional MaxMind dependency
# ---------------------------------------------------------------------------

try:
    import geoip2.database
    import geoip2.errors

    GEOIP2_AVAILABLE = True

except ImportError:
    geoip2 = None
    GEOIP2_AVAILABLE = False


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class GeoIPError(Exception):
    """Raised when a GeoIP operation fails."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _safe_str(value: Any) -> str | None:
    """Convert a value to string safely."""
    if value is None:
        return None

    value = str(value).strip()

    return value if value else None


def _normalize_ip(ip: str) -> str:
    """Validate and normalize an IP address."""

    if not isinstance(ip, str):
        raise GeoIPError("IP address must be a string")

    ip = ip.strip()

    if not ip:
        raise GeoIPError("IP address is empty")

    try:
        return str(ipaddress.ip_address(ip))
    except ValueError as exc:
        raise GeoIPError(f"Invalid IP address: {ip}") from exc


def _classify_ip(ip: str) -> dict[str, Any]:
    """
    Classify an IP before performing GeoIP lookup.

    GeoIP databases are primarily useful for public addresses.
    """

    address = ipaddress.ip_address(ip)

    classification = "public"

    if address.is_loopback:
        classification = "loopback"

    elif address.is_private:
        classification = "private"

    elif address.is_link_local:
        classification = "link_local"

    elif address.is_multicast:
        classification = "multicast"

    elif address.is_unspecified:
        classification = "unspecified"

    elif address.is_reserved:
        classification = "reserved"

    elif address.is_global is False:
        classification = "special"

    return {
        "classification": classification,
        "is_public": address.is_global,
        "is_private": address.is_private,
        "is_loopback": address.is_loopback,
        "is_link_local": address.is_link_local,
        "is_multicast": address.is_multicast,
        "is_reserved": address.is_reserved,
    }


def _empty_result(ip: str) -> dict[str, Any]:
    """Return a consistent result structure."""

    return {
        "ip": ip,
        "success": False,
        "source": None,

        "classification": None,
        "is_public": False,

        "country": None,
        "country_code": None,
        "continent": None,

        "region": None,
        "region_code": None,
        "city": None,

        "latitude": None,
        "longitude": None,
        "accuracy_radius_km": None,

        "timezone": None,

        "asn": None,
        "organization": None,

        "database": None,

        "error": None,
    }


# ---------------------------------------------------------------------------
# GeoIP Database Handling
# ---------------------------------------------------------------------------

def get_geoip_status() -> dict[str, Any]:
    """
    Return availability of GeoIP databases and Python dependency.
    """

    return {
        "geoip2_library": GEOIP2_AVAILABLE,
        "city_database": {
            "path": str(CITY_DB_PATH),
            "exists": CITY_DB_PATH.exists(),
        },
        "asn_database": {
            "path": str(ASN_DB_PATH),
            "exists": ASN_DB_PATH.exists(),
        },
    }


def _open_city_reader():
    """Open MaxMind City database."""

    if not GEOIP2_AVAILABLE:
        raise GeoIPError(
            "geoip2 is not installed. Run: pip install geoip2"
        )

    if not CITY_DB_PATH.exists():
        raise GeoIPError(
            f"GeoIP City database not found: {CITY_DB_PATH}"
        )

    return geoip2.database.Reader(str(CITY_DB_PATH))


def _open_asn_reader():
    """Open MaxMind ASN database."""

    if not GEOIP2_AVAILABLE:
        raise GeoIPError(
            "geoip2 is not installed. Run: pip install geoip2"
        )

    if not ASN_DB_PATH.exists():
        raise GeoIPError(
            f"GeoIP ASN database not found: {ASN_DB_PATH}"
        )

    return geoip2.database.Reader(str(ASN_DB_PATH))


# ---------------------------------------------------------------------------
# City / Country Lookup
# ---------------------------------------------------------------------------

def lookup_city(ip: str) -> dict[str, Any]:
    """
    Perform GeoIP city/country lookup.

    Returns evidence suitable for forensic analysis.
    """

    normalized_ip = _normalize_ip(ip)

    result = _empty_result(normalized_ip)

    classification = _classify_ip(normalized_ip)

    result.update(classification)

    # GeoIP is not meaningful for private/local addresses.
    if not classification["is_public"]:
        result["error"] = (
            "IP is not a public globally routable address"
        )
        return result

    try:
        with _open_city_reader() as reader:

            response = reader.city(normalized_ip)

            result.update(
                {
                    "success": True,
                    "source": "MaxMind GeoIP",
                    "database": str(CITY_DB_PATH.name),

                    "country": _safe_str(
                        response.country.name
                    ),

                    "country_code": _safe_str(
                        response.country.iso_code
                    ),

                    "continent": _safe_str(
                        response.continent.name
                    ),

                    "region": _safe_str(
                        response.subdivisions.most_specific.name
                    ),

                    "region_code": _safe_str(
                        response.subdivisions.most_specific.iso_code
                    ),

                    "city": _safe_str(
                        response.city.name
                    ),

                    "latitude": (
                        float(response.location.latitude)
                        if response.location.latitude is not None
                        else None
                    ),

                    "longitude": (
                        float(response.location.longitude)
                        if response.location.longitude is not None
                        else None
                    ),

                    "accuracy_radius_km": (
                        int(response.location.accuracy_radius)
                        if response.location.accuracy_radius is not None
                        else None
                    ),

                    "timezone": _safe_str(
                        response.location.time_zone
                    ),
                }
            )

            return result

    except geoip2.errors.AddressNotFoundError:
        result["error"] = (
            "IP address not present in GeoIP database"
        )
        return result

    except GeoIPError as exc:
        result["error"] = str(exc)
        return result

    except Exception as exc:
        result["error"] = (
            f"GeoIP lookup failed: {exc}"
        )
        return result


# ---------------------------------------------------------------------------
# ASN Lookup
# ---------------------------------------------------------------------------

def lookup_asn(ip: str) -> dict[str, Any]:
    """
    Perform ASN / network organization lookup.
    """

    normalized_ip = _normalize_ip(ip)

    result = {
        "ip": normalized_ip,
        "success": False,
        "source": None,
        "asn": None,
        "organization": None,
        "network": None,
        "error": None,
    }

    classification = _classify_ip(normalized_ip)

    if not classification["is_public"]:
        result["error"] = (
            "IP is not a public globally routable address"
        )
        return result

    try:
        with _open_asn_reader() as reader:

            response = reader.asn(normalized_ip)

            network = response.network

            result.update(
                {
                    "success": True,
                    "source": "MaxMind GeoIP",
                    "asn": (
                        response.autonomous_system_number
                        if response.autonomous_system_number
                        else None
                    ),
                    "organization": _safe_str(
                        response.autonomous_system_organization
                    ),
                    "network": (
                        str(network)
                        if network
                        else None
                    ),
                }
            )

            return result

    except geoip2.errors.AddressNotFoundError:
        result["error"] = (
            "IP address not present in ASN database"
        )
        return result

    except GeoIPError as exc:
        result["error"] = str(exc)
        return result

    except Exception as exc:
        result["error"] = (
            f"ASN lookup failed: {exc}"
        )
        return result


# ---------------------------------------------------------------------------
# Combined IP Intelligence
# ---------------------------------------------------------------------------

def analyze_geoip(ip: str) -> dict[str, Any]:
    """
    Perform combined geographic + ASN analysis.

    This is the primary function used by the orchestration layer.
    """

    normalized_ip = _normalize_ip(ip)

    city = lookup_city(normalized_ip)
    asn = lookup_asn(normalized_ip)

    return {
        "ip": normalized_ip,

        "success": (
            city["success"] or
            asn["success"]
        ),

        "classification": city.get(
            "classification"
        ),

        "is_public": city.get(
            "is_public",
            False
        ),

        "geolocation": {
            "country": city.get("country"),
            "country_code": city.get("country_code"),
            "continent": city.get("continent"),
            "region": city.get("region"),
            "region_code": city.get("region_code"),
            "city": city.get("city"),
            "latitude": city.get("latitude"),
            "longitude": city.get("longitude"),
            "accuracy_radius_km": city.get(
                "accuracy_radius_km"
            ),
            "timezone": city.get("timezone"),
        },

        "network": {
            "asn": asn.get("asn"),
            "organization": asn.get("organization"),
            "network": asn.get("network"),
        },

        "sources": {
            "geoip": city.get("source"),
            "asn": asn.get("source"),
        },

        "errors": [
            error
            for error in [
                city.get("error"),
                asn.get("error"),
            ]
            if error
        ],
    }


def analyze_ips(ips: list[str]) -> list[dict[str, Any]]:
    """
    Analyze multiple IP addresses.

    Invalid IPs are returned as failed results rather than
    stopping the complete investigation.
    """

    results = []

    seen = set()

    for ip in ips or []:

        try:
            normalized_ip = _normalize_ip(ip)

            if normalized_ip in seen:
                continue

            seen.add(normalized_ip)

            results.append(
                analyze_geoip(normalized_ip)
            )

        except Exception as exc:

            results.append(
                {
                    "ip": str(ip),
                    "success": False,
                    "classification": None,
                    "is_public": False,
                    "geolocation": {},
                    "network": {},
                    "sources": {},
                    "errors": [str(exc)],
                }
            )

    return results


# ---------------------------------------------------------------------------
# Risk / Evidence Signals
# ---------------------------------------------------------------------------

def build_geo_signals(
    geo_results: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Convert GeoIP intelligence into explainable evidence signals.

    IMPORTANT:
        Geolocation itself is NOT treated as proof of maliciousness.

    Geographic information is primarily contextual evidence.
    """

    signals: list[dict[str, Any]] = []

    for result in geo_results or []:

        if not result.get("success"):
            continue

        ip = result.get("ip")

        country = (
            result.get("geolocation", {})
            .get("country")
        )

        country_code = (
            result.get("geolocation", {})
            .get("country_code")
        )

        city = (
            result.get("geolocation", {})
            .get("city")
        )

        asn = (
            result.get("network", {})
            .get("asn")
        )

        organization = (
            result.get("network", {})
            .get("organization")
        )

        # Geographic observation.
        if country or city:

            location = ", ".join(
                part
                for part in [
                    city,
                    country,
                ]
                if part
            )

            signals.append(
                {
                    "type": "geoip_observation",
                    "severity": "informational",
                    "description": (
                        f"Observed IP {ip} geolocates to "
                        f"{location}."
                    ),
                    "evidence": {
                        "ip": ip,
                        "country": country,
                        "country_code": country_code,
                        "city": city,
                        "source": result.get(
                            "sources", {}
                        ).get("geoip"),
                    },
                }
            )

        # ASN observation.
        if asn or organization:

            network_name = organization or (
                f"AS{asn}"
                if asn
                else "unknown network"
            )

            signals.append(
                {
                    "type": "asn_observation",
                    "severity": "informational",
                    "description": (
                        f"IP {ip} is associated with "
                        f"{network_name}."
                    ),
                    "evidence": {
                        "ip": ip,
                        "asn": asn,
                        "organization": organization,
                        "source": result.get(
                            "sources", {}
                        ).get("asn"),
                    },
                }
            )

    return signals


# ---------------------------------------------------------------------------
# Convenience API
# ---------------------------------------------------------------------------

def get_ip_geolocation(ip: str) -> dict[str, Any]:
    """
    Compatibility wrapper.

    Useful if another service expects a function named
    get_ip_geolocation().
    """

    return analyze_geoip(ip)


def get_geoip_status() -> dict[str, Any]:
    """
    Public health/status endpoint helper.
    """

    return {
        "service": "GeoIP Intelligence",
        "status": (
            "ready"
            if GEOIP2_AVAILABLE
            else "dependency_missing"
        ),
        "geoip2_installed": GEOIP2_AVAILABLE,
        "city_database": str(CITY_DB_PATH),
        "city_database_available": CITY_DB_PATH.exists(),
        "asn_database": str(ASN_DB_PATH),
        "asn_database_available": ASN_DB_PATH.exists(),
    }


# ---------------------------------------------------------------------------
# Module Test
# ---------------------------------------------------------------------------

if __name__ == "__main__":

    print("=" * 60)
    print("GeoIP Intelligence Service")
    print("=" * 60)

    print("\n[STATUS]")
    print(get_geoip_status())

    test_ip = "8.8.8.8"

    print(f"\n[TEST] {test_ip}")

    try:
        result = analyze_geoip(test_ip)

        print(result)

    except Exception as exc:
        print(f"Error: {exc}")