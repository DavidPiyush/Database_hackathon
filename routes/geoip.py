from fastapi import APIRouter, HTTPException

from services.geio import GeoIPError, analyze_geoip, get_geoip_status
from services.ip_intelligence import analyze_ip

router = APIRouter(prefix="/geoip", tags=["GeoIP"])


@router.get("/status")
async def geoip_status():
    """Return GeoIP database and dependency status."""
    return get_geoip_status()


@router.get("/{ip}")
async def geoip_lookup(ip: str):
    """Return geographic, ASN, and reverse-DNS context for an IP address."""
    try:
        geoip_result = analyze_geoip(ip)
        infrastructure_result = analyze_ip(ip, perform_reverse_dns=True)
    except GeoIPError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    data = {
        **geoip_result,
        "reverse_dns": infrastructure_result.get("reverse_dns"),
        "hostname_analysis": infrastructure_result.get("hostname_analysis"),
        "signals": infrastructure_result.get("signals", []),
    }

    return {
        "success": bool(data.get("success")),
        "data": data,
    }
