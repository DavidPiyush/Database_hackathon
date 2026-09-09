# Model 4 - Geo/Infrastructure Anomaly Engine
import requests
import ipaddress
import re
import json

def validate_ip(ip):

    try:
        ipaddress.ip_address(ip)
        return True

    except ValueError:
        return False    


def classify_ip(ip):

    try:
        address = ipaddress.ip_address(ip)

        if address.is_private:
            return "Private"

        if address.is_loopback:
            return "Loopback"

        if address.is_reserved:
            return "Reserved"

        if address.is_multicast:
            return "Multicast"

        return "Public"

    except ValueError:
        return "Invalid"


def extract_ips(text):

    pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"

    candidates = re.findall(pattern, text)

    valid_ips = []

    for ip in candidates:

        if validate_ip(ip) and ip not in valid_ips:
            valid_ips.append(ip)

    return valid_ips


def geolocate_ip(ip):

    if classify_ip(ip) != "Public":

        return {
            "ip": ip,
            "type": classify_ip(ip),
            "message": "Private/reserved IP - no public geolocation"
        }

    url = f"https://ipwho.is/{ip}"

    try:

        response = requests.get(
            url,
            timeout=10
        )

        data = response.json()

        if not data.get("success", False):

            return {
                "ip": ip,
                "error": data.get(
                    "message",
                    "Geolocation failed"
                )
            }

        return {
            "ip": ip,
            "type": "Public",
            "country": data.get("country"),
            "country_code": data.get("country_code"),
            "region": data.get("region"),
            "city": data.get("city"),
            "latitude": data.get("latitude"),
            "longitude": data.get("longitude"),
            "isp": data.get("connection", {}).get("isp"),
            "organization": data.get("connection", {}).get("org"),
            "asn": data.get("connection", {}).get("asn")
        }

    except Exception as e:

        return {
            "ip": ip,
            "error": str(e)
        }


def classify_infrastructure(info):

    text = " ".join([
        str(info.get("isp", "")),
        str(info.get("organization", ""))
    ]).lower()

    hosting_keywords = [
        "hosting",
        "cloud",
        "amazon",
        "aws",
        "google cloud",
        "microsoft azure",
        "digitalocean",
        "ovh",
        "hetzner",
        "vultr",
        "linode"
    ]

    vpn_keywords = [
        "vpn",
        "proxy",
        "anonymous",
        "tor"
    ]

    for keyword in vpn_keywords:

        if keyword in text:
            return "VPN/Proxy"

    for keyword in hosting_keywords:

        if keyword in text:
            return "Hosting/Cloud"

    return "General ISP"


def infrastructure_risk(info):

    score = 0
    findings = []

    infrastructure = classify_infrastructure(info)

    if infrastructure == "VPN/Proxy":

        score += 25

        findings.append(
            "IP appears associated with VPN/proxy infrastructure"
        )

    elif infrastructure == "Hosting/Cloud":

        score += 10

        findings.append(
            "IP appears associated with hosting/cloud infrastructure"
        )

    return score, findings


def geographic_anomaly(info, expected_country=None):

    score = 0
    findings = []

    if not expected_country:
        return score, findings

    actual_country = info.get(
        "country_code"
    )

    if not actual_country:
        return score, findings

    if actual_country.upper() != expected_country.upper():

        score += 10

        findings.append(
            f"Origin country ({actual_country}) "
            f"differs from expected country "
            f"({expected_country})"
        )

    return score, findings


def analyze_ip(ip, expected_country=None):

    result = geolocate_ip(ip)

    if "error" in result:

        return {
            "ip": ip,
            "score": 0,
            "findings": [
                result["error"]
            ],
            "information": result
        }

    score = 0
    findings = []

    # Infrastructure analysis
    infra_score, infra_findings = infrastructure_risk(
        result
    )

    score += infra_score
    findings.extend(infra_findings)

    # Geographic analysis
    geo_score, geo_findings = geographic_anomaly(
        result,
        expected_country
    )

    score += geo_score
    findings.extend(geo_findings)

    result["infrastructure_type"] = classify_infrastructure(
        result
    )

    result["risk_score"] = min(score, 100)

    result["findings"] = findings

    return result


def analyze_multiple_ips(
    ips,
    expected_country=None
):

    results = []

    for ip in ips:

        result = analyze_ip(
            ip,
            expected_country
        )

        results.append(result)

    return results


def model4_geo_analysis(
    email_text,
    expected_country=None
):

    ips = extract_ips(email_text)

    public_ips = [
        ip for ip in ips
        if classify_ip(ip) == "Public"
    ]

    private_ips = [
        ip for ip in ips
        if classify_ip(ip) == "Private"
    ]

    results = analyze_multiple_ips(
        public_ips,
        expected_country
    )

    total_score = 0
    findings = []

    for result in results:

        total_score += result.get(
            "risk_score",
            0
        )

        findings.extend(
            result.get(
                "findings",
                []
            )
        )

    return {

        "ips_found": ips,

        "public_ips": public_ips,

        "private_ips": private_ips,

        "ip_intelligence": results,

        "geo_infrastructure_score":
            min(total_score, 100),

        "findings": findings
    }