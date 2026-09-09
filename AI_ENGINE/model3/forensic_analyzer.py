# Model 3 - Email Forensic Analysis Engine
import re
import email
import json
import os
import ipaddress

from email import policy
from email.parser import BytesParser
from email.utils import parseaddr, parsedate_to_datetime
def parse_email(file_path):

    with open(file_path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    return msg


def extract_headers(msg):

    headers = {}

    headers["from"] = msg.get("From", "")
    headers["to"] = msg.get("To", "")
    headers["cc"] = msg.get("Cc", "")
    headers["reply_to"] = msg.get("Reply-To", "")
    headers["return_path"] = msg.get("Return-Path", "")
    headers["subject"] = msg.get("Subject", "")
    headers["date"] = msg.get("Date", "")
    headers["message_id"] = msg.get("Message-ID", "")
    headers["mime_version"] = msg.get("MIME-Version", "")
    headers["content_type"] = msg.get("Content-Type", "")

    return headers


def extract_authentication(msg):

    auth = {
        "spf": "unknown",
        "dkim": "unknown",
        "dmarc": "unknown"
    }

    authentication_results = msg.get_all(
        "Authentication-Results",
        []
    )

    auth_text = " ".join(
        str(x) for x in authentication_results
    ).lower()

    # SPF
    if re.search(r"\bspf=pass\b", auth_text):
        auth["spf"] = "pass"
    elif re.search(r"\bspf=fail\b", auth_text):
        auth["spf"] = "fail"
    elif re.search(r"\bspf=softfail\b", auth_text):
        auth["spf"] = "softfail"
    elif re.search(r"\bspf=neutral\b", auth_text):
        auth["spf"] = "neutral"

    # DKIM
    if re.search(r"\bdkim=pass\b", auth_text):
        auth["dkim"] = "pass"
    elif re.search(r"\bdkim=fail\b", auth_text):
        auth["dkim"] = "fail"

    # DMARC
    if re.search(r"\bdmarc=pass\b", auth_text):
        auth["dmarc"] = "pass"
    elif re.search(r"\bdmarc=fail\b", auth_text):
        auth["dmarc"] = "fail"

    return auth


def authentication_score(auth):

    score = 0
    findings = []

    if auth["spf"] == "fail":
        score += 25
        findings.append("SPF authentication failed")

    elif auth["spf"] == "softfail":
        score += 15
        findings.append("SPF softfail")

    if auth["dkim"] == "fail":
        score += 25
        findings.append("DKIM authentication failed")

    if auth["dmarc"] == "fail":
        score += 30
        findings.append("DMARC authentication failed")

    if (
        auth["spf"] == "pass"
        and auth["dkim"] == "pass"
        and auth["dmarc"] == "pass"
    ):
        findings.append(
            "SPF, DKIM and DMARC passed"
        )

    return score, findings


def extract_received_headers(msg):

    received = msg.get_all("Received", [])

    return [
        str(header)
        for header in received
    ]


def extract_ips_from_received(received_headers):

    ips = []

    for header in received_headers:

        found_ips = re.findall(
            r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
            header
        )

        for ip in found_ips:

            try:
                ipaddress.ip_address(ip)

                if ip not in ips:
                    ips.append(ip)

            except ValueError:
                pass

    return ips


def analyze_ip_addresses(ips):

    results = []

    for ip in ips:

        address = ipaddress.ip_address(ip)

        if address.is_private:
            classification = "Private IP"

        elif address.is_loopback:
            classification = "Loopback"

        elif address.is_reserved:
            classification = "Reserved"

        else:
            classification = "Public IP"

        results.append({
            "ip": ip,
            "type": classification
        })

    return results


def analyze_sender(headers):

    findings = []
    score = 0

    from_address = parseaddr(
        headers["from"]
    )[1].lower()

    reply_address = parseaddr(
        headers["reply_to"]
    )[1].lower()

    return_path = parseaddr(
        headers["return_path"]
    )[1].lower()

    # From vs Reply-To
    if (
        from_address
        and reply_address
        and from_address != reply_address
    ):
        score += 20

        findings.append(
            "From and Reply-To addresses differ"
        )

    # From vs Return-Path
    if (
        from_address
        and return_path
        and from_address.split("@")[-1]
        != return_path.split("@")[-1]
    ):
        score += 15

        findings.append(
            "From and Return-Path domains differ"
        )

    return score, findings


def check_reply_to(headers):

    reply_to = parseaddr(
        headers["reply_to"]
    )[1]

    sender = parseaddr(
        headers["from"]
    )[1]

    if not reply_to or not sender:
        return 0, []

    sender_domain = sender.split("@")[-1].lower()
    reply_domain = reply_to.split("@")[-1].lower()

    if sender_domain != reply_domain:

        return (
            20,
            [
                "Reply-To uses a different domain "
                "than the sender"
            ]
        )

    return 0, []


def check_message_id(headers):

    message_id = headers["message_id"]

    if not message_id:

        return (
            10,
            ["Missing Message-ID header"]
        )

    if "@" not in message_id:

        return (
            10,
            ["Malformed Message-ID"]
        )

    return 0, []


def check_date_header(headers):

    date_value = headers["date"]

    if not date_value:

        return (
            10,
            ["Missing Date header"]
        )

    try:

        parsedate_to_datetime(
            date_value
        )

        return 0, []

    except Exception:

        return (
            10,
            ["Malformed Date header"]
        )


def analyze_mime(msg):

    score = 0
    findings = []

    if msg.is_multipart():

        for part in msg.walk():

            content_type = part.get_content_type()
            content_disposition = (
                part.get("Content-Disposition", "")
            )

            # Executable attachments
            filename = part.get_filename()

            if filename:

                suspicious_extensions = (
                    ".exe",
                    ".scr",
                    ".bat",
                    ".cmd",
                    ".js",
                    ".vbs",
                    ".ps1",
                    ".jar"
                )

                if filename.lower().endswith(
                    suspicious_extensions
                ):

                    score += 30

                    findings.append(
                        f"Suspicious attachment: {filename}"
                    )

            # HTML content
            if content_type == "text/html":

                findings.append(
                    "HTML email body detected"
                )

    return score, findings


def analyze_encoding(msg):

    score = 0
    findings = []

    raw_email = str(msg)

    # Base64-like blocks
    base64_blocks = re.findall(
        r"[A-Za-z0-9+/]{80,}={0,2}",
        raw_email
    )

    if base64_blocks:

        score += 10

        findings.append(
            "Large Base64-encoded content detected"
        )

    # Zero-width Unicode characters
    zero_width = re.findall(
        r"[\u200B-\u200F\uFEFF]",
        raw_email
    )

    if zero_width:

        score += 20

        findings.append(
            "Zero-width Unicode characters detected"
        )

    return score, findings


def extract_body(msg):

    body = ""

    if msg.is_multipart():

        for part in msg.walk():

            if part.get_content_type() == "text/plain":

                try:
                    body += part.get_content()

                except Exception:
                    pass

    else:

        try:
            body = msg.get_content()

        except Exception:
            body = ""

    return body


def forensic_analysis(file_path):

    msg = parse_email(file_path)

    headers = extract_headers(msg)

    auth = extract_authentication(msg)

    received = extract_received_headers(msg)

    ips = extract_ips_from_received(
        received
    )

    ip_analysis = analyze_ip_addresses(
        ips
    )

    total_score = 0
    findings = []

    # Authentication
    score, result = authentication_score(auth)
    total_score += score
    findings.extend(result)

    # Sender identity
    score, result = analyze_sender(headers)
    total_score += score
    findings.extend(result)

    # Reply-To
    score, result = check_reply_to(headers)
    total_score += score
    findings.extend(result)

    # Message ID
    score, result = check_message_id(headers)
    total_score += score
    findings.extend(result)

    # Date
    score, result = check_date_header(headers)
    total_score += score
    findings.extend(result)

    # MIME
    score, result = analyze_mime(msg)
    total_score += score
    findings.extend(result)

    # Encoding
    score, result = analyze_encoding(msg)
    total_score += score
    findings.extend(result)

    return {
        "forensic_score": min(total_score, 100),
        "authentication": auth,
        "received_headers": received,
        "ip_addresses": ip_analysis,
        "findings": findings,
        "headers": headers
    }


