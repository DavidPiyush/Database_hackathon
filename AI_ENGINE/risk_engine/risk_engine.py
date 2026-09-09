
def clamp(value, minimum=0, maximum=100):
    """Keep a numeric value within a specified range."""
    try:
        value = float(value)
    except (TypeError, ValueError):
        return minimum

    return max(minimum, min(value, maximum))


def probability_to_score(probability):
    """Convert probability from 0-1 to risk score 0-100."""
    try:
        return clamp(float(probability) * 100)
    except (TypeError, ValueError):
        return 0.0


def calculate_forensic_score(forensic_result):
    """Convert Model 3 forensic analysis into a 0-100 risk score."""
    if not isinstance(forensic_result, dict):
        return 0.0

    return clamp(forensic_result.get("forensic_score", 0))


def calculate_geo_score(geo_result):
    """Convert Model 4 geo/infrastructure analysis into a 0-100 risk score."""
    if not isinstance(geo_result, dict):
        return 0.0

    return clamp(geo_result.get("geo_infrastructure_score", 0))


def get_threat_level(score):
    """Convert final risk score into a threat classification."""
    score = clamp(score)

    if score >= 80:
        return "CRITICAL"
    elif score >= 60:
        return "HIGH"
    elif score >= 40:
        return "MEDIUM"
    elif score >= 20:
        return "LOW"
    else:
        return "SAFE"


def generate_risk_factors(model1_score, model2_score, forensic_result, geo_result):
    """Generate human-readable reasons for the final risk score."""
    factors = []

    if model1_score >= 80:
        factors.append(f"High phishing probability ({model1_score:.1f}%)")
    elif model1_score >= 60:
        factors.append(f"Elevated phishing probability ({model1_score:.1f}%)")

    if model2_score >= 80:
        factors.append(f"High BEC/social-engineering probability ({model2_score:.1f}%)")
    elif model2_score >= 60:
        factors.append(f"Elevated BEC/social-engineering probability ({model2_score:.1f}%)")

    if isinstance(forensic_result, dict):
        factors.extend(forensic_result.get("findings", []))

    if isinstance(geo_result, dict):
        factors.extend(geo_result.get("findings", []))

    return factors


def calculate_final_risk(model1_probability, model2_probability, forensic_result, geo_result):
    """Combine Models 1-4 into a final threat assessment."""

    model1_score = probability_to_score(model1_probability)
    model2_score = probability_to_score(model2_probability)
    model3_score = calculate_forensic_score(forensic_result)
    model4_score = calculate_geo_score(geo_result)

    W_MODEL1 = 0.30
    W_MODEL2 = 0.25
    W_MODEL3 = 0.30
    W_MODEL4 = 0.15

    final_score = (
        model1_score * W_MODEL1
        + model2_score * W_MODEL2
        + model3_score * W_MODEL3
        + model4_score * W_MODEL4
    )

    final_score = clamp(final_score)
    threat_level = get_threat_level(final_score)

    factors = generate_risk_factors(model1_score, model2_score, forensic_result, geo_result)

    return {
        "final_score": round(final_score, 2),
        "threat_level": threat_level,
        "model_scores": {
            "model1_phishing": round(model1_score, 2),
            "model2_bec": round(model2_score, 2),
            "model3_forensics": round(model3_score, 2),
            "model4_geo": round(model4_score, 2),
        },
        "weights": {
            "model1": W_MODEL1,
            "model2": W_MODEL2,
            "model3": W_MODEL3,
            "model4": W_MODEL4,
        },
        "risk_factors": factors,
        "forensics": forensic_result,
        "geo_intelligence": geo_result,
    }
    
