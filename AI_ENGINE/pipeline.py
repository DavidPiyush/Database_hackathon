import os
import joblib

from contracts import (
    EmailInput,
    ModelResult,
    PipelineResult
)

from model3.forensic_analyzer import forensic_analysis
from model4.geo_analyzer import model4_geo_analysis
from risk_engine.risk_engine import calculate_final_risk


# ============================================================
# MODEL PATHS
# ============================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

MODEL1_PATH = os.path.join(
    BASE_DIR,
    "model1",
    "model1.pkl"
)

VECTORIZER1_PATH = os.path.join(
    BASE_DIR,
    "model1",
    "vectorizer.pkl"
)

MODEL2_PATH = os.path.join(
    BASE_DIR,
    "model2",
    "model2.pkl"
)

VECTORIZER2_PATH = os.path.join(
    BASE_DIR,
    "model2",
    "model2_tfidf.pkl"
)


# ============================================================
# LOAD TRAINED MODELS
# ============================================================

print("Loading trained models...")

model1 = joblib.load(MODEL1_PATH)
vectorizer1 = joblib.load(VECTORIZER1_PATH)

model2 = joblib.load(MODEL2_PATH)
vectorizer2 = joblib.load(VECTORIZER2_PATH)

print("Models loaded successfully!")


# ============================================================
# MODEL 1 - PHISHING DETECTION
# ============================================================

def run_model1(email_text):

    vectorized_text = vectorizer1.transform(
        [email_text]
    )

    prediction = model1.predict(
        vectorized_text
    )[0]

    probabilities = model1.predict_proba(
        vectorized_text
    )[0]

    classes = model1.classes_

    # Find probability of SPAM
    spam_probability = 0.0

    for i, class_name in enumerate(classes):

        if str(class_name).lower() == "spam":
            spam_probability = float(probabilities[i])

    label = str(prediction)

    return {
        "model": "Model 1 - Phishing Detection",
        "label": label,
        "probability": spam_probability,
        "score": spam_probability * 100,
        "findings": [
            f"Phishing/Spam probability: "
            f"{spam_probability * 100:.2f}%"
        ],
        "details": {
            "prediction": label
        }
    }


# ============================================================
# MODEL 2 - BEC DETECTION
# ============================================================

def run_model2(subject, body):

    email_text = (
        "SUBJECT: "
        + str(subject)
        + " BODY: "
        + str(body)
    )

    vectorized_text = vectorizer2.transform(
        [email_text]
    )

    prediction = model2.predict(
        vectorized_text
    )[0]

    probabilities = model2.predict_proba(
        vectorized_text
    )[0]

    classes = model2.classes_

    # Find probability of BEC class
    bec_probability = 0.0

    for i, class_name in enumerate(classes):

        # Model 2 dataset uses 0 and 1.
        # 1 represents the positive/BEC class.
        if str(class_name) == "1":
            bec_probability = float(probabilities[i])

    label = str(prediction)

    return {
        "model": "Model 2 - BEC Detection",
        "label": label,
        "probability": bec_probability,
        "score": bec_probability * 100,
        "findings": [
            f"BEC probability: "
            f"{bec_probability * 100:.2f}%"
        ],
        "details": {
            "prediction": label
        }
    }


# ============================================================
# MODEL 3 - FORENSIC ANALYSIS
# ============================================================

def run_model3(file_path):

    if not file_path:

        return {
            "model": "Model 3 - Email Forensics",
            "label": "Unavailable",
            "probability": 0.0,
            "score": 0.0,
            "findings": [
                "No email file was provided for forensic analysis"
            ],
            "details": {}
        }

    if not os.path.exists(file_path):

        return {
            "model": "Model 3 - Email Forensics",
            "label": "Error",
            "probability": 0.0,
            "score": 0.0,
            "findings": [
                "Email file could not be found"
            ],
            "details": {}
        }

    result = forensic_analysis(file_path)

    forensic_score = result.get(
        "forensic_score",
        0
    )

    return {
        "model": "Model 3 - Email Forensics",
        "label": "Suspicious" if forensic_score >= 40 else "Normal",
        "probability": forensic_score / 100,
        "score": forensic_score,
        "findings": result.get(
            "findings",
            []
        ),
        "details": result
    }


# ============================================================
# MODEL 4 - GEO / INFRASTRUCTURE ANALYSIS
# ============================================================

def run_model4(email_text, expected_country=None):

    result = model4_geo_analysis(
        email_text,
        expected_country
    )

    geo_score = result.get(
        "geo_infrastructure_score",
        0
    )

    return {
        "model": "Model 4 - Geo/Infrastructure",
        "label": (
            "Suspicious"
            if geo_score >= 40
            else "Normal"
        ),
        "probability": geo_score / 100,
        "score": geo_score,
        "findings": result.get(
            "findings",
            []
        ),
        "details": result
    }


# ============================================================
# COMPLETE EMAIL ANALYSIS PIPELINE
# ============================================================

def analyze_email(
    email: EmailInput,
    expected_country=None
) -> PipelineResult:

    subject = email.get(
        "subject",
        ""
    )

    body = email.get(
        "body",
        ""
    )

    file_path = email.get(
        "file_path",
        ""
    )


    # --------------------------------------------------------
    # Combine subject + body
    # --------------------------------------------------------

    email_text = (
        "SUBJECT: "
        + str(subject)
        + "\nBODY: "
        + str(body)
    )


    # --------------------------------------------------------
    # Run Model 1
    # --------------------------------------------------------

    model1_result = run_model1(
        email_text
    )


    # --------------------------------------------------------
    # Run Model 2
    # --------------------------------------------------------

    model2_result = run_model2(
        subject,
        body
    )


    # --------------------------------------------------------
    # Run Model 3
    # --------------------------------------------------------

    model3_result = run_model3(
        file_path
    )


    # --------------------------------------------------------
    # Run Model 4
    # --------------------------------------------------------

    model4_result = run_model4(
        email_text,
        expected_country
    )


    # --------------------------------------------------------
    # Collect all results
    # --------------------------------------------------------

    model_results = [
        model1_result,
        model2_result,
        model3_result,
        model4_result
    ]


    # --------------------------------------------------------
    # Run Risk Engine
    # --------------------------------------------------------

    risk_result = calculate_final_risk(

        model1_result["probability"],

        model2_result["probability"],

        model3_result["details"],

        model4_result["details"]
    )


    # --------------------------------------------------------
    # Return complete result
    # --------------------------------------------------------

    return {
        "email": email,

        "model_results": model_results,

        "risk_result": risk_result
    }


# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":

    print("\nPipeline module loaded successfully.")

    print("Model 1:", MODEL1_PATH)
    print("Model 2:", MODEL2_PATH)

