import joblib


MODEL_PATH = r"AI_ENGINE\model1\model1.pkl"
VECTORIZER_PATH = r"AI_ENGINE\model1\vectorizer.pkl"


model = joblib.load(MODEL_PATH)
vectorizer = joblib.load(VECTORIZER_PATH)


tests = [
    (
        "Normal personal email",
        """
        Hi David,

        Just wanted to confirm that our meeting is scheduled for tomorrow
        at 10 AM. Please let me know if you need anything before then.

        Regards,
        Rahul
        """,
    ),
    (
        "Normal business email",
        """
        Hello,

        Please find the project status update attached. The development
        team has completed the planned tasks for this week.

        Regards,
        Project Team
        """,
    ),
    (
        "Obvious spam",
        """
        CONGRATULATIONS! You have won a $1,000,000 cash prize.
        Click here immediately to claim your reward.
        This offer expires today!
        """,
    ),
    (
        "Phishing-style email",
        """
        Your account has been suspended.

        We detected unusual activity on your account.
        Verify your account immediately by clicking the link below
        or your account will be permanently disabled.
        """,
    ),
    (
        "Urgent payment email",
        """
        URGENT ACTION REQUIRED

        Your payment account requires immediate verification.
        Confirm your billing information today to avoid interruption
        of your service.
        """,
    ),
]


print("=" * 70)
print("MODEL 1 - SPAM DETECTION TEST")
print("=" * 70)

print("\nModel:", type(model).__name__)
print("Classes:", model.classes_)
print("Model features:", model.coef_.shape[1])
print("Vectorizer features:", len(vectorizer.vocabulary_))
print("=" * 70)


for name, text in tests:
    X = vectorizer.transform([text])

    prediction = model.predict(X)[0]
    probabilities = model.predict_proba(X)[0]

    probability_map = dict(zip(model.classes_, probabilities))

    print(f"\n{name}")
    print("-" * 70)

    print("Prediction:", prediction)

    for label, probability in probability_map.items():
        print(f"{label:>5}: {probability * 100:.2f}%")

    print("Feature vector shape:", X.shape)


print("\n" + "=" * 70)
print("TEST COMPLETE")
print("=" * 70)