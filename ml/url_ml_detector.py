import os

from joblib import load


MODEL_PATH = "models/url_phishing_model.joblib"


def features_to_list(features):
    return [
        features["url_length"],
        features["uses_http"],
        features["uses_https"],
        features["uses_ip"],
        features["suspicious_word_count"],
        features["has_at_symbol"],
        features["dot_count"],
        features["hyphen_count"],
        features["path_length"]
    ]


def predict_ml_url_risk(features):
    # If model file does not exist, skip ML safely
    if not os.path.exists(MODEL_PATH):
        return None, "ML model not found, using rule-based score only"

    # Load trained model from disk
    model = load(MODEL_PATH)

    # Convert dictionary features into numeric list
    feature_list = features_to_list(features)

    # Model expects a list of rows, so wrap feature_list inside another list
    phishing_probability = model.predict_proba([feature_list])[0][1]
    ml_risk_score = int(phishing_probability * 100)
    return ml_risk_score, f"ML phishing probability score: {ml_risk_score}"
