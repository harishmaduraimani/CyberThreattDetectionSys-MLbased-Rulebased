import csv
import os
from joblib import dump
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score
from sklearn.model_selection import train_test_split
from detectors.url_detector import extract_url_features
from ml.url_ml_detector import features_to_list

DATA_PATH = "data/training_data.csv"
MODEL_PATH = "models/url_phishing_model.joblib"


def load_training_data():
    features = []
    labels = []
    with open(DATA_PATH, "r") as file:
        reader = csv.DictReader(file)
        for row in reader:
            url = row["url"]
            label = int(row["label"])
            url_features = extract_url_features(url)
            feature_list = features_to_list(url_features)
            features.append(feature_list)
            labels.append(label)

    return features, labels


def train_model():
    features, labels = load_training_data()
    x_train, x_test, y_train, y_test = train_test_split(
        features,
        labels,
        test_size=0.3,
        random_state=42
    )

    model = LogisticRegression(max_iter=1000)
    model.fit(x_train, y_train)

    predictions = model.predict(x_test)

    accuracy = accuracy_score(y_test, predictions)

    os.makedirs("models", exist_ok=True)

    dump(model, MODEL_PATH)

    print("Model trained successfully")
    print("Accuracy:", accuracy)
    print("Saved model:", MODEL_PATH)


if __name__ == "__main__":
    train_model()
