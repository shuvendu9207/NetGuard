"""
ML Trainer
Trains a model from a labeled CSV dataset and saves it to disk.
"""

import pickle
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from extractor.feature_extractor import FEATURE_NAMES


def train(dataset_path: str,
          algorithm: str = "random_forest",
          output_path: str = "ml/models/model.pkl"):

    df = pd.read_csv(dataset_path)
    X = df[FEATURE_NAMES].values
    y = df["label"].astype("category").cat.codes.values

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    if algorithm == "random_forest":
        from sklearn.ensemble import RandomForestClassifier
        model = RandomForestClassifier(n_estimators=100, random_state=42)
    elif algorithm == "xgboost":
        from xgboost import XGBClassifier
        model = XGBClassifier(use_label_encoder=False, eval_metric="mlogloss")
    elif algorithm == "isolation_forest":
        from sklearn.ensemble import IsolationForest
        model = IsolationForest(contamination=0.05, random_state=42)
    elif algorithm == "one_class_svm":
        from sklearn.svm import OneClassSVM
        model = OneClassSVM(nu=0.05)
    elif algorithm == "logistic_regression":
        from sklearn.linear_model import LogisticRegression
        model = LogisticRegression(max_iter=1000)
    else:
        raise ValueError(f"Unknown algorithm: {algorithm}")

    model.fit(X_train, y_train)

    if hasattr(model, "predict"):
        y_pred = model.predict(X_test)
        print(classification_report(y_test, y_pred))

    with open(output_path, "wb") as f:
        pickle.dump(model, f)
    print(f"[Trainer] Model saved to {output_path}")
