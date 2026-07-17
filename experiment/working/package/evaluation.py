from collections import defaultdict
import time
from .sampling import sampling_strategies
from .models import models
from sklearn.model_selection import StratifiedKFold
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import precision_score, recall_score, f1_score, accuracy_score
from numpy.typing import NDArray
from typing import Dict
import pandas as pd
import numpy as np

RANDOM_SEED = 42
KFOLD = 5
def evaluate(y_pred: pd.DataFrame, y_true: pd.DataFrame, labels: NDArray) -> Dict[str, float]:
    precisions = precision_score(y_true=y_true, y_pred=y_pred, labels=labels, average=None)
    recalls = recall_score(y_true=y_true, y_pred=y_pred, labels=labels, average=None)
    f1_scores = f1_score(y_true=y_true, y_pred=y_pred, labels=labels, average=None)
    accuracy = accuracy_score(y_true=y_true, y_pred=y_pred)

    metric_dict = {"accuracy": accuracy}
    for index, label in enumerate(labels):
        metric_dict[f"precision_class_{label}"] = precisions[index]
        metric_dict[f"recall_class_{label}"] = recalls[index]
        metric_dict[f"f1_class_{label}"] = f1_scores[index]
    
    return metric_dict


def training_and_evaluation(X: pd.DataFrame, y: pd.DataFrame, average_metric_plotting: bool = False) -> pd.DataFrame:
    stratifiedKFold = StratifiedKFold(n_splits=KFOLD)
    training_and_validation_set = defaultdict(list)
    for sample_method, create_sampler in sampling_strategies:
        for train_indices, val_indices in stratifiedKFold.split(X=X, y=y):
            X_train, y_train = X.iloc[train_indices].reset_index(drop=True), y.iloc[train_indices].reset_index(drop=True)
            X_val, y_val = X.iloc[val_indices].reset_index(drop=True), y.iloc[val_indices].reset_index(drop=True)
            sampler = create_sampler()

            X_sample, y_sample = sampler.fit_resample(X_train, y_train)
            training_and_validation_set[sample_method].append((X_sample, y_sample, X_val, y_val))
    
    print(f"Training and evaluating with:\nFeatures: {X.columns.to_list()}\nLabel: {np.unique(y)}")

    metrics = []
    for sample_method in training_and_validation_set:
        for model_name, create_model in models:
            print(f"\tStart KStratifiedKFold (k={KFOLD}) for: model={model_name}, sample_method={sample_method}, scaler=StandardScaler")
            for iteration, (X_sample, y_sample, X_val, y_val) in enumerate(training_and_validation_set[sample_method]):
                labels = np.unique(y_val)

                scaler = StandardScaler()
                model = create_model()

                X_sample_scaled = scaler.fit_transform(X_sample)
                X_val_scaled = scaler.transform(X_val)

                startTime = time.perf_counter()
                model.fit(X_sample_scaled, y_sample)
                endTime = time.perf_counter()

                y_val_pred = model.predict(X_val_scaled)

                metric_dict = evaluate(y_val_pred, y_val, labels)
                metric_dict["model"] = model_name
                metric_dict["sample_method"] = sample_method
                metric_dict["iteration"] = iteration
                metric_dict["labels"] = labels
                metric_dict["train_time"] = endTime - startTime
                metrics.append(metric_dict)

    return pd.DataFrame(metrics)


                
