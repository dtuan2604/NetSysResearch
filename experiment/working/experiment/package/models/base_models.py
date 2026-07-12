from sklearn.tree import DecisionTreeClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression

def create_logistic_regression(random_seed: int = 42) -> LogisticRegression:
    return LogisticRegression(
        solver="saga",
        max_iter=5000,
        random_state=random_seed,
        n_jobs=-1
    )

def create_knn() -> KNeighborsClassifier:
    return KNeighborsClassifier(
        n_neighbors=5,       # Explicitly indicated by the paper
        weights="uniform",   # scikit-learn 0.21 default
        algorithm="auto",
        leaf_size=30,
        metric="minkowski",
        p=2,                 # Minkowski p=2 = Euclidean distance
        n_jobs=-1,
    )

def create_decision_tree(random_seed: int = 42) -> DecisionTreeClassifier:
    return DecisionTreeClassifier(
        criterion="gini",
        splitter="best",
        max_depth=None,
        min_samples_split=2,
        min_samples_leaf=1,
        min_weight_fraction_leaf=0.0,
        max_features=None,
        max_leaf_nodes=None,
        min_impurity_decrease=0.0,
        class_weight=None,
        random_state=random_seed,
    )

def create_random_forest(random_seed: int = 42) -> RandomForestClassifier:
    return RandomForestClassifier(
        # Historical scikit-learn 0.21 default.
        # This changed to 100 in scikit-learn 0.22.
        n_estimators=10,

        criterion="gini",
        max_depth=None,
        min_samples_split=2,
        min_samples_leaf=1,
        min_weight_fraction_leaf=0.0,

        # In scikit-learn 0.21, the default was "auto",
        # which meant sqrt(n_features) for classification.
        # "sqrt" is the current compatible equivalent.
        max_features="sqrt",

        max_leaf_nodes=None,
        oob_score=False,
        class_weight=None,
        random_state=random_seed,
        n_jobs=-1,
    )


models = [
    # ("KNN", create_knn),
    ("DecisionTree", create_decision_tree),
    ("RandomForest", create_random_forest),
    # ("LogisticRegression", create_logistic_regression),
]