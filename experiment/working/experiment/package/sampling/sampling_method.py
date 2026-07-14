from imblearn.over_sampling import SMOTE
from imblearn.under_sampling import RandomUnderSampler

def create_SMOTE_sampler(random_seed: int = 42) -> SMOTE:
    """
    Create a SMOTE sampler for oversampling the minority class.

    Args:
        random_seed (int): Random seed for reproducibility.

    Returns:
        SMOTE: An instance of the SMOTE sampler.
    """
    return SMOTE(random_state=random_seed, k_neighbors=3)

def create_under_sampler(random_seed: int = 42) -> RandomUnderSampler:
    """
    Create a RandomUnderSampler for undersampling the majority class.

    Args:
        random_seed (int): Random seed for reproducibility.

    Returns:
        RandomUnderSampler: An instance of the RandomUnderSampler.
    """
    return RandomUnderSampler(random_state=random_seed)

sampling_strategies = [("RandomUnderSampler", create_under_sampler), ("SMOTE", create_SMOTE_sampler)]
    