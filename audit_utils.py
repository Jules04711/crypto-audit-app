"""
Audit Utilities Module

This module provides comprehensive audit utility functions for cryptocurrency auditing,
including risk assessment, control effectiveness rating, transaction sampling,
anomaly detection, statistical analysis, and data visualization helpers.
"""

import pandas as pd
import numpy as np
from typing import Dict, List, Tuple, Optional, Union, Any
from datetime import datetime, time, date
import random
from collections import Counter
import math


# =============================================================================
# RISK SCORE CALCULATION FUNCTIONS
# =============================================================================

def calculate_risk_score(likelihood: int, impact: int) -> int:
    """
    Calculate risk score based on likelihood and impact.

    Args:
        likelihood: Likelihood rating (1-5, where 5 is most likely)
        impact: Impact rating (1-5, where 5 is most severe)

    Returns:
        Risk score (1-25)

    Example:
        >>> calculate_risk_score(3, 4)
        12
    """
    if not (1 <= likelihood <= 5):
        raise ValueError("Likelihood must be between 1 and 5")
    if not (1 <= impact <= 5):
        raise ValueError("Impact must be between 1 and 5")

    return likelihood * impact


def get_risk_rating(score: int) -> str:
    """
    Get risk rating string based on risk score.

    Args:
        score: Risk score (1-25)

    Returns:
        Risk rating string ('Low', 'Medium', 'High', 'Critical')

    Example:
        >>> get_risk_rating(12)
        'High'
    """
    if score <= 4:
        return "Low"
    elif score <= 9:
        return "Medium"
    elif score <= 16:
        return "High"
    else:
        return "Critical"


def calculate_inherent_risk(factors: Dict[str, int]) -> float:
    """
    Calculate inherent risk score from multiple risk factors.

    Args:
        factors: Dictionary of risk factors with their scores (1-5)
                 e.g., {'complexity': 4, 'volume': 3, 'regulatory': 5}

    Returns:
        Weighted average inherent risk score (1.0-5.0)

    Example:
        >>> calculate_inherent_risk({'complexity': 4, 'volume': 3, 'regulatory': 5})
        4.0
    """
    if not factors:
        raise ValueError("At least one risk factor must be provided")

    for factor_name, score in factors.items():
        if not (1 <= score <= 5):
            raise ValueError(f"Factor '{factor_name}' score must be between 1 and 5")

    total_score = sum(factors.values())
    return total_score / len(factors)


def calculate_residual_risk(inherent: float, controls: Dict[str, float]) -> float:
    """
    Calculate residual risk after applying control effectiveness.

    Args:
        inherent: Inherent risk score (1.0-5.0)
        controls: Dictionary of control names and their effectiveness (0.0-1.0)
                  e.g., {'segregation_of_duties': 0.8, 'reconciliation': 0.7}

    Returns:
        Residual risk score after controls

    Example:
        >>> calculate_residual_risk(4.0, {'control1': 0.8, 'control2': 0.7})
        2.4
    """
    if not (1.0 <= inherent <= 5.0):
        raise ValueError("Inherent risk must be between 1.0 and 5.0")

    if not controls:
        return inherent

    for control_name, effectiveness in controls.items():
        if not (0.0 <= effectiveness <= 1.0):
            raise ValueError(f"Control '{control_name}' effectiveness must be between 0.0 and 1.0")

    # Calculate average control effectiveness
    avg_effectiveness = sum(controls.values()) / len(controls)

    # Residual risk = Inherent risk * (1 - control effectiveness)
    residual = inherent * (1 - avg_effectiveness)

    # Ensure minimum residual risk of 0.5 (risk can never be fully eliminated)
    return max(0.5, residual)


# =============================================================================
# CONTROL EFFECTIVENESS RATING FUNCTIONS
# =============================================================================

def rate_control_effectiveness(test_results: List[Dict[str, Any]]) -> float:
    """
    Calculate control effectiveness rating based on test results.

    Args:
        test_results: List of test result dictionaries with 'passed' boolean key
                      e.g., [{'test': 'test1', 'passed': True}, {'test': 'test2', 'passed': False}]

    Returns:
        Control effectiveness rating (0.0-1.0)

    Example:
        >>> rate_control_effectiveness([{'passed': True}, {'passed': True}, {'passed': False}])
        0.6666666666666666
    """
    if not test_results:
        raise ValueError("At least one test result must be provided")

    passed_count = sum(1 for result in test_results if result.get('passed', False))
    return passed_count / len(test_results)


def calculate_control_gap(expected: float, actual: float) -> float:
    """
    Calculate the gap between expected and actual control performance.

    Args:
        expected: Expected control performance (0.0-1.0)
        actual: Actual control performance (0.0-1.0)

    Returns:
        Gap score (0.0-1.0), where higher indicates larger gap

    Example:
        >>> calculate_control_gap(0.9, 0.7)
        0.2
    """
    if not (0.0 <= expected <= 1.0):
        raise ValueError("Expected performance must be between 0.0 and 1.0")
    if not (0.0 <= actual <= 1.0):
        raise ValueError("Actual performance must be between 0.0 and 1.0")

    return max(0.0, expected - actual)


def get_control_status(rating: float) -> str:
    """
    Get control status string based on effectiveness rating.

    Args:
        rating: Control effectiveness rating (0.0-1.0)

    Returns:
        Control status string ('Ineffective', 'Needs Improvement', 'Satisfactory', 'Effective')

    Example:
        >>> get_control_status(0.85)
        'Effective'
    """
    if rating < 0.5:
        return "Ineffective"
    elif rating < 0.7:
        return "Needs Improvement"
    elif rating < 0.85:
        return "Satisfactory"
    else:
        return "Effective"


# =============================================================================
# TRANSACTION SAMPLING ALGORITHMS
# =============================================================================

def random_sampling(population: pd.DataFrame, sample_size: int) -> pd.DataFrame:
    """
    Perform random sampling from a population of transactions.

    Args:
        population: DataFrame containing the population of transactions
        sample_size: Number of items to sample

    Returns:
        DataFrame containing the random sample

    Example:
        >>> df = pd.DataFrame({'id': range(100), 'amount': range(100)})
        >>> sample = random_sampling(df, 10)
        >>> len(sample)
        10
    """
    if sample_size <= 0:
        raise ValueError("Sample size must be positive")

    if sample_size > len(population):
        raise ValueError("Sample size cannot exceed population size")

    return population.sample(n=sample_size, random_state=None).reset_index(drop=True)


def stratified_sampling(
    population: pd.DataFrame,
    strata_column: str,
    sample_size: int
) -> pd.DataFrame:
    """
    Perform stratified sampling from a population of transactions.

    Args:
        population: DataFrame containing the population of transactions
        strata_column: Column name to use for stratification
        sample_size: Total number of items to sample

    Returns:
        DataFrame containing the stratified sample

    Example:
        >>> df = pd.DataFrame({'id': range(100), 'category': ['A']*50 + ['B']*50})
        >>> sample = stratified_sampling(df, 'category', 10)
        >>> len(sample)
        10
    """
    if strata_column not in population.columns:
        raise ValueError(f"Column '{strata_column}' not found in population")

    if sample_size <= 0:
        raise ValueError("Sample size must be positive")

    if sample_size > len(population):
        raise ValueError("Sample size cannot exceed population size")

    # Calculate proportion of each stratum
    strata_counts = population[strata_column].value_counts()
    total_population = len(population)

    samples = []
    remaining_sample_size = sample_size

    for stratum, count in strata_counts.items():
        # Calculate proportional sample size for this stratum
        stratum_proportion = count / total_population
        stratum_sample_size = max(1, int(sample_size * stratum_proportion))

        # Ensure we don't sample more than available in the stratum
        stratum_sample_size = min(stratum_sample_size, count, remaining_sample_size)

        if stratum_sample_size > 0:
            stratum_data = population[population[strata_column] == stratum]
            stratum_sample = stratum_data.sample(n=stratum_sample_size, random_state=None)
            samples.append(stratum_sample)
            remaining_sample_size -= stratum_sample_size

    result = pd.concat(samples, ignore_index=True) if samples else pd.DataFrame()
    return result.reset_index(drop=True)


def monetary_unit_sampling(
    population: pd.DataFrame,
    amount_column: str,
    sample_size: int,
    interval: Optional[float] = None
) -> pd.DataFrame:
    """
    Perform Monetary Unit Sampling (MUS) for audit testing.

    Args:
        population: DataFrame containing the population of transactions
        amount_column: Column name containing the monetary amounts
        sample_size: Number of items to sample
        interval: Sampling interval (if None, calculated automatically)

    Returns:
        DataFrame containing the MUS sample

    Example:
        >>> df = pd.DataFrame({'id': range(10), 'amount': [1000, 2000, 500, 1500, 3000, 800, 1200, 900, 2500, 600]})
        >>> sample = monetary_unit_sampling(df, 'amount', 5)
    """
    if amount_column not in population.columns:
        raise ValueError(f"Column '{amount_column}' not found in population")

    if sample_size <= 0:
        raise ValueError("Sample size must be positive")

    # Filter out zero and negative amounts
    valid_population = population[population[amount_column] > 0].copy()

    if len(valid_population) == 0:
        raise ValueError("No valid positive amounts found in population")

    if sample_size > len(valid_population):
        sample_size = len(valid_population)

    # Calculate total monetary value
    total_value = valid_population[amount_column].sum()

    # Calculate sampling interval if not provided
    if interval is None:
        interval = total_value / sample_size

    # Generate random starting point
    random_start = random.uniform(0, interval)

    # Create cumulative sum for selection
    valid_population = valid_population.reset_index(drop=True)
    valid_population['_cumsum'] = valid_population[amount_column].cumsum()

    # Select items based on monetary units
    selected_indices = set()
    current_point = random_start

    while current_point <= total_value and len(selected_indices) < sample_size:
        # Find the item that contains this monetary unit
        for idx, row in valid_population.iterrows():
            if row['_cumsum'] >= current_point:
                selected_indices.add(idx)
                break
        current_point += interval

    # Get selected rows
    sample = valid_population.loc[list(selected_indices)].drop(columns=['_cumsum'])

    return sample.reset_index(drop=True)


# =============================================================================
# ANOMALY DETECTION FUNCTIONS
# =============================================================================

def detect_outliers_zscore(
    data: Union[List[float], pd.Series],
    threshold: float = 3.0
) -> Dict[str, Any]:
    """
    Detect outliers using Z-score method.

    Args:
        data: List or Series of numerical values
        threshold: Z-score threshold for outlier detection (default: 3.0)

    Returns:
        Dictionary with outlier information including indices, values, and z-scores

    Example:
        >>> data = [10, 12, 11, 100, 13, 11, 12]
        >>> result = detect_outliers_zscore(data)
        >>> result['outlier_indices']
        [3]
    """
    if isinstance(data, list):
        data = pd.Series(data)

    if len(data) < 3:
        return {
            'outlier_indices': [],
            'outlier_values': [],
            'z_scores': [],
            'mean': float(data.mean()) if len(data) > 0 else 0,
            'std': float(data.std()) if len(data) > 0 else 0
        }

    mean = data.mean()
    std = data.std()

    if std == 0:
        return {
            'outlier_indices': [],
            'outlier_values': [],
            'z_scores': [0.0] * len(data),
            'mean': float(mean),
            'std': 0.0
        }

    z_scores = [(x - mean) / std for x in data]

    outlier_indices = [i for i, z in enumerate(z_scores) if abs(z) > threshold]
    outlier_values = [float(data.iloc[i]) for i in outlier_indices]

    return {
        'outlier_indices': outlier_indices,
        'outlier_values': outlier_values,
        'z_scores': z_scores,
        'mean': float(mean),
        'std': float(std)
    }


def detect_outliers_iqr(data: Union[List[float], pd.Series]) -> Dict[str, Any]:
    """
    Detect outliers using Interquartile Range (IQR) method.

    Args:
        data: List or Series of numerical values

    Returns:
        Dictionary with outlier information including indices, values, and boundaries

    Example:
        >>> data = [10, 12, 11, 100, 13, 11, 12]
        >>> result = detect_outliers_iqr(data)
        >>> result['outlier_indices']
        [3]
    """
    if isinstance(data, list):
        data = pd.Series(data)

    if len(data) < 4:
        return {
            'outlier_indices': [],
            'outlier_values': [],
            'q1': float(data.quantile(0.25)) if len(data) > 0 else 0,
            'q3': float(data.quantile(0.75)) if len(data) > 0 else 0,
            'iqr': 0,
            'lower_bound': 0,
            'upper_bound': 0
        }

    q1 = data.quantile(0.25)
    q3 = data.quantile(0.75)
    iqr = q3 - q1

    lower_bound = q1 - 1.5 * iqr
    upper_bound = q3 + 1.5 * iqr

    outlier_indices = [
        i for i, x in enumerate(data)
        if x < lower_bound or x > upper_bound
    ]
    outlier_values = [float(data.iloc[i]) for i in outlier_indices]

    return {
        'outlier_indices': outlier_indices,
        'outlier_values': outlier_values,
        'q1': float(q1),
        'q3': float(q3),
        'iqr': float(iqr),
        'lower_bound': float(lower_bound),
        'upper_bound': float(upper_bound)
    }


def detect_unusual_patterns(transactions: pd.DataFrame) -> Dict[str, List[int]]:
    """
    Detect unusual patterns in transaction data.

    Args:
        transactions: DataFrame with transaction data (expected columns: 'amount', 'timestamp')

    Returns:
        Dictionary with different pattern flags and their indices

    Example:
        >>> df = pd.DataFrame({
        ...     'amount': [100, 100, 100, 500, 100],
        ...     'timestamp': pd.date_range('2024-01-01', periods=5, freq='H')
        ... })
        >>> flags = detect_unusual_patterns(df)
    """
    flags = {
        'rapid_succession': [],
        'unusual_amounts': [],
        'split_transactions': []
    }

    # Check for rapid succession transactions (within 1 minute)
    if 'timestamp' in transactions.columns:
        transactions = transactions.copy()
        transactions['timestamp'] = pd.to_datetime(transactions['timestamp'])
        transactions = transactions.sort_values('timestamp')

        for i in range(1, len(transactions)):
            time_diff = (
                transactions['timestamp'].iloc[i] -
                transactions['timestamp'].iloc[i-1]
            ).total_seconds()

            if time_diff < 60:  # Less than 1 minute apart
                flags['rapid_succession'].extend([i-1, i])

        flags['rapid_succession'] = list(set(flags['rapid_succession']))

    # Check for unusual amounts using IQR
    if 'amount' in transactions.columns:
        outliers = detect_outliers_iqr(transactions['amount'])
        flags['unusual_amounts'] = outliers['outlier_indices']

        # Check for potential split transactions (similar amounts in sequence)
        amounts = transactions['amount'].tolist()
        for i in range(len(amounts) - 2):
            # Check if three consecutive amounts are similar (within 10%)
            if amounts[i] > 0:
                ratio1 = amounts[i+1] / amounts[i] if amounts[i] != 0 else 0
                ratio2 = amounts[i+2] / amounts[i] if amounts[i] != 0 else 0

                if 0.9 <= ratio1 <= 1.1 and 0.9 <= ratio2 <= 1.1:
                    flags['split_transactions'].extend([i, i+1, i+2])

        flags['split_transactions'] = list(set(flags['split_transactions']))

    return flags


def flag_round_numbers(
    amounts: Union[List[float], pd.Series],
    threshold: int = 100
) -> Dict[str, Any]:
    """
    Flag transactions with suspiciously round numbers.

    Args:
        amounts: List or Series of transaction amounts
        threshold: Minimum round number threshold to flag (default: 100)

    Returns:
        Dictionary with flagged indices and their values

    Example:
        >>> amounts = [1000, 1234.56, 5000, 999.99, 10000]
        >>> flagged = flag_round_numbers(amounts)
        >>> flagged['flagged_indices']
        [0, 2, 4]
    """
    if isinstance(amounts, list):
        amounts = pd.Series(amounts)

    flagged_indices = []
    flagged_values = []

    for i, amount in enumerate(amounts):
        # Check if the amount is a round number (divisible by threshold with no remainder)
        if amount >= threshold and amount % threshold == 0:
            flagged_indices.append(i)
            flagged_values.append(float(amount))

    return {
        'flagged_indices': flagged_indices,
        'flagged_values': flagged_values,
        'count': len(flagged_indices),
        'percentage': len(flagged_indices) / len(amounts) * 100 if len(amounts) > 0 else 0
    }


# =============================================================================
# STATISTICAL ANALYSIS HELPERS
# =============================================================================

def calculate_statistics(data: Union[List[float], pd.Series]) -> Dict[str, float]:
    """
    Calculate comprehensive statistics for a dataset.

    Args:
        data: List or Series of numerical values

    Returns:
        Dictionary with statistical measures (mean, std, min, max, median, etc.)

    Example:
        >>> data = [10, 20, 30, 40, 50]
        >>> stats = calculate_statistics(data)
        >>> stats['mean']
        30.0
    """
    if isinstance(data, list):
        data = pd.Series(data)

    if len(data) == 0:
        return {
            'mean': 0.0,
            'std': 0.0,
            'min': 0.0,
            'max': 0.0,
            'median': 0.0,
            'count': 0,
            'sum': 0.0,
            'variance': 0.0,
            'skewness': 0.0,
            'kurtosis': 0.0
        }

    return {
        'mean': float(data.mean()),
        'std': float(data.std()),
        'min': float(data.min()),
        'max': float(data.max()),
        'median': float(data.median()),
        'count': len(data),
        'sum': float(data.sum()),
        'variance': float(data.var()),
        'skewness': float(data.skew()) if len(data) > 2 else 0.0,
        'kurtosis': float(data.kurtosis()) if len(data) > 3 else 0.0
    }


def benford_law_analysis(amounts: Union[List[float], pd.Series]) -> Dict[str, Any]:
    """
    Perform Benford's Law analysis on transaction amounts.

    Benford's Law predicts that in naturally occurring datasets, the first digit
    follows a specific distribution (1 appears ~30.1%, 2 appears ~17.6%, etc.)

    Args:
        amounts: List or Series of transaction amounts

    Returns:
        Dictionary with chi-square result and conformity score

    Example:
        >>> amounts = [1234, 2345, 1567, 3456, 1890, 2100, 1500, 4500]
        >>> result = benford_law_analysis(amounts)
        >>> 'chi_square' in result
        True
    """
    if isinstance(amounts, list):
        amounts = pd.Series(amounts)

    # Expected Benford's Law distribution for first digit
    expected_benford = {
        1: 0.301,
        2: 0.176,
        3: 0.125,
        4: 0.097,
        5: 0.079,
        6: 0.067,
        7: 0.058,
        8: 0.051,
        9: 0.046
    }

    # Filter out zero and negative amounts
    valid_amounts = amounts[amounts > 0]

    if len(valid_amounts) == 0:
        return {
            'chi_square': 0.0,
            'conformity_score': 0.0,
            'observed_distribution': {},
            'expected_distribution': expected_benford,
            'digit_counts': {},
            'sample_size': 0
        }

    # Extract first digits
    first_digits = []
    for amount in valid_amounts:
        first_digit = int(str(abs(amount)).lstrip('0').replace('.', '')[0])
        if 1 <= first_digit <= 9:
            first_digits.append(first_digit)

    if len(first_digits) == 0:
        return {
            'chi_square': 0.0,
            'conformity_score': 0.0,
            'observed_distribution': {},
            'expected_distribution': expected_benford,
            'digit_counts': {},
            'sample_size': 0
        }

    # Count observed frequencies
    digit_counts = Counter(first_digits)
    total = len(first_digits)

    # Calculate observed distribution
    observed_distribution = {d: digit_counts.get(d, 0) / total for d in range(1, 10)}

    # Calculate chi-square statistic
    chi_square = 0.0
    for digit in range(1, 10):
        observed = digit_counts.get(digit, 0)
        expected = expected_benford[digit] * total
        if expected > 0:
            chi_square += ((observed - expected) ** 2) / expected

    # Calculate conformity score (inverse of chi-square, normalized)
    # Lower chi-square = better conformity
    # Critical value for chi-square with 8 degrees of freedom at 0.05 significance = 15.51
    conformity_score = max(0.0, min(1.0, 1 - (chi_square / 50)))

    return {
        'chi_square': chi_square,
        'conformity_score': conformity_score,
        'observed_distribution': observed_distribution,
        'expected_distribution': expected_benford,
        'digit_counts': dict(digit_counts),
        'sample_size': total
    }


def detect_duplicates(
    transactions: pd.DataFrame,
    columns: List[str]
) -> pd.DataFrame:
    """
    Detect duplicate transactions based on specified columns.

    Args:
        transactions: DataFrame containing transaction data
        columns: List of column names to check for duplicates

    Returns:
        DataFrame containing only the duplicate rows

    Example:
        >>> df = pd.DataFrame({
        ...     'amount': [100, 200, 100, 300, 200],
        ...     'date': ['2024-01-01', '2024-01-02', '2024-01-01', '2024-01-03', '2024-01-02']
        ... })
        >>> duplicates = detect_duplicates(df, ['amount', 'date'])
    """
    for col in columns:
        if col not in transactions.columns:
            raise ValueError(f"Column '{col}' not found in transactions")

    # Find all duplicates (keep all occurrences)
    duplicates = transactions[transactions.duplicated(subset=columns, keep=False)]

    return duplicates.reset_index(drop=True)


# =============================================================================
# DATA VISUALIZATION HELPERS
# =============================================================================

def create_risk_heatmap_data(risks: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Create data structure for risk heatmap visualization.

    Args:
        risks: List of risk dictionaries with 'name', 'likelihood', and 'impact' keys

    Returns:
        Dictionary with heatmap matrix and metadata

    Example:
        >>> risks = [
        ...     {'name': 'Risk A', 'likelihood': 3, 'impact': 4},
        ...     {'name': 'Risk B', 'likelihood': 2, 'impact': 5}
        ... ]
        >>> heatmap = create_risk_heatmap_data(risks)
    """
    # Initialize 5x5 matrix for likelihood x impact
    matrix = [[[] for _ in range(5)] for _ in range(5)]

    for risk in risks:
        likelihood = risk.get('likelihood', 1)
        impact = risk.get('impact', 1)
        name = risk.get('name', 'Unknown Risk')

        # Adjust for 0-based indexing
        likelihood_idx = max(0, min(4, likelihood - 1))
        impact_idx = max(0, min(4, impact - 1))

        matrix[likelihood_idx][impact_idx].append({
            'name': name,
            'score': likelihood * impact,
            'rating': get_risk_rating(likelihood * impact)
        })

    # Create summary counts
    counts = {
        'Low': 0,
        'Medium': 0,
        'High': 0,
        'Critical': 0
    }

    for risk in risks:
        score = risk.get('likelihood', 1) * risk.get('impact', 1)
        rating = get_risk_rating(score)
        counts[rating] += 1

    return {
        'matrix': matrix,
        'counts': counts,
        'total_risks': len(risks),
        'labels': {
            'likelihood': ['Rare', 'Unlikely', 'Possible', 'Likely', 'Almost Certain'],
            'impact': ['Insignificant', 'Minor', 'Moderate', 'Major', 'Catastrophic']
        }
    }


def create_transaction_timeline_data(transactions: pd.DataFrame) -> Dict[str, Any]:
    """
    Create data structure for transaction timeline visualization.

    Args:
        transactions: DataFrame with 'timestamp' and 'amount' columns

    Returns:
        Dictionary with timeline data organized by time periods

    Example:
        >>> df = pd.DataFrame({
        ...     'timestamp': pd.date_range('2024-01-01', periods=10, freq='D'),
        ...     'amount': [100, 200, 150, 300, 250, 180, 220, 190, 280, 210]
        ... })
        >>> timeline = create_transaction_timeline_data(df)
    """
    if 'timestamp' not in transactions.columns:
        raise ValueError("Transactions must have a 'timestamp' column")

    transactions = transactions.copy()
    transactions['timestamp'] = pd.to_datetime(transactions['timestamp'])

    # Sort by timestamp
    transactions = transactions.sort_values('timestamp')

    # Daily aggregation
    daily_data = transactions.set_index('timestamp').resample('D').agg({
        'amount': ['sum', 'count', 'mean'] if 'amount' in transactions.columns else ['count']
    }).reset_index()

    # Flatten column names
    if 'amount' in transactions.columns:
        daily_data.columns = ['date', 'total_amount', 'count', 'avg_amount']
    else:
        daily_data.columns = ['date', 'count']

    # Hourly distribution (aggregate across all days)
    transactions['hour'] = transactions['timestamp'].dt.hour
    hourly_distribution = transactions.groupby('hour').size().to_dict()

    # Day of week distribution
    transactions['day_of_week'] = transactions['timestamp'].dt.day_name()
    dow_distribution = transactions.groupby('day_of_week').size().to_dict()

    return {
        'daily_data': daily_data.to_dict('records'),
        'hourly_distribution': hourly_distribution,
        'day_of_week_distribution': dow_distribution,
        'date_range': {
            'start': str(transactions['timestamp'].min()),
            'end': str(transactions['timestamp'].max())
        },
        'total_transactions': len(transactions)
    }


def create_control_status_summary(controls: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Create summary of control statuses for visualization.

    Args:
        controls: List of control dictionaries with 'name' and 'effectiveness' keys

    Returns:
        Dictionary with control status summary

    Example:
        >>> controls = [
        ...     {'name': 'Control A', 'effectiveness': 0.9},
        ...     {'name': 'Control B', 'effectiveness': 0.6},
        ...     {'name': 'Control C', 'effectiveness': 0.3}
        ... ]
        >>> summary = create_control_status_summary(controls)
    """
    status_counts = {
        'Effective': 0,
        'Satisfactory': 0,
        'Needs Improvement': 0,
        'Ineffective': 0
    }

    control_details = []

    for control in controls:
        name = control.get('name', 'Unknown Control')
        effectiveness = control.get('effectiveness', 0.0)
        status = get_control_status(effectiveness)

        status_counts[status] += 1
        control_details.append({
            'name': name,
            'effectiveness': effectiveness,
            'status': status
        })

    # Calculate overall effectiveness
    if controls:
        avg_effectiveness = sum(c.get('effectiveness', 0) for c in controls) / len(controls)
    else:
        avg_effectiveness = 0.0

    return {
        'status_counts': status_counts,
        'control_details': control_details,
        'total_controls': len(controls),
        'average_effectiveness': avg_effectiveness,
        'overall_status': get_control_status(avg_effectiveness)
    }


# =============================================================================
# UNUSUAL TIMING ANALYSIS
# =============================================================================

def detect_off_hours_transactions(
    transactions: pd.DataFrame,
    business_hours: Tuple[int, int] = (9, 17)
) -> Dict[str, Any]:
    """
    Detect transactions occurring outside business hours.

    Args:
        transactions: DataFrame with 'timestamp' column
        business_hours: Tuple of (start_hour, end_hour) in 24-hour format

    Returns:
        Dictionary with flagged transaction indices and statistics

    Example:
        >>> df = pd.DataFrame({
        ...     'timestamp': ['2024-01-01 10:00:00', '2024-01-01 22:00:00', '2024-01-01 03:00:00'],
        ...     'amount': [100, 200, 300]
        ... })
        >>> result = detect_off_hours_transactions(df)
    """
    if 'timestamp' not in transactions.columns:
        raise ValueError("Transactions must have a 'timestamp' column")

    transactions = transactions.copy()
    transactions['timestamp'] = pd.to_datetime(transactions['timestamp'])
    transactions['hour'] = transactions['timestamp'].dt.hour

    start_hour, end_hour = business_hours

    # Identify off-hours transactions
    off_hours_mask = (transactions['hour'] < start_hour) | (transactions['hour'] >= end_hour)
    flagged_indices = transactions[off_hours_mask].index.tolist()

    # Calculate statistics
    total = len(transactions)
    off_hours_count = len(flagged_indices)

    # Hour distribution of off-hours transactions
    off_hours_distribution = transactions[off_hours_mask]['hour'].value_counts().to_dict()

    return {
        'flagged_indices': flagged_indices,
        'flagged_count': off_hours_count,
        'total_count': total,
        'percentage': off_hours_count / total * 100 if total > 0 else 0,
        'hour_distribution': off_hours_distribution,
        'business_hours': business_hours
    }


def detect_weekend_transactions(transactions: pd.DataFrame) -> Dict[str, Any]:
    """
    Detect transactions occurring on weekends.

    Args:
        transactions: DataFrame with 'timestamp' column

    Returns:
        Dictionary with flagged transaction indices and statistics

    Example:
        >>> df = pd.DataFrame({
        ...     'timestamp': ['2024-01-01', '2024-01-06', '2024-01-07'],  # Mon, Sat, Sun
        ...     'amount': [100, 200, 300]
        ... })
        >>> result = detect_weekend_transactions(df)
    """
    if 'timestamp' not in transactions.columns:
        raise ValueError("Transactions must have a 'timestamp' column")

    transactions = transactions.copy()
    transactions['timestamp'] = pd.to_datetime(transactions['timestamp'])
    transactions['day_of_week'] = transactions['timestamp'].dt.dayofweek

    # Weekend is Saturday (5) and Sunday (6)
    weekend_mask = transactions['day_of_week'].isin([5, 6])
    flagged_indices = transactions[weekend_mask].index.tolist()

    # Calculate statistics
    total = len(transactions)
    weekend_count = len(flagged_indices)

    # Count by day
    day_names = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
    weekend_distribution = {
        day_names[5]: len(transactions[transactions['day_of_week'] == 5]),
        day_names[6]: len(transactions[transactions['day_of_week'] == 6])
    }

    return {
        'flagged_indices': flagged_indices,
        'flagged_count': weekend_count,
        'total_count': total,
        'percentage': weekend_count / total * 100 if total > 0 else 0,
        'weekend_distribution': weekend_distribution
    }


def detect_holiday_transactions(
    transactions: pd.DataFrame,
    holidays: List[Union[str, date]]
) -> Dict[str, Any]:
    """
    Detect transactions occurring on specified holidays.

    Args:
        transactions: DataFrame with 'timestamp' column
        holidays: List of holiday dates (strings in 'YYYY-MM-DD' format or date objects)

    Returns:
        Dictionary with flagged transaction indices and statistics

    Example:
        >>> df = pd.DataFrame({
        ...     'timestamp': ['2024-01-01', '2024-01-02', '2024-12-25'],
        ...     'amount': [100, 200, 300]
        ... })
        >>> holidays = ['2024-01-01', '2024-12-25']
        >>> result = detect_holiday_transactions(df, holidays)
    """
    if 'timestamp' not in transactions.columns:
        raise ValueError("Transactions must have a 'timestamp' column")

    transactions = transactions.copy()
    transactions['timestamp'] = pd.to_datetime(transactions['timestamp'])
    transactions['date'] = transactions['timestamp'].dt.date

    # Convert holidays to date objects
    holiday_dates = set()
    for holiday in holidays:
        if isinstance(holiday, str):
            holiday_dates.add(pd.to_datetime(holiday).date())
        else:
            holiday_dates.add(holiday)

    # Identify holiday transactions
    holiday_mask = transactions['date'].isin(holiday_dates)
    flagged_indices = transactions[holiday_mask].index.tolist()

    # Calculate statistics
    total = len(transactions)
    holiday_count = len(flagged_indices)

    # Count by holiday
    holiday_distribution = {}
    for holiday in holiday_dates:
        count = len(transactions[transactions['date'] == holiday])
        if count > 0:
            holiday_distribution[str(holiday)] = count

    return {
        'flagged_indices': flagged_indices,
        'flagged_count': holiday_count,
        'total_count': total,
        'percentage': holiday_count / total * 100 if total > 0 else 0,
        'holiday_distribution': holiday_distribution,
        'holidays_checked': [str(h) for h in holiday_dates]
    }
