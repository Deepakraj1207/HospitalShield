"""
data_loader.py - Data loading, filtering, sorting, and defensive metric calculations
HospitalShield Level 1 — Network Exposure Dashboard
"""

from pathlib import Path
from typing import Dict, Any, Tuple, Optional, List
import pandas as pd


def get_default_csv_path() -> Path:
    """Resolve the default absolute path to level1_exposure.csv."""
    base_dir = Path(__file__).resolve().parent.parent
    return base_dir / "data" / "level1_exposure.csv"


def load_exposure_data(csv_path: Optional[str | Path] = None) -> pd.DataFrame:
    """
    Load the synthetic Level 1 network exposure records from CSV for Demo Mode.
    
    Returns:
        pd.DataFrame: Validated DataFrame containing the scenario records.
    """
    path = Path(csv_path) if csv_path else get_default_csv_path()
    
    if not path.exists():
        raise FileNotFoundError(
            f"Dataset not found at: {path}. "
            "Please ensure 'level1_exposure.csv' exists in the 'data/' directory."
        )
        
    df = pd.read_csv(path)
    
    # Required columns
    expected_cols = {"port", "service", "detail", "risk"}
    if not expected_cols.issubset(set(df.columns)):
        missing = expected_cols - set(df.columns)
        raise ValueError(f"Dataset is missing required columns: {missing}")
        
    # Standardize types and formatting
    df["port"] = df["port"].astype(int)
    df["risk"] = df["risk"].str.strip().str.capitalize()
    df["service"] = df["service"].str.strip()
    df["detail"] = df["detail"].str.strip()
    
    # In demo mode, all scenario services are open/reachable
    if "state" not in df.columns:
        df["state"] = "OPEN"
    else:
        df["state"] = df["state"].str.strip().str.upper()
        
    if "protocol" not in df.columns:
        df["protocol"] = "TCP"
    else:
        df["protocol"] = df["protocol"].str.strip().str.upper()
        
    if "exposure" not in df.columns:
        df["exposure"] = df["detail"]
        
    if "response_time" not in df.columns:
        # Synthetic realistic demo response times for display
        demo_times = {443: "35 ms", 22: "42 ms", 53: "18 ms", 3389: "55 ms"}
        df["response_time"] = df["port"].map(demo_times).fillna("30 ms")
        
    if "response_time_ms" not in df.columns:
        demo_ms = {443: 35.0, 22: 42.0, 53: 18.0, 3389: 55.0}
        df["response_time_ms"] = df["port"].map(demo_ms).fillna(30.0)
        
    if "segment" in df.columns:
        df["segment"] = df["segment"].str.strip()
    else:
        df["segment"] = "Unassigned"
        
    if "target" in df.columns:
        df["target"] = df["target"].str.strip()
    else:
        df["target"] = "General Host"
        
    return df


def load_demo_data(csv_path: Optional[str | Path] = None) -> pd.DataFrame:
    """Convenience alias for loading demo mode dataset."""
    return load_exposure_data(csv_path)


def calculate_risk_metrics(df: pd.DataFrame) -> Dict[str, Any]:
    """
    Calculate summary risk and scan metrics dynamically from the dataset.
    
    For risk breakdown: reflects reachable/exposed ('OPEN') services.
    For scan counts: calculates Total, Open, Closed, Filtered, and Unfiltered.
    """
    if df is None or df.empty:
        return {
            "total_scanned": 0,
            "open_count": 0,
            "closed_count": 0,
            "filtered_count": 0,
            "unfiltered_count": 0,
            "total": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "high_pct": 0.0,
            "medium_pct": 0.0,
            "low_pct": 0.0,
        }

    total_scanned = len(df)
    
    # State counts
    states_upper = df["state"].astype(str).str.upper() if "state" in df.columns else pd.Series(["OPEN"] * total_scanned)
    open_count = (states_upper == "OPEN").sum()
    closed_count = (states_upper == "CLOSED").sum()
    filtered_count = (states_upper == "FILTERED").sum()
    unfiltered_count = (states_upper == "UNFILTERED").sum()

    # Reachable/exposed services for risk metrics
    exposed_df = df[states_upper == "OPEN"] if "state" in df.columns else df
    total_exposed = len(exposed_df)
    
    risk_counts = exposed_df["risk"].value_counts().to_dict() if not exposed_df.empty else {}
    
    high_count = risk_counts.get("High", 0)
    medium_count = risk_counts.get("Medium", 0)
    low_count = risk_counts.get("Low", 0)
    
    high_pct = (high_count / total_exposed * 100.0) if total_exposed > 0 else 0.0
    medium_pct = (medium_count / total_exposed * 100.0) if total_exposed > 0 else 0.0
    low_pct = (low_count / total_exposed * 100.0) if total_exposed > 0 else 0.0
    
    return {
        "total_scanned": total_scanned,
        "open_count": int(open_count),
        "closed_count": int(closed_count),
        "filtered_count": int(filtered_count),
        "unfiltered_count": int(unfiltered_count),
        "total": total_exposed,
        "high_count": high_count,
        "medium_count": medium_count,
        "low_count": low_count,
        "high_pct": high_pct,
        "medium_pct": medium_pct,
        "low_pct": low_pct,
    }


def filter_and_sort_data(
    df: pd.DataFrame,
    state_filter: Optional[str] = "All",
    service_filter: Optional[str] = "All",
    port_search: Optional[str] = None,
    risk_filter: Optional[List[str]] = None,
    sort_by: str = "Port",
    ascending: bool = True
) -> pd.DataFrame:
    """
    Filter and sort the dataset dynamically based on UI controls.

    Filters:
    - state_filter: 'All', 'Open', 'Closed', 'Filtered', 'Unfiltered'
    - service_filter: 'All' or specific service name (e.g. 'SSH', 'HTTPS')
    - port_search: string search for port number
    - risk_filter: list of risk tiers ('High', 'Medium', 'Low', 'None')
    - sort_by: 'Port', 'State', 'Service', 'Response Time', 'Risk'
    """
    if df is None or df.empty:
        return pd.DataFrame()

    filtered_df = df.copy()
    
    # State Filter
    if state_filter and state_filter.lower() != "all" and "state" in filtered_df.columns:
        filtered_df = filtered_df[
            filtered_df["state"].astype(str).str.upper() == state_filter.upper()
        ]
        
    # Service Filter
    if service_filter and service_filter.lower() != "all" and "service" in filtered_df.columns:
        filtered_df = filtered_df[
            filtered_df["service"].astype(str).str.lower() == service_filter.lower()
        ]

    # Port Search
    if port_search and port_search.strip():
        search_term = port_search.strip()
        filtered_df = filtered_df[
            filtered_df["port"].astype(str).str.contains(search_term)
        ]

    # Risk Filter
    if risk_filter and "risk" in filtered_df.columns:
        filtered_df = filtered_df[filtered_df["risk"].isin(risk_filter)]
        
    # Sorting
    sort_col = sort_by.lower()
    if sort_col == "port":
        filtered_df = filtered_df.sort_values(by="port", ascending=ascending)
    elif sort_col == "state" and "state" in filtered_df.columns:
        filtered_df = filtered_df.sort_values(by="state", ascending=ascending)
    elif sort_col == "service" and "service" in filtered_df.columns:
        filtered_df = filtered_df.sort_values(by="service", ascending=ascending)
    elif sort_col == "response time" or sort_col == "response_time":
        if "response_time_ms" in filtered_df.columns:
            # Sort by numeric ms, nulls last
            filtered_df = filtered_df.sort_values(
                by="response_time_ms",
                ascending=ascending,
                na_position="last"
            )
        else:
            filtered_df = filtered_df.sort_values(by="response_time", ascending=ascending)
    elif sort_col == "risk" and "risk" in filtered_df.columns:
        risk_order = {"High": 1, "Medium": 2, "Low": 3, "None": 4}
        filtered_df["_risk_order"] = filtered_df["risk"].map(risk_order).fillna(99)
        filtered_df = filtered_df.sort_values(by="_risk_order", ascending=ascending)
        filtered_df = filtered_df.drop(columns=["_risk_order"])
    else:
        filtered_df = filtered_df.sort_values(by="port", ascending=ascending)
        
    return filtered_df
