"""
Internal Audit Application - Crypto Audit Toolkit

A comprehensive Streamlit application demonstrating Internal Audit practices
for cryptocurrency ecosystems. This application showcases:
- COSO-aligned risk assessment
- Control effectiveness testing
- Data analytics and sampling
- Blockchain wallet reconciliation
- Compliance tracking
- Professional report generation

Designed to demonstrate skills relevant to Internal Audit positions
in crypto/payments auditing functions.
"""

import streamlit as st
import pandas as pd
import numpy as np
import datetime
import uuid
import random
from typing import Dict, List, Any, Optional
from dataclasses import asdict, is_dataclass

# Import from audit modules
from audit_data import (
    COSOComponent,
    COSO_FRAMEWORK,
    ControlCategory,
    CRYPTO_CONTROLS_LIBRARY,
    RISK_CATEGORIES,
    SAMPLE_CRYPTO_RISKS,
    SAMPLE_AUDIT_FINDINGS,
    SAMPLE_TRANSACTIONS,
    REGULATORY_COMPLIANCE_CHECKLISTS,
    RemediationStatus,
    FindingSeverity,
)
from audit_utils import (
    calculate_risk_score,
    get_risk_rating,
    calculate_inherent_risk,
    calculate_residual_risk,
    rate_control_effectiveness,
    get_control_status,
    calculate_statistics,
    benford_law_analysis,
    detect_outliers_zscore,
    detect_outliers_iqr,
    create_risk_heatmap_data,
    create_control_status_summary,
    random_sampling,
    stratified_sampling,
    monetary_unit_sampling,
    detect_unusual_patterns,
    flag_round_numbers,
    detect_off_hours_transactions,
    detect_weekend_transactions,
    detect_duplicates,
)


# =============================================================================
# HELPER: CONVERT DATACLASS TO DICT
# =============================================================================

def finding_to_dict(finding) -> dict:
    """Convert an AuditFinding dataclass or dict to a standardized dict."""
    if isinstance(finding, dict):
        return finding
    elif is_dataclass(finding):
        d = asdict(finding)
        # Convert enum values to strings
        for key, value in d.items():
            if hasattr(value, 'value'):
                d[key] = value.value
            elif isinstance(value, (datetime.date, datetime.datetime)):
                d[key] = str(value)
        return d
    else:
        # Try to access as object attributes
        return {
            'finding_id': getattr(finding, 'finding_id', 'Unknown'),
            'title': getattr(finding, 'title', 'Untitled'),
            'severity': str(getattr(finding, 'severity', 'N/A')),
            'status': str(getattr(finding, 'status', 'Open')),
            'condition': getattr(finding, 'condition', ''),
            'criteria': getattr(finding, 'criteria', ''),
            'cause': getattr(finding, 'cause', ''),
            'effect': getattr(finding, 'effect', ''),
            'recommendation': getattr(finding, 'recommendation', ''),
            'identified_date': str(getattr(finding, 'identified_date', '')),
            'target_remediation_date': str(getattr(finding, 'target_remediation_date', '')),
        }


# =============================================================================
# PAGE CONFIGURATION
# =============================================================================

st.set_page_config(
    page_title="Crypto Internal Audit Toolkit",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)


# =============================================================================
# CUSTOM CSS STYLING
# =============================================================================

st.markdown("""
<style>
    /* Main container styling */
    .main-header {
        font-size: 2.5rem;
        font-weight: 700;
        color: #1E3A5F;
        margin-bottom: 0.5rem;
    }

    .sub-header {
        font-size: 1.1rem;
        color: #5A6C7D;
        margin-bottom: 2rem;
    }

    /* Card styling */
    .audit-card {
        background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
        border-radius: 12px;
        padding: 1.5rem;
        margin-bottom: 1rem;
        border-left: 4px solid #1E3A5F;
        box-shadow: 0 2px 8px rgba(0,0,0,0.05);
    }

    .metric-card {
        background: #ffffff;
        border-radius: 10px;
        padding: 1.25rem;
        text-align: center;
        border: 1px solid #e9ecef;
        box-shadow: 0 2px 4px rgba(0,0,0,0.03);
    }

    .metric-value {
        font-size: 2rem;
        font-weight: 700;
        color: #1E3A5F;
    }

    .metric-label {
        font-size: 0.85rem;
        color: #6c757d;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }

    /* Status badges */
    .badge-low {
        background-color: #28a745;
        color: white;
        padding: 0.25rem 0.75rem;
        border-radius: 20px;
        font-size: 0.8rem;
        font-weight: 600;
    }

    .badge-medium {
        background-color: #ffc107;
        color: #212529;
        padding: 0.25rem 0.75rem;
        border-radius: 20px;
        font-size: 0.8rem;
        font-weight: 600;
    }

    .badge-high {
        background-color: #fd7e14;
        color: white;
        padding: 0.25rem 0.75rem;
        border-radius: 20px;
        font-size: 0.8rem;
        font-weight: 600;
    }

    .badge-critical {
        background-color: #dc3545;
        color: white;
        padding: 0.25rem 0.75rem;
        border-radius: 20px;
        font-size: 0.8rem;
        font-weight: 600;
    }

    /* Control effectiveness badges */
    .badge-effective {
        background-color: #28a745;
        color: white;
        padding: 0.25rem 0.75rem;
        border-radius: 20px;
        font-size: 0.8rem;
        font-weight: 600;
    }

    .badge-satisfactory {
        background-color: #17a2b8;
        color: white;
        padding: 0.25rem 0.75rem;
        border-radius: 20px;
        font-size: 0.8rem;
        font-weight: 600;
    }

    .badge-needs-improvement {
        background-color: #ffc107;
        color: #212529;
        padding: 0.25rem 0.75rem;
        border-radius: 20px;
        font-size: 0.8rem;
        font-weight: 600;
    }

    .badge-ineffective {
        background-color: #dc3545;
        color: white;
        padding: 0.25rem 0.75rem;
        border-radius: 20px;
        font-size: 0.8rem;
        font-weight: 600;
    }

    /* Section headers */
    .section-header {
        font-size: 1.5rem;
        font-weight: 600;
        color: #1E3A5F;
        margin-top: 1.5rem;
        margin-bottom: 1rem;
        padding-bottom: 0.5rem;
        border-bottom: 2px solid #e9ecef;
    }

    /* Info boxes */
    .info-box {
        background-color: #e7f3ff;
        border-left: 4px solid #0066cc;
        padding: 1rem;
        border-radius: 0 8px 8px 0;
        margin-bottom: 1rem;
    }

    .warning-box {
        background-color: #fff3e0;
        border-left: 4px solid #ff9800;
        padding: 1rem;
        border-radius: 0 8px 8px 0;
        margin-bottom: 1rem;
    }

    /* Sidebar styling */
    .sidebar-title {
        font-size: 1.3rem;
        font-weight: 600;
        color: #1E3A5F;
        margin-bottom: 1rem;
    }

    /* Capability list styling */
    .capability-item {
        background-color: #f8f9fa;
        padding: 0.75rem 1rem;
        border-radius: 8px;
        margin-bottom: 0.5rem;
        border-left: 3px solid #1E3A5F;
    }

    /* Skills alignment section */
    .skills-card {
        background: linear-gradient(135deg, #e3f2fd 0%, #bbdefb 100%);
        border-radius: 12px;
        padding: 1.5rem;
        margin-top: 1rem;
    }

    /* Engagement info styling */
    .engagement-info {
        background-color: #f1f3f4;
        border-radius: 8px;
        padding: 1rem;
        margin-top: 0.5rem;
    }

    /* Loading placeholder */
    .loading-placeholder {
        background: linear-gradient(90deg, #f0f0f0 25%, #e0e0e0 50%, #f0f0f0 75%);
        background-size: 200% 100%;
        animation: loading 1.5s infinite;
        border-radius: 8px;
        padding: 3rem;
        text-align: center;
        color: #6c757d;
    }

    @keyframes loading {
        0% { background-position: 200% 0; }
        100% { background-position: -200% 0; }
    }

    /* Table styling */
    .styled-table {
        width: 100%;
        border-collapse: collapse;
        margin-top: 1rem;
    }

    .styled-table th {
        background-color: #1E3A5F;
        color: white;
        padding: 0.75rem;
        text-align: left;
    }

    .styled-table td {
        padding: 0.75rem;
        border-bottom: 1px solid #e9ecef;
    }

    .styled-table tr:hover {
        background-color: #f8f9fa;
    }

    /* Hide Streamlit branding */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
</style>
""", unsafe_allow_html=True)


# =============================================================================
# SESSION STATE INITIALIZATION
# =============================================================================

def initialize_session_state():
    """Initialize all session state variables for the audit application."""

    # Audit engagement details
    if 'audit_engagement' not in st.session_state:
        st.session_state.audit_engagement = {
            'id': '',
            'auditor': '',
            'client': '',
            'scope': '',
            'start_date': datetime.date.today(),
            'end_date': datetime.date.today() + datetime.timedelta(days=30),
            'status': 'Not Started'
        }

    # Identified risks list
    if 'identified_risks' not in st.session_state:
        st.session_state.identified_risks = []

    # Tested controls results
    if 'tested_controls' not in st.session_state:
        st.session_state.tested_controls = []

    # Analytics results
    if 'analytics_results' not in st.session_state:
        st.session_state.analytics_results = {
            'samples': [],
            'anomalies': [],
            'statistics': {},
            'benford_analysis': None
        }

    # Reconciliation results
    if 'reconciliation_results' not in st.session_state:
        st.session_state.reconciliation_results = []

    # Compliance checklist items
    if 'compliance_items' not in st.session_state:
        st.session_state.compliance_items = []

    # Audit findings
    if 'audit_findings' not in st.session_state:
        st.session_state.audit_findings = []

    # Current navigation section
    if 'current_section' not in st.session_state:
        st.session_state.current_section = 'Home'

    # Demo mode toggle
    if 'demo_mode' not in st.session_state:
        st.session_state.demo_mode = False


# Initialize session state
initialize_session_state()


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def generate_engagement_id() -> str:
    """Generate a unique engagement ID."""
    today = datetime.date.today()
    random_suffix = str(uuid.uuid4())[:8].upper()
    return f"IA-{today.year}-{random_suffix}"


def get_risk_badge_html(rating: str) -> str:
    """Return HTML for a risk rating badge."""
    badge_class = f"badge-{rating.lower()}"
    return f'<span class="{badge_class}">{rating}</span>'


def get_control_badge_html(status: str) -> str:
    """Return HTML for a control status badge."""
    status_class = status.lower().replace(' ', '-')
    return f'<span class="badge-{status_class}">{status}</span>'


def display_engagement_info():
    """Display current engagement information in sidebar."""
    engagement = st.session_state.audit_engagement

    if engagement['id']:
        st.markdown(f"""
        <div class="engagement-info">
            <strong>Engagement ID:</strong> {engagement['id']}<br>
            <strong>Auditor:</strong> {engagement['auditor'] or 'Not set'}<br>
            <strong>Client:</strong> {engagement['client'] or 'Not set'}<br>
            <strong>Status:</strong> {engagement['status']}
        </div>
        """, unsafe_allow_html=True)
    else:
        st.info("No active engagement. Set up an engagement on the Home page.")


def clear_session():
    """Clear all session state data."""
    for key in list(st.session_state.keys()):
        del st.session_state[key]
    initialize_session_state()


# =============================================================================
# SIDEBAR NAVIGATION
# =============================================================================

with st.sidebar:
    st.markdown('<p class="sidebar-title">Internal Audit Toolkit</p>', unsafe_allow_html=True)

    st.divider()

    # Display engagement info
    st.markdown("**Current Engagement**")
    display_engagement_info()

    st.divider()

    # Navigation radio buttons
    st.markdown("**Navigation**")
    section = st.radio(
        "Select Section",
        options=[
            "Home",
            "Risk Assessment",
            "Control Testing",
            "Data Analytics",
            "Wallet Reconciliation",
            "Compliance Dashboard",
            "Report Generation"
        ],
        index=["Home", "Risk Assessment", "Control Testing", "Data Analytics",
               "Wallet Reconciliation", "Compliance Dashboard", "Report Generation"].index(
                   st.session_state.current_section
               ),
        label_visibility="collapsed"
    )
    st.session_state.current_section = section

    st.divider()

    # Demo mode toggle
    st.markdown("**Settings**")
    demo_mode = st.toggle("Demo Mode", value=st.session_state.demo_mode)
    st.session_state.demo_mode = demo_mode

    if demo_mode:
        st.caption("Demo mode loads sample data for demonstration purposes.")

    # Clear session button
    if st.button("Clear Session", type="secondary", use_container_width=True):
        clear_session()
        st.rerun()

    st.divider()

    # Footer info
    st.caption("Crypto Internal Audit Toolkit v1.0")
    st.caption("Demonstrates IA practices for crypto ecosystems")


# =============================================================================
# DEMO DATA LOADER FUNCTION
# =============================================================================

def load_full_demo_data():
    """
    Load comprehensive demo data across all audit modules for interview demonstrations.
    This function populates all session state variables with realistic sample data.
    """

    # Set demo mode flag
    st.session_state.demo_mode = True

    # 1. Set Audit Engagement Info
    st.session_state.audit_engagement = {
        'id': f"IA-2024-DEMO-{str(uuid.uuid4())[:6].upper()}",
        'auditor': 'Senior Internal Auditor',
        'client': 'CryptoExchange Inc',
        'scope': 'Annual internal audit of crypto custody operations, including assessment of wallet management controls, transaction monitoring effectiveness, key custody procedures, and regulatory compliance with BSA/AML requirements.',
        'start_date': datetime.date.today() - datetime.timedelta(days=14),
        'end_date': datetime.date.today() + datetime.timedelta(days=16),
        'status': 'Fieldwork'
    }

    # 2. Load Sample Risks into identified_risks
    st.session_state.identified_risks = [risk.copy() for risk in SAMPLE_CRYPTO_RISKS]

    # 3. Load Sample Tested Controls
    st.session_state.tested_controls = [
        {
            'control_id': 'WM-001',
            'control_name': 'Multi-Signature Wallet Configuration',
            'category': 'wallet_management',
            'test_date': datetime.date.today() - datetime.timedelta(days=5),
            'tester': 'Senior Internal Auditor',
            'rating': 'Effective',
            'effectiveness_score': 0.95,
            'observations': 'Multi-signature configuration verified on all production wallets. 2-of-3 setup confirmed for hot wallets and 3-of-5 for cold storage. All signatories have completed required background checks.',
            'evidence': 'Blockchain explorer screenshots, wallet configuration documentation, signatory matrix reviewed, HSM audit logs.',
            'deficiency': None,
            'test_results': [
                {'test': 'Review wallet configuration documentation', 'passed': True},
                {'test': 'Verify multi-sig setup on blockchain', 'passed': True},
                {'test': 'Test transaction approval workflow', 'passed': True},
                {'test': 'Review signatory access lists', 'passed': True}
            ]
        },
        {
            'control_id': 'KC-001',
            'control_name': 'HSM Key Storage',
            'category': 'key_custody',
            'test_date': datetime.date.today() - datetime.timedelta(days=4),
            'tester': 'Senior Internal Auditor',
            'rating': 'Effective',
            'effectiveness_score': 0.92,
            'observations': 'All private keys for institutional wallets are stored in FIPS 140-2 Level 3 certified HSMs. Tamper-evident seals intact. Key ceremony documentation complete.',
            'evidence': 'HSM certification certificates, physical inspection report, key ceremony video recordings.',
            'deficiency': None,
            'test_results': [
                {'test': 'Verify HSM certification documentation', 'passed': True},
                {'test': 'Review HSM access controls', 'passed': True},
                {'test': 'Test key generation procedures', 'passed': True},
                {'test': 'Verify tamper-evident seals', 'passed': True}
            ]
        },
        {
            'control_id': 'AM-002',
            'control_name': 'Multi-Factor Authentication',
            'category': 'access_management',
            'test_date': datetime.date.today() - datetime.timedelta(days=3),
            'tester': 'Senior Internal Auditor',
            'rating': 'Satisfactory',
            'effectiveness_score': 0.75,
            'observations': 'MFA is enforced for most systems including trading platforms and wallet access. Minor gap identified in legacy admin portal.',
            'evidence': 'MFA configuration screenshots, system access logs, enrollment reports, exception documentation.',
            'deficiency': 'Legacy admin portal does not enforce MFA for 3 administrative accounts. Compensating control: VPN-only access with IP whitelisting.',
            'test_results': [
                {'test': 'Review MFA policy', 'passed': True},
                {'test': 'Test MFA enforcement', 'passed': False},
                {'test': 'Verify MFA coverage', 'passed': True},
                {'test': 'Test MFA bypass controls', 'passed': True}
            ]
        },
        {
            'control_id': 'TA-001',
            'control_name': 'Transaction Approval Matrix',
            'category': 'transaction_approval',
            'test_date': datetime.date.today() - datetime.timedelta(days=2),
            'tester': 'Senior Internal Auditor',
            'rating': 'Effective',
            'effectiveness_score': 0.88,
            'observations': 'Transaction approval matrix properly implemented. Dual authorization required for transactions >$10K, three-person approval for >$100K.',
            'evidence': 'Approval matrix documentation, sample transaction approvals, system configuration exports.',
            'deficiency': None,
            'test_results': [
                {'test': 'Review approval matrix documentation', 'passed': True},
                {'test': 'Test threshold enforcement', 'passed': True},
                {'test': 'Verify approver authorization levels', 'passed': True},
                {'test': 'Test exception handling process', 'passed': True}
            ]
        },
        {
            'control_id': 'TA-003',
            'control_name': 'Transaction Velocity Limits',
            'category': 'transaction_approval',
            'test_date': datetime.date.today() - datetime.timedelta(days=1),
            'tester': 'Senior Internal Auditor',
            'rating': 'Needs Improvement',
            'effectiveness_score': 0.60,
            'observations': 'Velocity limits are configured but thresholds may be too high for current risk appetite. Alert escalation process needs strengthening.',
            'evidence': 'System configuration exports, velocity limit policy, alert logs, escalation records.',
            'deficiency': 'Velocity limits set at $500K/day which exceeds risk appetite of $250K/day. Two limit breaches in past month were not properly escalated to management.',
            'test_results': [
                {'test': 'Review velocity limit configuration', 'passed': True},
                {'test': 'Test limit enforcement', 'passed': True},
                {'test': 'Review limit breach alerts', 'passed': False},
                {'test': 'Verify exception handling process', 'passed': False}
            ]
        },
        {
            'control_id': 'WM-004',
            'control_name': 'Daily Wallet Reconciliation',
            'category': 'wallet_management',
            'test_date': datetime.date.today(),
            'tester': 'Senior Internal Auditor',
            'rating': 'Satisfactory',
            'effectiveness_score': 0.82,
            'observations': 'Daily reconciliation process is in place and generally effective. Minor delays noted in exception resolution.',
            'evidence': 'Daily reconciliation reports, exception logs, resolution documentation.',
            'deficiency': 'Exception resolution sometimes exceeds 24-hour SLA (5 of 30 sampled exceptions resolved in 36+ hours).',
            'test_results': [
                {'test': 'Review reconciliation procedures', 'passed': True},
                {'test': 'Verify reconciliation is performed daily', 'passed': True},
                {'test': 'Test reconciliation accuracy', 'passed': True},
                {'test': 'Review exception handling process', 'passed': False}
            ]
        }
    ]

    # 4. Load Sample Analytics Data (will be generated when visiting the page)
    st.session_state.analytics_results = {
        'samples': [
            {'sample_id': 'SMP-001', 'method': 'Random', 'size': 50, 'population': 500, 'date': datetime.date.today()},
            {'sample_id': 'SMP-002', 'method': 'Stratified', 'size': 75, 'population': 500, 'date': datetime.date.today()},
            {'sample_id': 'SMP-003', 'method': 'MUS', 'size': 30, 'population': 500, 'date': datetime.date.today()}
        ],
        'anomalies': [
            {'id': 'TXN-0042', 'amount': 125000.00, 'method': 'Z-Score', 'z_score': 4.2, 'timestamp': '2024-12-15 14:23:00'},
            {'id': 'TXN-0087', 'amount': 98500.00, 'method': 'Z-Score', 'z_score': 3.8, 'timestamp': '2024-12-16 09:15:00'},
            {'id': 'TXN-0123', 'amount': 75000.00, 'method': 'IQR', 'bounds': '[100, 25000]', 'timestamp': '2024-12-17 11:30:00'},
            {'id': 'TXN-0156', 'amount': 50000.00, 'method': 'Round Number', 'note': 'Divisible by 1000', 'timestamp': '2024-12-18 23:45:00'},
            {'id': 'TXN-0189', 'amount': 10000.00, 'method': 'Round Number', 'note': 'Divisible by 1000', 'timestamp': '2024-12-19 02:10:00'},
            {'id': 'TXN-0201', 'amount': 45000.00, 'method': 'Z-Score', 'z_score': 3.1, 'timestamp': '2024-12-20 16:00:00'},
        ],
        'statistics': {
            'mean': 4523.67,
            'median': 2150.00,
            'std': 8976.34,
            'min': 25.00,
            'max': 125000.00,
            'total': 2261835.00
        },
        'benford_analysis': {
            'chi_square': 5.47,
            'conformity_score': 0.89,
            'observed_distribution': {1: 0.298, 2: 0.179, 3: 0.128, 4: 0.095, 5: 0.081, 6: 0.068, 7: 0.056, 8: 0.052, 9: 0.043},
            'expected_distribution': {1: 0.301, 2: 0.176, 3: 0.125, 4: 0.097, 5: 0.079, 6: 0.067, 7: 0.058, 8: 0.051, 9: 0.046},
            'digit_counts': {1: 149, 2: 90, 3: 64, 4: 47, 5: 40, 6: 34, 7: 28, 8: 26, 9: 22},
            'sample_size': 500
        }
    }

    # 5. Load Sample Reconciliation Results
    st.session_state.wallet_entries = [
        {
            "wallet_id": "WALLET-001",
            "wallet_name": "Hot Wallet - Operations",
            "wallet_address": "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh",
            "crypto": "BTC",
            "recorded_balance": 12.45678901,
            "custodian": "Internal Treasury",
            "last_reconciled": datetime.date.today().isoformat()
        },
        {
            "wallet_id": "WALLET-002",
            "wallet_name": "Cold Storage - Reserve",
            "wallet_address": "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
            "crypto": "BTC",
            "recorded_balance": 156.78901234,
            "custodian": "Coinbase Custody",
            "last_reconciled": datetime.date.today().isoformat()
        },
        {
            "wallet_id": "WALLET-003",
            "wallet_name": "Trading Wallet - ETH",
            "wallet_address": "0x742d35Cc6634C0532925a3b844Bc9e7595f8fBe2",
            "crypto": "ETH",
            "recorded_balance": 245.67891234,
            "custodian": "Internal Treasury",
            "last_reconciled": datetime.date.today().isoformat()
        },
        {
            "wallet_id": "WALLET-004",
            "wallet_name": "Stablecoin Reserve",
            "wallet_address": "0x8B3B2cC1E3D24F0C1F76E3A8F3F0B9E1A2C3D4E5",
            "crypto": "USDC",
            "recorded_balance": 5000000.00,
            "custodian": "Circle",
            "last_reconciled": datetime.date.today().isoformat()
        }
    ]

    st.session_state.reconciliation_results = [
        {
            'wallet_id': 'WALLET-001',
            'wallet_name': 'Hot Wallet - Operations',
            'crypto': 'BTC',
            'wallet_address': '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa',
            'recorded_balance': 12.45678901,
            'blockchain_balance': 12.45678901,
            'variance_abs': 0.0,
            'variance_pct': 0.0,
            'variance_usd': 0.0,
            'usd_value': 12.45678901 * 42500,
            'status': 'Match',
            'status_color': 'green',
            'block_height': 821456,
            'verification_time': datetime.datetime.now().isoformat(),
            'custodian': 'Internal'
        },
        {
            'wallet_id': 'WALLET-002',
            'wallet_name': 'Cold Storage - Reserve',
            'crypto': 'BTC',
            'wallet_address': 'bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh',
            'recorded_balance': 156.78901234,
            'blockchain_balance': 156.78901234,
            'variance_abs': 0.0,
            'variance_pct': 0.0,
            'variance_usd': 0.0,
            'usd_value': 156.78901234 * 42500,
            'status': 'Match',
            'status_color': 'green',
            'block_height': 821456,
            'verification_time': datetime.datetime.now().isoformat(),
            'custodian': 'Coinbase Custody'
        },
        {
            'wallet_id': 'WALLET-003',
            'wallet_name': 'Trading Wallet - ETH',
            'crypto': 'ETH',
            'wallet_address': '0x742d35Cc6634C0532925a3b844Bc9e7595f1e4A2',
            'recorded_balance': 245.67891234,
            'blockchain_balance': 245.68123456,
            'variance_abs': 0.00232222,
            'variance_pct': 0.00094,
            'variance_usd': 0.00232222 * 2250,
            'usd_value': 245.68123456 * 2250,
            'status': 'Minor Variance',
            'status_color': 'yellow',
            'block_height': 19234567,
            'verification_time': datetime.datetime.now().isoformat(),
            'custodian': 'Internal'
        },
        {
            'wallet_id': 'WALLET-004',
            'wallet_name': 'Stablecoin Reserve',
            'crypto': 'USDC',
            'wallet_address': '0x8888888888888888888888888888888888888888',
            'recorded_balance': 5000000.00,
            'blockchain_balance': 5000000.00,
            'variance_abs': 0.0,
            'variance_pct': 0.0,
            'variance_usd': 0.0,
            'usd_value': 5000000.00,
            'status': 'Match',
            'status_color': 'green',
            'block_height': 19234567,
            'verification_time': datetime.datetime.now().isoformat(),
            'custodian': 'Circle'
        }
    ]

    # 6. Load Sample Compliance Items and Findings
    st.session_state.audit_findings = [finding_to_dict(f) for f in SAMPLE_AUDIT_FINDINGS]

    # Initialize compliance assessments
    st.session_state.compliance_items = {}
    demo_assessment_data = [
        ('AML-001', 'Compliant', 'CIP procedures verified. All customer accounts sampled had proper identity verification.'),
        ('AML-002', 'Compliant', 'SAR filing process tested. 15 SARs filed in Q4, all within required timeframes.'),
        ('AML-003', 'Compliant', 'CTR filing process automated and accurate. Tested 10 CTRs - all complete.'),
        ('AML-004', 'Partial', 'Transaction monitoring covers 60% of required scenarios. Phase 2 rules pending implementation.'),
        ('AML-005', 'Compliant', 'AML program documentation complete. BSA Officer designated. Training current.'),
        ('AML-006', 'Compliant', 'Travel Rule compliance verified. VASP integration operational.'),
        ('KYC-001', 'Compliant', 'CDD procedures tested. Risk ratings properly assigned to all sampled customers.'),
        ('KYC-002', 'Compliant', 'EDD files complete for high-risk customers. Senior management approval documented.'),
        ('KYC-003', 'Compliant', 'Beneficial ownership collected for all legal entity customers.'),
        ('KYC-004', 'Partial', 'PEP screening operational. Some delays in sanctions list updates noted.'),
        ('KYC-005', 'Compliant', 'Customer refresh schedule implemented. High-risk customers refreshed annually.'),
    ]

    for req_id, status, notes in demo_assessment_data:
        st.session_state.compliance_items[req_id] = {
            'status': status,
            'notes': notes,
            'last_assessed': datetime.date.today() - datetime.timedelta(days=random.randint(1, 30)),
            'assessor': 'Senior Internal Auditor'
        }

    # Fill remaining compliance items with appropriate statuses
    for reg_key, reg_data in REGULATORY_COMPLIANCE_CHECKLISTS.items():
        for req in reg_data.get('requirements', []):
            if req.requirement_id not in st.session_state.compliance_items:
                st.session_state.compliance_items[req.requirement_id] = {
                    'status': random.choice(['Compliant', 'Compliant', 'Compliant', 'Partial', 'Not Assessed']),
                    'notes': '',
                    'last_assessed': datetime.date.today() - datetime.timedelta(days=random.randint(0, 60)),
                    'assessor': 'Senior Internal Auditor'
                }


# =============================================================================
# HOME PAGE SECTION
# =============================================================================

def render_home_page():
    """Render the Home page section with Demo Walkthrough and Quick-Start Guide."""

    # Welcome header
    st.markdown('<h1 class="main-header">Crypto Internal Audit Toolkit</h1>', unsafe_allow_html=True)
    st.markdown(
        '<p class="sub-header">A comprehensive demonstration of Internal Audit practices '
        'for cryptocurrency and digital asset ecosystems</p>',
        unsafe_allow_html=True
    )

    # =========================================================================
    # DEMO WALKTHROUGH BUTTON - Prominent at top
    # =========================================================================
    st.markdown("""
    <style>
        .demo-button-container {
            background: linear-gradient(135deg, #1E3A5F 0%, #2E5A8F 50%, #3E7ABF 100%);
            border-radius: 16px;
            padding: 1.5rem 2rem;
            margin: 1rem 0 2rem 0;
            box-shadow: 0 8px 32px rgba(30, 58, 95, 0.3);
            border: 2px solid rgba(255, 255, 255, 0.1);
        }
        .demo-button-title {
            color: white;
            font-size: 1.4rem;
            font-weight: 700;
            margin-bottom: 0.5rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        .demo-button-subtitle {
            color: rgba(255, 255, 255, 0.85);
            font-size: 0.95rem;
            margin-bottom: 1rem;
        }
        .demo-features {
            display: flex;
            flex-wrap: wrap;
            gap: 0.75rem;
            margin-top: 0.75rem;
        }
        .demo-feature-tag {
            background: rgba(255, 255, 255, 0.15);
            color: white;
            padding: 0.35rem 0.75rem;
            border-radius: 20px;
            font-size: 0.8rem;
            border: 1px solid rgba(255, 255, 255, 0.2);
        }
        .quick-start-header {
            background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
            border-radius: 12px;
            padding: 1.25rem;
            border-left: 5px solid #28a745;
            margin-bottom: 1rem;
        }
        .guide-step {
            background: #ffffff;
            border-radius: 10px;
            padding: 1rem 1.25rem;
            margin-bottom: 0.75rem;
            border: 1px solid #e9ecef;
            display: flex;
            align-items: flex-start;
            gap: 1rem;
        }
        .step-number {
            background: #1E3A5F;
            color: white;
            width: 32px;
            height: 32px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 700;
            flex-shrink: 0;
        }
        .step-content {
            flex: 1;
        }
        .step-title {
            font-weight: 600;
            color: #1E3A5F;
            margin-bottom: 0.25rem;
        }
        .step-description {
            color: #5A6C7D;
            font-size: 0.9rem;
            margin-bottom: 0.25rem;
        }
        .step-time {
            color: #28a745;
            font-size: 0.8rem;
            font-weight: 600;
        }
        .talking-points {
            background: #e7f3ff;
            border-radius: 8px;
            padding: 0.75rem 1rem;
            margin-top: 0.5rem;
            font-size: 0.85rem;
        }
        .talking-points-title {
            color: #0066cc;
            font-weight: 600;
            margin-bottom: 0.25rem;
        }
        .info-tooltip {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            width: 18px;
            height: 18px;
            border-radius: 50%;
            background: #0066cc;
            color: white;
            font-size: 0.7rem;
            font-weight: 700;
            cursor: help;
            margin-left: 0.25rem;
        }
    </style>
    """, unsafe_allow_html=True)

    # Demo Mode Status Indicator
    if st.session_state.demo_mode:
        st.markdown("""
        <div style="background: linear-gradient(135deg, #d4edda 0%, #c3e6cb 100%); border-radius: 10px; padding: 1rem; margin-bottom: 1rem; border-left: 4px solid #28a745;">
            <strong style="color: #155724;">Demo Mode Active</strong>
            <span style="color: #155724;"> - All modules are pre-loaded with sample audit data. Navigate through the sections using the sidebar.</span>
        </div>
        """, unsafe_allow_html=True)

    # Demo Walkthrough Button Section
    st.markdown("""
    <div class="demo-button-container">
        <div class="demo-button-title">
            Launch Full Demo Experience
        </div>
        <div class="demo-button-subtitle">
            Pre-load all sections with realistic sample data for a complete walkthrough demonstration
        </div>
        <div class="demo-features">
            <span class="demo-feature-tag">10 Crypto Risks</span>
            <span class="demo-feature-tag">6 Tested Controls</span>
            <span class="demo-feature-tag">5 Audit Findings</span>
            <span class="demo-feature-tag">4 Wallet Reconciliations</span>
            <span class="demo-feature-tag">Full Compliance Data</span>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # Create prominent demo button
    demo_col1, demo_col2, demo_col3 = st.columns([1, 2, 1])
    with demo_col2:
        if st.button(
            "Start Interactive Demo",
            type="primary",
            use_container_width=True,
            help="Loads comprehensive sample data across all audit modules - perfect for interview demonstrations"
        ):
            load_full_demo_data()
            st.success("Demo data loaded successfully! All modules are now populated with sample audit data.")
            st.balloons()
            st.rerun()

    # =========================================================================
    # QUICK-START GUIDE FOR INTERVIEW
    # =========================================================================
    with st.expander("Interview Quick-Start Guide - Demo Flow & Talking Points", expanded=not st.session_state.demo_mode):
        st.markdown("""
        <div class="quick-start-header">
            <h4 style="margin: 0 0 0.5rem 0; color: #155724;">Recommended Demo Flow for Interviews</h4>
            <p style="margin: 0; color: #5A6C7D;">Follow this guide to deliver an impressive, comprehensive demonstration of your Internal Audit expertise in crypto ecosystems.</p>
        </div>
        """, unsafe_allow_html=True)

        # Step-by-step guide
        demo_steps = [
            {
                "number": "1",
                "title": "Risk Assessment Module",
                "description": "Start by demonstrating COSO-aligned risk identification for crypto operations. Show the risk universe, heat map, and scoring methodology.",
                "time": "3-4 minutes",
                "talking_points": [
                    "Explain how crypto-specific risks differ from traditional financial risks",
                    "Highlight the COSO framework alignment (Control Environment, Risk Assessment, Control Activities, Information & Communication, Monitoring)",
                    "Demonstrate inherent vs. residual risk calculations",
                    "Show how risk heat maps help prioritize audit focus"
                ]
            },
            {
                "number": "2",
                "title": "Control Testing Module",
                "description": "Navigate to Control Testing to show how controls are evaluated for design and operating effectiveness.",
                "time": "3-4 minutes",
                "talking_points": [
                    "Discuss multi-signature wallet controls as a key preventive control",
                    "Explain the difference between design effectiveness and operating effectiveness",
                    "Show how control gaps are identified and documented",
                    "Highlight HSM (Hardware Security Module) importance for key custody"
                ]
            },
            {
                "number": "3",
                "title": "Data Analytics Module",
                "description": "Demonstrate analytical procedures including sampling techniques and anomaly detection.",
                "time": "4-5 minutes",
                "talking_points": [
                    "Explain statistical sampling methods (Random, Stratified, MUS)",
                    "Show Benford's Law analysis for fraud detection",
                    "Demonstrate how outliers and unusual patterns are flagged",
                    "Discuss the importance of data analytics in continuous auditing"
                ]
            },
            {
                "number": "4",
                "title": "Wallet Reconciliation Module",
                "description": "Show blockchain verification and reconciliation processes for proof of reserves.",
                "time": "2-3 minutes",
                "talking_points": [
                    "Explain how blockchain balances are verified against book records",
                    "Discuss the importance of proof of reserves in crypto custody",
                    "Show hot wallet vs. cold storage segregation",
                    "Highlight reconciling items and variance investigation"
                ]
            },
            {
                "number": "5",
                "title": "Compliance Dashboard",
                "description": "Present regulatory compliance tracking for BSA/AML, KYC, and other requirements.",
                "time": "3-4 minutes",
                "talking_points": [
                    "Discuss key crypto regulations (BSA/AML, state MTL, Travel Rule)",
                    "Show how compliance assessments are tracked and documented",
                    "Explain the audit findings lifecycle (Open -> In Progress -> Remediated -> Closed)",
                    "Highlight the importance of continuous compliance monitoring"
                ]
            },
            {
                "number": "6",
                "title": "Report Generation",
                "description": "Conclude by demonstrating professional audit report generation capabilities.",
                "time": "2-3 minutes",
                "talking_points": [
                    "Show how findings are aggregated into professional reports",
                    "Discuss the importance of clear, actionable recommendations",
                    "Highlight management response tracking",
                    "Demonstrate export capabilities for audit workpapers"
                ]
            }
        ]

        for step in demo_steps:
            st.markdown(f"""
            <div class="guide-step">
                <div class="step-number">{step['number']}</div>
                <div class="step-content">
                    <div class="step-title">{step['title']}</div>
                    <div class="step-description">{step['description']}</div>
                    <div class="step-time">Estimated time: {step['time']}</div>
                    <div class="talking-points">
                        <div class="talking-points-title">Key Talking Points:</div>
                        <ul style="margin: 0.25rem 0 0 1rem; padding: 0;">
                            {''.join([f'<li style="margin-bottom: 0.15rem;">{point}</li>' for point in step['talking_points']])}
                        </ul>
                    </div>
                </div>
            </div>
            """, unsafe_allow_html=True)

        # Total time estimate
        st.markdown("""
        <div style="background: #fff3cd; border-radius: 8px; padding: 1rem; margin-top: 1rem; border-left: 4px solid #ffc107;">
            <strong style="color: #856404;">Total Demo Time: 17-23 minutes</strong>
            <p style="margin: 0.5rem 0 0 0; color: #856404; font-size: 0.9rem;">
                Adjust timing based on interviewer interest. Be prepared to dive deeper into any section if asked.
            </p>
        </div>
        """, unsafe_allow_html=True)

        # Pro tips section
        st.markdown("---")
        st.markdown("### Pro Tips for Interview Success")

        tip_col1, tip_col2 = st.columns(2)

        with tip_col1:
            st.markdown("""
            **Technical Depth Indicators:**
            - Reference specific control frameworks (COSO, COBIT)
            - Mention relevant regulations (BSA, AML, OFAC, Travel Rule)
            - Use proper terminology (inherent risk, residual risk, control effectiveness)
            - Discuss three lines of defense model
            - Reference SOC 1/2 reports when discussing third-party risk
            """)

        with tip_col2:
            st.markdown("""
            **Interview Differentiators:**
            - Connect crypto risks to traditional audit concepts
            - Discuss emerging risks (DeFi, smart contracts, oracle manipulation)
            - Mention proof of reserves and its importance post-FTX
            - Reference blockchain analytics tools (Chainalysis, Elliptic)
            - Discuss regulatory landscape evolution
            """)

    # =========================================================================
    # AUDIT KNOWLEDGE TOOLTIPS SECTION
    # =========================================================================
    st.markdown("---")

    # Overview section
    st.markdown('<h2 class="section-header">Internal Audit Methodology Overview</h2>', unsafe_allow_html=True)

    col1, col2 = st.columns([2, 1])

    with col1:
        st.markdown("""
        <div class="audit-card">
            <h4>About This Toolkit</h4>
            <p>This application demonstrates key Internal Audit practices specifically designed
            for cryptocurrency and digital payments ecosystems. It showcases how traditional
            audit methodologies can be adapted for the unique challenges of blockchain-based
            financial systems.</p>
            <p>The toolkit is aligned with the <strong>COSO Internal Control Framework</strong> and
            incorporates industry best practices for crypto asset custody, transaction monitoring,
            and regulatory compliance.</p>
        </div>
        """, unsafe_allow_html=True)

        st.markdown('<h3 class="section-header">Key Capabilities</h3>', unsafe_allow_html=True)

        # Capabilities with tooltips demonstrating audit knowledge
        capabilities = [
            {
                "title": "COSO-Aligned Risk Assessment",
                "description": "Comprehensive risk identification and assessment aligned with the COSO framework's five components",
                "tooltip": "COSO Framework: Control Environment, Risk Assessment, Control Activities, Information & Communication, and Monitoring Activities. Essential for SOX compliance and enterprise risk management."
            },
            {
                "title": "Control Effectiveness Testing",
                "description": "Systematic testing of internal controls with effectiveness ratings and gap analysis",
                "tooltip": "Tests both design effectiveness (is the control designed properly?) and operating effectiveness (is it working as designed?). Uses attribute sampling for compliance testing."
            },
            {
                "title": "Data Analytics and Sampling",
                "description": "Statistical sampling methods including MUS, stratified sampling, and anomaly detection",
                "tooltip": "MUS (Monetary Unit Sampling) weights selection by dollar value. Benford's Law analysis can detect manipulated data. Z-score analysis identifies statistical outliers."
            },
            {
                "title": "Blockchain Reconciliation",
                "description": "Wallet balance verification and transaction reconciliation with blockchain data",
                "tooltip": "Proof of Reserves: Verifies that custodied assets exist on-chain. Critical after crypto exchange failures. Uses blockchain explorers and on-chain analytics."
            },
            {
                "title": "Compliance Tracking",
                "description": "Regulatory compliance monitoring and checklist management for crypto operations",
                "tooltip": "Key regulations: BSA/AML (FinCEN), Travel Rule ($3K threshold), OFAC sanctions screening, state money transmitter licenses, and emerging MiCA (EU) requirements."
            },
            {
                "title": "Professional Report Generation",
                "description": "Comprehensive audit reports with findings, recommendations, and management responses",
                "tooltip": "Follows IIA standards: Condition (what is), Criteria (what should be), Cause (why it happened), Effect (risk/impact), and Recommendation (how to fix)."
            }
        ]

        for cap in capabilities:
            st.markdown(f"""
            <div class="capability-item">
                <strong>{cap['title']}</strong>
                <span title="{cap['tooltip']}" class="info-tooltip">i</span>
                <br>
                <span style="color: #5A6C7D; font-size: 0.9rem;">{cap['description']}</span>
            </div>
            """, unsafe_allow_html=True)

    with col2:
        # Quick stats with tooltips demonstrating audit knowledge
        st.markdown("""
        <div class="metric-card" title="COSO 2013 Framework: Control Environment, Risk Assessment, Control Activities, Information & Communication, Monitoring Activities">
            <div class="metric-value">5</div>
            <div class="metric-label">COSO Components</div>
        </div>
        """, unsafe_allow_html=True)
        st.caption("Hover for details")

        st.markdown("""
        <div class="metric-card" title="The 17 principles underpin the five components and provide guidance on implementing effective internal controls">
            <div class="metric-value">17</div>
            <div class="metric-label">COSO Principles</div>
        </div>
        """, unsafe_allow_html=True)

        # Count controls from library
        total_controls = sum(len(controls) for controls in CRYPTO_CONTROLS_LIBRARY.values())
        st.markdown(f"""
        <div class="metric-card" title="Includes wallet management, key custody, transaction approval, segregation of duties, access management, and change management controls">
            <div class="metric-value">{total_controls}+</div>
            <div class="metric-label">Crypto Controls</div>
        </div>
        """, unsafe_allow_html=True)

        st.markdown("""
        <div class="metric-card" title="Risk Assessment, Control Testing, Data Analytics, Wallet Reconciliation, Compliance Dashboard, Report Generation">
            <div class="metric-value">6</div>
            <div class="metric-label">Audit Modules</div>
        </div>
        """, unsafe_allow_html=True)

        # Demo data status indicator
        if st.session_state.demo_mode:
            st.markdown("""
            <div style="background: #d4edda; border-radius: 8px; padding: 0.75rem; margin-top: 0.5rem; text-align: center;">
                <span style="color: #155724; font-weight: 600;">Demo Data Loaded</span>
            </div>
            """, unsafe_allow_html=True)

    # Engagement Setup Section
    st.markdown('<h2 class="section-header">Audit Engagement Setup</h2>', unsafe_allow_html=True)

    engagement = st.session_state.audit_engagement

    with st.form("engagement_form"):
        col1, col2 = st.columns(2)

        with col1:
            # Auto-generate ID if empty
            default_id = engagement['id'] if engagement['id'] else generate_engagement_id()
            engagement_id = st.text_input(
                "Engagement ID",
                value=default_id,
                help="Unique identifier for this audit engagement"
            )

            auditor_name = st.text_input(
                "Auditor Name",
                value=engagement['auditor'],
                placeholder="Enter auditor name"
            )

            client_name = st.text_input(
                "Client Name",
                value=engagement['client'],
                placeholder="Enter client/organization name"
            )

        with col2:
            start_date = st.date_input(
                "Start Date",
                value=engagement['start_date']
            )

            end_date = st.date_input(
                "End Date",
                value=engagement['end_date']
            )

            status = st.selectbox(
                "Engagement Status",
                options=["Not Started", "Planning", "Fieldwork", "Reporting", "Completed"],
                index=["Not Started", "Planning", "Fieldwork", "Reporting", "Completed"].index(
                    engagement['status']
                )
            )

        scope_description = st.text_area(
            "Engagement Scope",
            value=engagement['scope'],
            placeholder="Describe the scope of this internal audit engagement...",
            height=100
        )

        submitted = st.form_submit_button("Save Engagement", type="primary", use_container_width=True)

        if submitted:
            st.session_state.audit_engagement = {
                'id': engagement_id,
                'auditor': auditor_name,
                'client': client_name,
                'scope': scope_description,
                'start_date': start_date,
                'end_date': end_date,
                'status': status
            }
            st.success(f"Engagement {engagement_id} saved successfully!")
            st.rerun()

    # Display current engagement if set
    if st.session_state.audit_engagement['id']:
        st.markdown('<h3 class="section-header">Current Engagement Details</h3>', unsafe_allow_html=True)

        eng = st.session_state.audit_engagement

        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Engagement ID", eng['id'])
        with col2:
            st.metric("Auditor", eng['auditor'] or "Not set")
        with col3:
            st.metric("Client", eng['client'] or "Not set")
        with col4:
            st.metric("Status", eng['status'])

        if eng['scope']:
            st.markdown(f"""
            <div class="info-box">
                <strong>Scope:</strong> {eng['scope']}
            </div>
            """, unsafe_allow_html=True)

    # Skills Alignment Section
    st.markdown('<h2 class="section-header">Skills Alignment</h2>', unsafe_allow_html=True)

    st.markdown("""
    <div class="skills-card">
        <h4>How This Application Demonstrates Internal Audit Skills</h4>
        <p>This toolkit showcases competencies relevant to Internal Audit positions in crypto/payments:</p>
    </div>
    """, unsafe_allow_html=True)

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("""
        **Risk Assessment Practices**
        - Identification of crypto-specific risks (custody, smart contract, regulatory)
        - Likelihood and impact assessment using risk matrices
        - Inherent and residual risk calculations
        - Risk prioritization and heat mapping

        **Internal Control Concepts**
        - COSO framework application to crypto operations
        - Three lines of defense model understanding
        - Control design and operating effectiveness testing
        - Gap analysis and remediation tracking
        """)

    with col2:
        st.markdown("""
        **Data Analytics Usage**
        - Statistical sampling techniques (random, stratified, MUS)
        - Anomaly detection algorithms
        - Benford's Law analysis for fraud detection
        - Pattern recognition in transaction data

        **Critical Thinking in Crypto**
        - Understanding unique risks in crypto ecosystems
        - Blockchain verification and reconciliation
        - Regulatory compliance challenges
        - Emerging risk identification
        """)


# =============================================================================
# PLACEHOLDER SECTIONS
# =============================================================================

def render_placeholder_section(section_name: str, description: str):
    """Render a placeholder for sections being implemented by other builders."""

    st.markdown(f'<h1 class="main-header">{section_name}</h1>', unsafe_allow_html=True)

    st.markdown(f"""
    <div class="loading-placeholder">
        <h3>Module Loading...</h3>
        <p>{description}</p>
        <p style="font-size: 0.9rem; color: #888;">
            This module is being implemented and will be available soon.
        </p>
    </div>
    """, unsafe_allow_html=True)

    # Show what will be available
    st.markdown('<h3 class="section-header">Planned Features</h3>', unsafe_allow_html=True)

    features = {
        "Risk Assessment": [
            "COSO-aligned risk identification",
            "Risk likelihood and impact assessment",
            "Risk heat map visualization",
            "Inherent vs. residual risk tracking",
            "Risk register management"
        ],
        "Control Testing": [
            "Control library with crypto-specific controls",
            "Test procedure documentation",
            "Control effectiveness rating",
            "Exception tracking and follow-up",
            "Control gap analysis"
        ],
        "Data Analytics": [
            "Transaction sampling (random, stratified, MUS)",
            "Anomaly detection algorithms",
            "Benford's Law analysis",
            "Statistical analysis dashboards",
            "Pattern recognition tools"
        ],
        "Wallet Reconciliation": [
            "Blockchain balance verification",
            "Multi-wallet reconciliation",
            "Transaction matching",
            "Discrepancy investigation",
            "Proof of reserves analysis"
        ],
        "Compliance Dashboard": [
            "Regulatory checklist management",
            "Compliance status tracking",
            "Policy attestation tracking",
            "Regulatory change monitoring",
            "Compliance scoring"
        ],
        "Report Generation": [
            "Executive summary generation",
            "Detailed findings documentation",
            "Management response tracking",
            "Remediation timelines",
            "PDF/Excel export capabilities"
        ]
    }

    if section_name in features:
        for feature in features[section_name]:
            st.markdown(f"- {feature}")


def render_risk_assessment():
    """Render the Risk Assessment section with full functionality."""

    # Page header
    st.markdown('<h1 class="main-header">Risk Assessment</h1>', unsafe_allow_html=True)
    st.markdown(
        '<p class="sub-header">COSO-aligned risk identification and assessment for crypto operations</p>',
        unsafe_allow_html=True
    )

    # Load sample data if demo mode is enabled and no risks exist
    if st.session_state.demo_mode and not st.session_state.identified_risks:
        st.session_state.identified_risks = [risk.copy() for risk in SAMPLE_CRYPTO_RISKS]
        st.toast("Demo data loaded successfully!", icon="check")

    # Create tabs for different sections
    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "Risk Universe",
        "Risk Register",
        "Risk Scoring",
        "Risk Heat Map",
        "Export Workpaper"
    ])

    # ==========================================================================
    # TAB 1: RISK UNIVERSE
    # ==========================================================================
    with tab1:
        st.markdown('<h2 class="section-header">Crypto Risk Universe</h2>', unsafe_allow_html=True)

        st.markdown("""
        <div class="info-box">
            <strong>About the Risk Universe:</strong> The risk universe represents all potential risk categories
            specific to cryptocurrency operations. Each category contains sub-risks that should be assessed
            during the risk identification process.
        </div>
        """, unsafe_allow_html=True)

        # Display risk categories in a 3-column layout
        cols = st.columns(3)

        for idx, (category_key, category) in enumerate(RISK_CATEGORIES.items()):
            col_idx = idx % 3
            with cols[col_idx]:
                # Get count of identified risks in this category
                risk_count = len([r for r in st.session_state.identified_risks
                                  if r.get('category') == category_key])

                st.markdown(f"""
                <div class="audit-card" style="border-left-color: {category['color']};">
                    <h4 style="color: {category['color']}; margin-bottom: 0.5rem;">
                        {category['name']}
                    </h4>
                    <p style="font-size: 0.9rem; color: #5A6C7D; margin-bottom: 1rem;">
                        {category['description']}
                    </p>
                    <div style="background: #f1f3f4; padding: 0.5rem; border-radius: 8px; margin-bottom: 0.5rem;">
                        <strong>Risks Identified:</strong> {risk_count}
                    </div>
                    <details>
                        <summary style="cursor: pointer; color: #1E3A5F; font-weight: 600;">
                            View Sub-Categories
                        </summary>
                        <ul style="margin-top: 0.5rem; padding-left: 1.25rem;">
                            {''.join([f'<li style="font-size: 0.85rem; color: #5A6C7D;">{sub}</li>'
                                      for sub in category['sub_categories']])}
                        </ul>
                    </details>
                </div>
                """, unsafe_allow_html=True)

        # Summary metrics
        st.markdown('<h3 class="section-header">Risk Universe Summary</h3>', unsafe_allow_html=True)

        metric_cols = st.columns(6)
        total_risks = len(st.session_state.identified_risks)

        for idx, (cat_key, cat) in enumerate(RISK_CATEGORIES.items()):
            with metric_cols[idx]:
                count = len([r for r in st.session_state.identified_risks
                             if r.get('category') == cat_key])
                st.markdown(f"""
                <div class="metric-card">
                    <div class="metric-value" style="color: {cat['color']};">{count}</div>
                    <div class="metric-label">{cat['name'].replace(' Risk', '')}</div>
                </div>
                """, unsafe_allow_html=True)

    # ==========================================================================
    # TAB 2: RISK REGISTER
    # ==========================================================================
    with tab2:
        st.markdown('<h2 class="section-header">Risk Register</h2>', unsafe_allow_html=True)

        # Add new risk form
        with st.expander("Add New Risk", expanded=False):
            with st.form("add_risk_form", clear_on_submit=True):
                col1, col2 = st.columns(2)

                with col1:
                    risk_name = st.text_input(
                        "Risk Name*",
                        placeholder="Enter a descriptive risk name"
                    )

                    risk_category = st.selectbox(
                        "Risk Category*",
                        options=list(RISK_CATEGORIES.keys()),
                        format_func=lambda x: RISK_CATEGORIES[x]['name']
                    )

                    coso_component = st.selectbox(
                        "COSO Component*",
                        options=list(COSOComponent),
                        format_func=lambda x: x.value.replace('_', ' ').title()
                    )

                    risk_owner = st.text_input(
                        "Risk Owner",
                        placeholder="Enter the responsible owner"
                    )

                with col2:
                    likelihood = st.select_slider(
                        "Likelihood (1-5)*",
                        options=[1, 2, 3, 4, 5],
                        value=3,
                        help="1=Rare, 2=Unlikely, 3=Possible, 4=Likely, 5=Almost Certain"
                    )

                    impact = st.select_slider(
                        "Impact (1-5)*",
                        options=[1, 2, 3, 4, 5],
                        value=3,
                        help="1=Insignificant, 2=Minor, 3=Moderate, 4=Major, 5=Catastrophic"
                    )

                    risk_status = st.selectbox(
                        "Status",
                        options=["Open", "Mitigated", "Accepted", "Closed"]
                    )

                risk_description = st.text_area(
                    "Risk Description*",
                    placeholder="Provide a detailed description of the risk...",
                    height=100
                )

                # Inherent risk factors
                st.markdown("**Inherent Risk Factors** (Rate 1-5)")
                factor_cols = st.columns(4)
                with factor_cols[0]:
                    complexity = st.slider("Complexity", 1, 5, 3, key="new_complexity")
                with factor_cols[1]:
                    volume = st.slider("Volume", 1, 5, 3, key="new_volume")
                with factor_cols[2]:
                    regulatory = st.slider("Regulatory", 1, 5, 3, key="new_regulatory")
                with factor_cols[3]:
                    technology = st.slider("Technology", 1, 5, 3, key="new_technology")

                submitted = st.form_submit_button("Add Risk", type="primary", use_container_width=True)

                if submitted:
                    if risk_name and risk_description:
                        new_risk = {
                            "id": f"RISK-{str(uuid.uuid4())[:8].upper()}",
                            "name": risk_name,
                            "description": risk_description,
                            "category": risk_category,
                            "coso_component": coso_component,
                            "likelihood": likelihood,
                            "impact": impact,
                            "inherent_factors": {
                                "complexity": complexity,
                                "volume": volume,
                                "regulatory": regulatory,
                                "technology": technology
                            },
                            "control_effectiveness": {},
                            "owner": risk_owner or "Unassigned",
                            "status": risk_status
                        }
                        st.session_state.identified_risks.append(new_risk)
                        st.success(f"Risk '{risk_name}' added successfully!")
                        st.rerun()
                    else:
                        st.error("Please fill in all required fields (marked with *)")

        # Display risk register
        if st.session_state.identified_risks:
            # Filter options
            st.markdown("**Filter Risks**")
            filter_cols = st.columns(4)

            with filter_cols[0]:
                filter_category = st.multiselect(
                    "Category",
                    options=list(RISK_CATEGORIES.keys()),
                    format_func=lambda x: RISK_CATEGORIES[x]['name'],
                    default=None
                )

            with filter_cols[1]:
                filter_rating = st.multiselect(
                    "Rating",
                    options=["Low", "Medium", "High", "Critical"],
                    default=None
                )

            with filter_cols[2]:
                filter_status = st.multiselect(
                    "Status",
                    options=["Open", "Mitigated", "Accepted", "Closed"],
                    default=None
                )

            with filter_cols[3]:
                sort_by = st.selectbox(
                    "Sort By",
                    options=["Risk Score (High to Low)", "Risk Score (Low to High)", "Name (A-Z)"]
                )

            # Filter and sort risks
            filtered_risks = st.session_state.identified_risks.copy()

            if filter_category:
                filtered_risks = [r for r in filtered_risks if r.get('category') in filter_category]

            if filter_rating:
                filtered_risks = [r for r in filtered_risks
                                  if get_risk_rating(r.get('likelihood', 1) * r.get('impact', 1)) in filter_rating]

            if filter_status:
                filtered_risks = [r for r in filtered_risks if r.get('status') in filter_status]

            # Sort risks
            if sort_by == "Risk Score (High to Low)":
                filtered_risks.sort(key=lambda x: x.get('likelihood', 1) * x.get('impact', 1), reverse=True)
            elif sort_by == "Risk Score (Low to High)":
                filtered_risks.sort(key=lambda x: x.get('likelihood', 1) * x.get('impact', 1))
            else:
                filtered_risks.sort(key=lambda x: x.get('name', ''))

            st.markdown(f"**Showing {len(filtered_risks)} of {len(st.session_state.identified_risks)} risks**")

            # Display risks as cards
            for risk in filtered_risks:
                risk_score = risk.get('likelihood', 1) * risk.get('impact', 1)
                rating = get_risk_rating(risk_score)
                badge_class = f"badge-{rating.lower()}"

                # Calculate inherent and residual risk
                inherent_factors = risk.get('inherent_factors', {'complexity': 3, 'volume': 3, 'regulatory': 3, 'technology': 3})
                control_eff = risk.get('control_effectiveness', {})

                inherent_risk = calculate_inherent_risk(inherent_factors)
                residual_risk = calculate_residual_risk(inherent_risk, control_eff) if control_eff else inherent_risk

                coso_value = risk.get('coso_component', COSOComponent.RISK_ASSESSMENT)
                if isinstance(coso_value, COSOComponent):
                    coso_display = coso_value.value.replace('_', ' ').title()
                else:
                    coso_display = str(coso_value).replace('_', ' ').title()

                st.markdown(f"""
                <div class="audit-card">
                    <div style="display: flex; justify-content: space-between; align-items: flex-start;">
                        <div>
                            <h4 style="margin-bottom: 0.25rem;">{risk.get('name', 'Unknown')}</h4>
                            <span style="font-size: 0.8rem; color: #6c757d;">ID: {risk.get('id', 'N/A')} |
                            Category: {RISK_CATEGORIES.get(risk.get('category', 'custody'), {}).get('name', 'Unknown')}</span>
                        </div>
                        <div>
                            <span class="{badge_class}">{rating}</span>
                        </div>
                    </div>
                    <p style="margin-top: 0.75rem; margin-bottom: 0.75rem; color: #5A6C7D;">
                        {risk.get('description', 'No description provided.')[:200]}{'...' if len(risk.get('description', '')) > 200 else ''}
                    </p>
                    <div style="display: flex; gap: 2rem; flex-wrap: wrap;">
                        <div>
                            <strong>Likelihood:</strong> {risk.get('likelihood', 'N/A')} |
                            <strong>Impact:</strong> {risk.get('impact', 'N/A')} |
                            <strong>Score:</strong> {risk_score}
                        </div>
                        <div>
                            <strong>Inherent Risk:</strong> {inherent_risk:.2f} |
                            <strong>Residual Risk:</strong> {residual_risk:.2f}
                        </div>
                    </div>
                    <div style="margin-top: 0.5rem; font-size: 0.85rem; color: #6c757d;">
                        <strong>COSO:</strong> {coso_display} |
                        <strong>Owner:</strong> {risk.get('owner', 'Unassigned')} |
                        <strong>Status:</strong> {risk.get('status', 'Open')}
                    </div>
                </div>
                """, unsafe_allow_html=True)

            # Delete risk option
            st.markdown("---")
            with st.expander("Manage Risks"):
                risk_to_delete = st.selectbox(
                    "Select risk to delete",
                    options=[r.get('id') for r in st.session_state.identified_risks],
                    format_func=lambda x: next((r.get('name') for r in st.session_state.identified_risks
                                                 if r.get('id') == x), x)
                )

                if st.button("Delete Selected Risk", type="secondary"):
                    st.session_state.identified_risks = [
                        r for r in st.session_state.identified_risks
                        if r.get('id') != risk_to_delete
                    ]
                    st.success("Risk deleted successfully!")
                    st.rerun()
        else:
            st.markdown("""
            <div class="warning-box">
                <strong>No risks identified yet.</strong> Use the form above to add risks,
                or enable Demo Mode in the sidebar to load sample data.
            </div>
            """, unsafe_allow_html=True)

    # ==========================================================================
    # TAB 3: RISK SCORING
    # ==========================================================================
    with tab3:
        st.markdown('<h2 class="section-header">Interactive Risk Scoring</h2>', unsafe_allow_html=True)

        st.markdown("""
        <div class="info-box">
            <strong>Risk Scoring Matrix:</strong> Use the interactive tool below to calculate risk scores
            based on the standard 5x5 Likelihood x Impact matrix. The resulting score determines the
            risk rating (Low, Medium, High, or Critical).
        </div>
        """, unsafe_allow_html=True)

        col1, col2 = st.columns([1, 1])

        with col1:
            st.markdown("### Calculate Risk Score")

            likelihood_options = {
                1: "1 - Rare (< 10% probability)",
                2: "2 - Unlikely (10-25% probability)",
                3: "3 - Possible (25-50% probability)",
                4: "4 - Likely (50-75% probability)",
                5: "5 - Almost Certain (> 75% probability)"
            }

            impact_options = {
                1: "1 - Insignificant (Minimal impact)",
                2: "2 - Minor (Limited impact)",
                3: "3 - Moderate (Significant impact)",
                4: "4 - Major (Serious impact)",
                5: "5 - Catastrophic (Severe impact)"
            }

            selected_likelihood = st.selectbox(
                "Select Likelihood",
                options=list(likelihood_options.keys()),
                format_func=lambda x: likelihood_options[x],
                key="scoring_likelihood"
            )

            selected_impact = st.selectbox(
                "Select Impact",
                options=list(impact_options.keys()),
                format_func=lambda x: impact_options[x],
                key="scoring_impact"
            )

            # Calculate and display results
            calc_score = calculate_risk_score(selected_likelihood, selected_impact)
            calc_rating = get_risk_rating(calc_score)

            # Display the result with appropriate styling
            rating_colors = {
                "Low": "#28a745",
                "Medium": "#ffc107",
                "High": "#fd7e14",
                "Critical": "#dc3545"
            }

            st.markdown(f"""
            <div class="metric-card" style="margin-top: 1rem; border-left: 4px solid {rating_colors.get(calc_rating, '#1E3A5F')};">
                <div class="metric-value" style="color: {rating_colors.get(calc_rating, '#1E3A5F')};">{calc_score}</div>
                <div class="metric-label">Risk Score</div>
                <div style="margin-top: 0.5rem;">
                    <span class="badge-{calc_rating.lower()}">{calc_rating}</span>
                </div>
            </div>
            """, unsafe_allow_html=True)

        with col2:
            st.markdown("### Risk Score Matrix Reference")

            # Create a visual matrix
            matrix_html = """
            <table style="width: 100%; border-collapse: collapse; text-align: center; font-size: 0.85rem;">
                <tr>
                    <th style="padding: 8px; background: #1E3A5F; color: white;"></th>
                    <th style="padding: 8px; background: #1E3A5F; color: white;">Impact 1</th>
                    <th style="padding: 8px; background: #1E3A5F; color: white;">Impact 2</th>
                    <th style="padding: 8px; background: #1E3A5F; color: white;">Impact 3</th>
                    <th style="padding: 8px; background: #1E3A5F; color: white;">Impact 4</th>
                    <th style="padding: 8px; background: #1E3A5F; color: white;">Impact 5</th>
                </tr>
            """

            for likelihood in range(5, 0, -1):
                matrix_html += f"<tr><td style='padding: 8px; background: #1E3A5F; color: white; font-weight: bold;'>L{likelihood}</td>"
                for impact in range(1, 6):
                    score = likelihood * impact
                    rating = get_risk_rating(score)
                    bg_color = rating_colors.get(rating, '#f8f9fa')
                    text_color = 'white' if rating in ['High', 'Critical'] else '#212529'
                    matrix_html += f"<td style='padding: 8px; background: {bg_color}; color: {text_color}; font-weight: 600;'>{score}</td>"
                matrix_html += "</tr>"

            matrix_html += "</table>"
            st.markdown(matrix_html, unsafe_allow_html=True)

            # Legend
            st.markdown("""
            <div style="margin-top: 1rem; display: flex; gap: 1rem; flex-wrap: wrap;">
                <span><span class="badge-low">Low (1-4)</span></span>
                <span><span class="badge-medium">Medium (5-9)</span></span>
                <span><span class="badge-high">High (10-16)</span></span>
                <span><span class="badge-critical">Critical (17-25)</span></span>
            </div>
            """, unsafe_allow_html=True)

        # Inherent vs Residual Risk Calculator
        st.markdown('<h3 class="section-header">Inherent vs Residual Risk Calculator</h3>', unsafe_allow_html=True)

        calc_col1, calc_col2, calc_col3 = st.columns(3)

        with calc_col1:
            st.markdown("**Inherent Risk Factors**")
            ir_complexity = st.slider("Complexity", 1, 5, 3, key="ir_complexity")
            ir_volume = st.slider("Volume", 1, 5, 3, key="ir_volume")
            ir_regulatory = st.slider("Regulatory Exposure", 1, 5, 3, key="ir_regulatory")
            ir_technology = st.slider("Technology Dependency", 1, 5, 3, key="ir_technology")

        with calc_col2:
            st.markdown("**Control Effectiveness**")
            ctrl_1 = st.slider("Control 1 Effectiveness", 0.0, 1.0, 0.7, 0.05, key="ctrl_1")
            ctrl_2 = st.slider("Control 2 Effectiveness", 0.0, 1.0, 0.7, 0.05, key="ctrl_2")
            ctrl_3 = st.slider("Control 3 Effectiveness", 0.0, 1.0, 0.7, 0.05, key="ctrl_3")

        with calc_col3:
            st.markdown("**Results**")

            ir_factors = {
                "complexity": ir_complexity,
                "volume": ir_volume,
                "regulatory": ir_regulatory,
                "technology": ir_technology
            }

            controls = {
                "control_1": ctrl_1,
                "control_2": ctrl_2,
                "control_3": ctrl_3
            }

            inherent = calculate_inherent_risk(ir_factors)
            residual = calculate_residual_risk(inherent, controls)
            reduction = ((inherent - residual) / inherent) * 100 if inherent > 0 else 0

            st.markdown(f"""
            <div class="metric-card" style="margin-bottom: 0.5rem;">
                <div class="metric-value" style="color: #fd7e14;">{inherent:.2f}</div>
                <div class="metric-label">Inherent Risk</div>
            </div>
            """, unsafe_allow_html=True)

            st.markdown(f"""
            <div class="metric-card" style="margin-bottom: 0.5rem;">
                <div class="metric-value" style="color: #28a745;">{residual:.2f}</div>
                <div class="metric-label">Residual Risk</div>
            </div>
            """, unsafe_allow_html=True)

            st.markdown(f"""
            <div class="metric-card">
                <div class="metric-value" style="color: #0288D1;">{reduction:.1f}%</div>
                <div class="metric-label">Risk Reduction</div>
            </div>
            """, unsafe_allow_html=True)

    # ==========================================================================
    # TAB 4: RISK HEAT MAP
    # ==========================================================================
    with tab4:
        st.markdown('<h2 class="section-header">Risk Heat Map</h2>', unsafe_allow_html=True)

        if st.session_state.identified_risks:
            # Get heatmap data
            heatmap_data = create_risk_heatmap_data(st.session_state.identified_risks)

            # Summary metrics
            st.markdown("### Risk Distribution Summary")

            summary_cols = st.columns(5)

            with summary_cols[0]:
                st.markdown(f"""
                <div class="metric-card">
                    <div class="metric-value">{heatmap_data['total_risks']}</div>
                    <div class="metric-label">Total Risks</div>
                </div>
                """, unsafe_allow_html=True)

            with summary_cols[1]:
                st.markdown(f"""
                <div class="metric-card">
                    <div class="metric-value" style="color: #28a745;">{heatmap_data['counts']['Low']}</div>
                    <div class="metric-label">Low</div>
                </div>
                """, unsafe_allow_html=True)

            with summary_cols[2]:
                st.markdown(f"""
                <div class="metric-card">
                    <div class="metric-value" style="color: #ffc107;">{heatmap_data['counts']['Medium']}</div>
                    <div class="metric-label">Medium</div>
                </div>
                """, unsafe_allow_html=True)

            with summary_cols[3]:
                st.markdown(f"""
                <div class="metric-card">
                    <div class="metric-value" style="color: #fd7e14;">{heatmap_data['counts']['High']}</div>
                    <div class="metric-label">High</div>
                </div>
                """, unsafe_allow_html=True)

            with summary_cols[4]:
                st.markdown(f"""
                <div class="metric-card">
                    <div class="metric-value" style="color: #dc3545;">{heatmap_data['counts']['Critical']}</div>
                    <div class="metric-label">Critical</div>
                </div>
                """, unsafe_allow_html=True)

            # Visual Heat Map using Streamlit columns
            st.markdown("### 5x5 Risk Heat Map")
            st.markdown("""
            <p style="color: #5A6C7D; font-size: 0.9rem;">
                The heat map displays risks based on their likelihood (vertical axis) and impact (horizontal axis).
                Numbers in cells indicate the count of risks in that position.
            </p>
            """, unsafe_allow_html=True)

            # Create header row
            header_cols = st.columns([1, 1, 1, 1, 1, 1])
            with header_cols[0]:
                st.markdown("**Likelihood \\ Impact**")
            for i, label in enumerate(heatmap_data['labels']['impact']):
                with header_cols[i + 1]:
                    st.markdown(f"**{i+1}**", help=label)

            # Create heat map rows (from highest likelihood to lowest)
            likelihood_labels = heatmap_data['labels']['likelihood']

            for likelihood_idx in range(4, -1, -1):
                row_cols = st.columns([1, 1, 1, 1, 1, 1])

                with row_cols[0]:
                    st.markdown(f"**{likelihood_idx + 1}**", help=likelihood_labels[likelihood_idx])

                for impact_idx in range(5):
                    with row_cols[impact_idx + 1]:
                        cell_risks = heatmap_data['matrix'][likelihood_idx][impact_idx]
                        risk_count = len(cell_risks)
                        score = (likelihood_idx + 1) * (impact_idx + 1)
                        rating = get_risk_rating(score)

                        # Set colors based on rating
                        bg_colors = {
                            "Low": "#d4edda",
                            "Medium": "#fff3cd",
                            "High": "#ffe0b2",
                            "Critical": "#f8d7da"
                        }
                        text_colors = {
                            "Low": "#155724",
                            "Medium": "#856404",
                            "High": "#e65100",
                            "Critical": "#721c24"
                        }

                        bg = bg_colors.get(rating, '#f8f9fa')
                        txt = text_colors.get(rating, '#212529')

                        # Create cell content
                        risk_names = ""
                        if cell_risks:
                            risk_names = ", ".join([r['name'][:15] + "..." if len(r['name']) > 15 else r['name']
                                                    for r in cell_risks[:3]])
                            if len(cell_risks) > 3:
                                risk_names += f" +{len(cell_risks) - 3} more"

                        st.markdown(f"""
                        <div style="background: {bg}; padding: 1rem; border-radius: 8px;
                                    text-align: center; min-height: 60px; display: flex;
                                    flex-direction: column; justify-content: center;">
                            <div style="font-size: 1.5rem; font-weight: 700; color: {txt};">
                                {risk_count if risk_count > 0 else '-'}
                            </div>
                            <div style="font-size: 0.7rem; color: {txt};">
                                Score: {score}
                            </div>
                        </div>
                        """, unsafe_allow_html=True)

                        if cell_risks:
                            with st.expander(f"View {risk_count} risk(s)"):
                                for r in cell_risks:
                                    st.markdown(f"- **{r['name']}** (Score: {r['score']})")

            # Legend
            st.markdown("### Legend")
            legend_cols = st.columns(4)
            with legend_cols[0]:
                st.markdown('<div style="background: #d4edda; padding: 0.5rem; border-radius: 4px; text-align: center;">Low (1-4)</div>', unsafe_allow_html=True)
            with legend_cols[1]:
                st.markdown('<div style="background: #fff3cd; padding: 0.5rem; border-radius: 4px; text-align: center;">Medium (5-9)</div>', unsafe_allow_html=True)
            with legend_cols[2]:
                st.markdown('<div style="background: #ffe0b2; padding: 0.5rem; border-radius: 4px; text-align: center;">High (10-16)</div>', unsafe_allow_html=True)
            with legend_cols[3]:
                st.markdown('<div style="background: #f8d7da; padding: 0.5rem; border-radius: 4px; text-align: center;">Critical (17-25)</div>', unsafe_allow_html=True)

        else:
            st.markdown("""
            <div class="warning-box">
                <strong>No risks to display.</strong> Add risks in the Risk Register tab or enable Demo Mode
                to load sample data for the heat map visualization.
            </div>
            """, unsafe_allow_html=True)

    # ==========================================================================
    # TAB 5: EXPORT WORKPAPER
    # ==========================================================================
    with tab5:
        st.markdown('<h2 class="section-header">Export Risk Assessment Workpaper</h2>', unsafe_allow_html=True)

        st.markdown("""
        <div class="info-box">
            <strong>Export Options:</strong> Generate a comprehensive risk assessment workpaper for
            documentation and review purposes. The export includes all identified risks with their
            scores, ratings, and control effectiveness information.
        </div>
        """, unsafe_allow_html=True)

        if st.session_state.identified_risks:
            # Prepare export data
            export_data = []
            for risk in st.session_state.identified_risks:
                inherent_factors = risk.get('inherent_factors', {'complexity': 3, 'volume': 3, 'regulatory': 3, 'technology': 3})
                control_eff = risk.get('control_effectiveness', {})

                inherent_risk = calculate_inherent_risk(inherent_factors)
                residual_risk = calculate_residual_risk(inherent_risk, control_eff) if control_eff else inherent_risk
                risk_score = risk.get('likelihood', 1) * risk.get('impact', 1)

                coso_value = risk.get('coso_component', COSOComponent.RISK_ASSESSMENT)
                if isinstance(coso_value, COSOComponent):
                    coso_display = coso_value.value.replace('_', ' ').title()
                else:
                    coso_display = str(coso_value).replace('_', ' ').title()

                export_data.append({
                    'Risk ID': risk.get('id', 'N/A'),
                    'Risk Name': risk.get('name', 'Unknown'),
                    'Category': RISK_CATEGORIES.get(risk.get('category', 'custody'), {}).get('name', 'Unknown'),
                    'Description': risk.get('description', ''),
                    'COSO Component': coso_display,
                    'Likelihood': risk.get('likelihood', 'N/A'),
                    'Impact': risk.get('impact', 'N/A'),
                    'Risk Score': risk_score,
                    'Risk Rating': get_risk_rating(risk_score),
                    'Inherent Risk': round(inherent_risk, 2),
                    'Residual Risk': round(residual_risk, 2),
                    'Owner': risk.get('owner', 'Unassigned'),
                    'Status': risk.get('status', 'Open')
                })

            # Display preview
            st.markdown("### Export Preview")
            df = pd.DataFrame(export_data)
            st.dataframe(df, use_container_width=True, hide_index=True)

            # Export options
            st.markdown("### Download Options")

            export_cols = st.columns(3)

            with export_cols[0]:
                # CSV Export
                csv_data = df.to_csv(index=False)
                st.download_button(
                    label="Download as CSV",
                    data=csv_data,
                    file_name=f"risk_assessment_workpaper_{datetime.date.today().isoformat()}.csv",
                    mime="text/csv",
                    use_container_width=True
                )

            with export_cols[1]:
                # Text/Markdown Export
                engagement = st.session_state.audit_engagement

                text_content = f"""RISK ASSESSMENT WORKPAPER
========================
Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Engagement ID: {engagement.get('id', 'N/A')}
Auditor: {engagement.get('auditor', 'N/A')}
Client: {engagement.get('client', 'N/A')}

EXECUTIVE SUMMARY
-----------------
Total Risks Identified: {len(st.session_state.identified_risks)}
Critical Risks: {len([r for r in st.session_state.identified_risks if get_risk_rating(r.get('likelihood', 1) * r.get('impact', 1)) == 'Critical'])}
High Risks: {len([r for r in st.session_state.identified_risks if get_risk_rating(r.get('likelihood', 1) * r.get('impact', 1)) == 'High'])}
Medium Risks: {len([r for r in st.session_state.identified_risks if get_risk_rating(r.get('likelihood', 1) * r.get('impact', 1)) == 'Medium'])}
Low Risks: {len([r for r in st.session_state.identified_risks if get_risk_rating(r.get('likelihood', 1) * r.get('impact', 1)) == 'Low'])}

RISK REGISTER
-------------
"""

                for idx, row in enumerate(export_data, 1):
                    text_content += f"""
{idx}. {row['Risk Name']} [{row['Risk ID']}]
   Category: {row['Category']}
   Description: {row['Description']}
   COSO Component: {row['COSO Component']}
   Likelihood: {row['Likelihood']} | Impact: {row['Impact']} | Score: {row['Risk Score']} | Rating: {row['Risk Rating']}
   Inherent Risk: {row['Inherent Risk']} | Residual Risk: {row['Residual Risk']}
   Owner: {row['Owner']} | Status: {row['Status']}
"""

                text_content += f"""
METHODOLOGY
-----------
Risk scoring is based on a 5x5 Likelihood x Impact matrix:
- Low (1-4): Acceptable risk level
- Medium (5-9): Monitor and review
- High (10-16): Action required
- Critical (17-25): Immediate action required

Inherent Risk: Average of complexity, volume, regulatory exposure, and technology dependency factors (1-5 scale)
Residual Risk: Inherent risk reduced by average control effectiveness

COSO Framework Components:
- Control Environment
- Risk Assessment
- Control Activities
- Information & Communication
- Monitoring Activities

---
End of Workpaper
"""

                st.download_button(
                    label="Download as Text",
                    data=text_content,
                    file_name=f"risk_assessment_workpaper_{datetime.date.today().isoformat()}.txt",
                    mime="text/plain",
                    use_container_width=True
                )

            with export_cols[2]:
                # Summary stats download
                summary_content = f"""Risk Assessment Summary Statistics
Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Total Risks: {len(st.session_state.identified_risks)}

By Rating:
- Critical: {len([r for r in st.session_state.identified_risks if get_risk_rating(r.get('likelihood', 1) * r.get('impact', 1)) == 'Critical'])}
- High: {len([r for r in st.session_state.identified_risks if get_risk_rating(r.get('likelihood', 1) * r.get('impact', 1)) == 'High'])}
- Medium: {len([r for r in st.session_state.identified_risks if get_risk_rating(r.get('likelihood', 1) * r.get('impact', 1)) == 'Medium'])}
- Low: {len([r for r in st.session_state.identified_risks if get_risk_rating(r.get('likelihood', 1) * r.get('impact', 1)) == 'Low'])}

By Category:
"""
                for cat_key, cat in RISK_CATEGORIES.items():
                    count = len([r for r in st.session_state.identified_risks if r.get('category') == cat_key])
                    summary_content += f"- {cat['name']}: {count}\n"

                summary_content += f"""
By Status:
- Open: {len([r for r in st.session_state.identified_risks if r.get('status') == 'Open'])}
- Mitigated: {len([r for r in st.session_state.identified_risks if r.get('status') == 'Mitigated'])}
- Accepted: {len([r for r in st.session_state.identified_risks if r.get('status') == 'Accepted'])}
- Closed: {len([r for r in st.session_state.identified_risks if r.get('status') == 'Closed'])}

Average Scores:
- Average Risk Score: {sum([r.get('likelihood', 1) * r.get('impact', 1) for r in st.session_state.identified_risks]) / len(st.session_state.identified_risks):.2f}
- Average Likelihood: {sum([r.get('likelihood', 1) for r in st.session_state.identified_risks]) / len(st.session_state.identified_risks):.2f}
- Average Impact: {sum([r.get('impact', 1) for r in st.session_state.identified_risks]) / len(st.session_state.identified_risks):.2f}
"""

                st.download_button(
                    label="Download Summary",
                    data=summary_content,
                    file_name=f"risk_summary_{datetime.date.today().isoformat()}.txt",
                    mime="text/plain",
                    use_container_width=True
                )

        else:
            st.markdown("""
            <div class="warning-box">
                <strong>No risks to export.</strong> Add risks in the Risk Register tab or enable Demo Mode
                to load sample data before exporting.
            </div>
            """, unsafe_allow_html=True)


def render_control_testing():
    """Render the Control Testing section with full functionality."""

    # Three Lines of Defense Model Definition
    THREE_LINES_OF_DEFENSE = {
        "first_line": {
            "name": "First Line of Defense",
            "title": "Operational Management",
            "color": "#28a745",
            "description": "Business operations and front-line controls",
            "responsibilities": [
                "Day-to-day control ownership",
                "Risk identification and assessment",
                "Control implementation and execution",
                "Issue identification and escalation",
                "Process documentation"
            ],
            "crypto_examples": [
                "Transaction approval and execution",
                "Wallet balance monitoring",
                "Customer onboarding verification",
                "Daily reconciliation execution"
            ]
        },
        "second_line": {
            "name": "Second Line of Defense",
            "title": "Risk Management & Compliance",
            "color": "#ffc107",
            "description": "Oversight and monitoring functions",
            "responsibilities": [
                "Risk framework development",
                "Policy and procedure design",
                "Control monitoring and testing",
                "Compliance monitoring",
                "Risk reporting to management"
            ],
            "crypto_examples": [
                "AML/KYC compliance monitoring",
                "Transaction monitoring rules",
                "Regulatory reporting oversight",
                "Risk limit monitoring"
            ]
        },
        "third_line": {
            "name": "Third Line of Defense",
            "title": "Internal Audit",
            "color": "#dc3545",
            "description": "Independent assurance function",
            "responsibilities": [
                "Independent control evaluation",
                "Risk-based audit planning",
                "Control effectiveness testing",
                "Findings and recommendations",
                "Board and audit committee reporting"
            ],
            "crypto_examples": [
                "Wallet security audits",
                "Smart contract reviews",
                "Custody control assessments",
                "Regulatory compliance audits"
            ]
        }
    }

    # Page Header
    st.markdown('<h1 class="main-header">Control Testing</h1>', unsafe_allow_html=True)
    st.markdown(
        '<p class="sub-header">Systematic testing of internal controls with effectiveness ratings and deficiency documentation</p>',
        unsafe_allow_html=True
    )

    # Initialize session state for tested controls if needed
    if 'tested_controls' not in st.session_state:
        st.session_state.tested_controls = []

    # Load demo data if demo mode is enabled
    if st.session_state.demo_mode and len(st.session_state.tested_controls) == 0:
        st.session_state.tested_controls = [
            {
                'control_id': 'WM-001',
                'control_name': 'Multi-Signature Wallet Configuration',
                'category': 'wallet_management',
                'test_date': datetime.date.today() - datetime.timedelta(days=5),
                'tester': 'Demo Auditor',
                'rating': 'Effective',
                'effectiveness_score': 0.95,
                'observations': 'Multi-signature configuration verified on all production wallets. 2-of-3 setup confirmed for hot wallets and 3-of-5 for cold storage.',
                'evidence': 'Blockchain explorer screenshots, wallet configuration documentation, signatory matrix reviewed.',
                'deficiency': None,
                'test_results': [
                    {'test': 'Review wallet configuration documentation', 'passed': True},
                    {'test': 'Verify multi-sig setup on blockchain', 'passed': True},
                    {'test': 'Test transaction approval workflow', 'passed': True},
                    {'test': 'Review signatory access lists', 'passed': True}
                ]
            },
            {
                'control_id': 'AM-002',
                'control_name': 'Multi-Factor Authentication',
                'category': 'access_management',
                'test_date': datetime.date.today() - datetime.timedelta(days=3),
                'tester': 'Demo Auditor',
                'rating': 'Satisfactory',
                'effectiveness_score': 0.75,
                'observations': 'MFA is enforced for most systems. Minor gap identified in legacy admin portal.',
                'evidence': 'MFA configuration screenshots, system access logs, enrollment reports.',
                'deficiency': 'Legacy admin portal does not enforce MFA for 3 administrative accounts.',
                'test_results': [
                    {'test': 'Review MFA policy', 'passed': True},
                    {'test': 'Test MFA enforcement', 'passed': False},
                    {'test': 'Verify MFA coverage', 'passed': True},
                    {'test': 'Test MFA bypass controls', 'passed': True}
                ]
            },
            {
                'control_id': 'TA-003',
                'control_name': 'Transaction Velocity Limits',
                'category': 'transaction_approval',
                'test_date': datetime.date.today() - datetime.timedelta(days=1),
                'tester': 'Demo Auditor',
                'rating': 'Needs Improvement',
                'effectiveness_score': 0.60,
                'observations': 'Velocity limits are configured but thresholds may be too high for current risk appetite.',
                'evidence': 'System configuration exports, velocity limit policy, alert logs.',
                'deficiency': 'Velocity limits set at $500K/day which exceeds risk appetite of $250K/day. Two limit breaches in past month were not properly escalated.',
                'test_results': [
                    {'test': 'Review velocity limit configuration', 'passed': True},
                    {'test': 'Test limit enforcement', 'passed': True},
                    {'test': 'Review limit breach alerts', 'passed': False},
                    {'test': 'Verify exception handling process', 'passed': False}
                ]
            }
        ]

    # Summary metrics at the top
    tested_count = len(st.session_state.tested_controls)
    total_controls = sum(len(controls) for controls in CRYPTO_CONTROLS_LIBRARY.values())

    if tested_count > 0:
        summary = create_control_status_summary([
            {'name': tc['control_name'], 'effectiveness': tc['effectiveness_score']}
            for tc in st.session_state.tested_controls
        ])

        col1, col2, col3, col4, col5 = st.columns(5)
        with col1:
            st.markdown(f"""
            <div class="metric-card">
                <div class="metric-value">{tested_count}</div>
                <div class="metric-label">Controls Tested</div>
            </div>
            """, unsafe_allow_html=True)
        with col2:
            st.markdown(f"""
            <div class="metric-card">
                <div class="metric-value">{total_controls - tested_count}</div>
                <div class="metric-label">Remaining</div>
            </div>
            """, unsafe_allow_html=True)
        with col3:
            effective_count = summary['status_counts']['Effective'] + summary['status_counts']['Satisfactory']
            st.markdown(f"""
            <div class="metric-card">
                <div class="metric-value" style="color: #28a745;">{effective_count}</div>
                <div class="metric-label">Effective/Satisfactory</div>
            </div>
            """, unsafe_allow_html=True)
        with col4:
            needs_work = summary['status_counts']['Needs Improvement'] + summary['status_counts']['Ineffective']
            st.markdown(f"""
            <div class="metric-card">
                <div class="metric-value" style="color: #dc3545;">{needs_work}</div>
                <div class="metric-label">Needs Attention</div>
            </div>
            """, unsafe_allow_html=True)
        with col5:
            avg_eff = summary['average_effectiveness'] * 100
            st.markdown(f"""
            <div class="metric-card">
                <div class="metric-value">{avg_eff:.1f}%</div>
                <div class="metric-label">Avg Effectiveness</div>
            </div>
            """, unsafe_allow_html=True)

    st.divider()

    # Create tabs for different sections
    tab1, tab2, tab3, tab4 = st.tabs([
        "Control Library",
        "Test a Control",
        "Test Results",
        "Three Lines of Defense"
    ])

    # ==========================================================================
    # TAB 1: Control Library Browser
    # ==========================================================================
    with tab1:
        st.markdown('<h2 class="section-header">Crypto Controls Library</h2>', unsafe_allow_html=True)

        st.markdown("""
        <div class="info-box">
            <strong>Control Library Overview</strong><br>
            Browse controls organized by COSO component and category. Each control includes
            test procedures, evidence requirements, and risk mitigation details.
        </div>
        """, unsafe_allow_html=True)

        # Filter options
        col1, col2 = st.columns(2)
        with col1:
            selected_coso = st.selectbox(
                "Filter by COSO Component",
                options=["All Components"] + [c.value.replace('_', ' ').title() for c in COSOComponent],
                key="library_coso_filter"
            )
        with col2:
            selected_category = st.selectbox(
                "Filter by Control Category",
                options=["All Categories"] + [c.value.replace('_', ' ').title() for c in ControlCategory],
                key="library_category_filter"
            )

        # Display controls by category
        for category, controls in CRYPTO_CONTROLS_LIBRARY.items():
            # Apply category filter
            if selected_category != "All Categories":
                if category.value.replace('_', ' ').title() != selected_category:
                    continue

            # Filter controls by COSO component
            filtered_controls = controls
            if selected_coso != "All Components":
                filtered_controls = [
                    c for c in controls
                    if c.coso_component.value.replace('_', ' ').title() == selected_coso
                ]

            if not filtered_controls:
                continue

            category_display = category.value.replace('_', ' ').title()
            with st.expander(f"**{category_display}** ({len(filtered_controls)} controls)", expanded=False):
                for control in filtered_controls:
                    # Check if this control has been tested
                    tested = any(tc['control_id'] == control.control_id for tc in st.session_state.tested_controls)
                    tested_badge = '<span class="badge-effective">Tested</span>' if tested else '<span class="badge-medium">Not Tested</span>'

                    st.markdown(f"""
                    <div class="audit-card">
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <h4 style="margin: 0;">{control.control_id}: {control.name}</h4>
                            {tested_badge}
                        </div>
                        <p style="color: #5A6C7D; margin-top: 0.5rem;">{control.description}</p>
                        <div style="display: flex; gap: 1rem; flex-wrap: wrap; margin-top: 0.5rem;">
                            <span><strong>Type:</strong> {control.control_type}</span>
                            <span><strong>Frequency:</strong> {control.frequency}</span>
                            <span><strong>Owner:</strong> {control.owner}</span>
                            <span><strong>COSO:</strong> {control.coso_component.value.replace('_', ' ').title()}</span>
                        </div>
                    </div>
                    """, unsafe_allow_html=True)

                    # Show details with checkbox toggle
                    if st.checkbox(f"View Details - {control.control_id}", key=f"details_{control.control_id}"):
                        col1, col2 = st.columns(2)
                        with col1:
                            st.markdown("**Test Procedures:**")
                            for i, proc in enumerate(control.test_procedures, 1):
                                st.markdown(f"{i}. {proc}")

                            st.markdown("**Evidence Required:**")
                            for evidence in control.evidence_required:
                                st.markdown(f"- {evidence}")

                        with col2:
                            st.markdown("**Risks Addressed:**")
                            for risk in control.risk_addressed:
                                st.markdown(f"- {risk}")
                        st.divider()

    # ==========================================================================
    # TAB 2: Test a Control
    # ==========================================================================
    with tab2:
        st.markdown('<h2 class="section-header">Control Testing Interface</h2>', unsafe_allow_html=True)

        st.markdown("""
        <div class="info-box">
            <strong>Control Testing Workflow</strong><br>
            1. Select a control to test<br>
            2. Document your walkthrough observations<br>
            3. Execute test procedures and record results<br>
            4. Upload or describe evidence collected<br>
            5. Rate control effectiveness<br>
            6. Document any deficiencies found
        </div>
        """, unsafe_allow_html=True)

        # Build flat list of all controls for selection
        all_controls = []
        for category, controls in CRYPTO_CONTROLS_LIBRARY.items():
            for control in controls:
                all_controls.append({
                    'id': control.control_id,
                    'name': control.name,
                    'category': category.value,
                    'control_obj': control
                })

        # Control Selection
        st.markdown("### Step 1: Select Control to Test")

        col1, col2 = st.columns([2, 1])
        with col1:
            control_options = [f"{c['id']}: {c['name']}" for c in all_controls]
            selected_control_str = st.selectbox(
                "Select Control",
                options=control_options,
                key="test_control_select"
            )

        with col2:
            tester_name = st.text_input(
                "Tester Name",
                value=st.session_state.audit_engagement.get('auditor', ''),
                key="tester_name_input"
            )

        # Get the selected control object
        selected_idx = control_options.index(selected_control_str)
        selected_control = all_controls[selected_idx]['control_obj']

        # Display control details
        st.markdown("### Control Details")
        st.markdown(f"""
        <div class="audit-card">
            <h4>{selected_control.control_id}: {selected_control.name}</h4>
            <p>{selected_control.description}</p>
            <div style="display: flex; gap: 2rem; flex-wrap: wrap; margin-top: 1rem;">
                <div><strong>Category:</strong> {selected_control.category.value.replace('_', ' ').title()}</div>
                <div><strong>Type:</strong> {selected_control.control_type}</div>
                <div><strong>Frequency:</strong> {selected_control.frequency}</div>
                <div><strong>Owner:</strong> {selected_control.owner}</div>
                <div><strong>COSO Component:</strong> {selected_control.coso_component.value.replace('_', ' ').title()}</div>
            </div>
        </div>
        """, unsafe_allow_html=True)

        # Test Procedure Documentation
        st.markdown("### Step 2: Test Procedure Documentation")

        st.markdown("**Defined Test Procedures:**")
        test_results = []
        for i, procedure in enumerate(selected_control.test_procedures):
            col1, col2 = st.columns([3, 1])
            with col1:
                st.markdown(f"**{i+1}.** {procedure}")
            with col2:
                result = st.selectbox(
                    "Result",
                    options=["Not Tested", "Pass", "Fail"],
                    key=f"proc_result_{selected_control.control_id}_{i}",
                    label_visibility="collapsed"
                )
                if result != "Not Tested":
                    test_results.append({
                        'test': procedure,
                        'passed': result == "Pass"
                    })

        # Control Walkthrough Documentation
        st.markdown("### Step 3: Control Walkthrough Documentation")

        walkthrough_observations = st.text_area(
            "Walkthrough Observations",
            placeholder="Document your observations from the control walkthrough. Include:\n- How the control operates in practice\n- Personnel interviewed\n- Processes observed\n- Any deviations from documented procedures",
            height=150,
            key="walkthrough_obs"
        )

        # Evidence Upload Simulation
        st.markdown("### Step 4: Evidence Collection")

        col1, col2 = st.columns(2)
        with col1:
            st.markdown("**Required Evidence:**")
            for evidence in selected_control.evidence_required:
                st.markdown(f"- {evidence}")

        with col2:
            uploaded_file = st.file_uploader(
                "Upload Evidence File (Optional)",
                type=['pdf', 'png', 'jpg', 'xlsx', 'docx', 'csv'],
                key="evidence_upload"
            )

            evidence_description = st.text_area(
                "Evidence Description",
                placeholder="Describe the evidence collected, including file names, dates, and sources...",
                height=100,
                key="evidence_desc"
            )

        # Control Effectiveness Rating
        st.markdown("### Step 5: Control Effectiveness Rating")

        col1, col2 = st.columns(2)
        with col1:
            effectiveness_rating = st.selectbox(
                "Overall Control Rating",
                options=["Effective", "Satisfactory", "Needs Improvement", "Ineffective"],
                key="effectiveness_rating",
                help="Effective (85%+), Satisfactory (70-84%), Needs Improvement (50-69%), Ineffective (<50%)"
            )

            # Map rating to score
            rating_scores = {
                "Effective": 0.90,
                "Satisfactory": 0.75,
                "Needs Improvement": 0.60,
                "Ineffective": 0.35
            }
            effectiveness_score = rating_scores[effectiveness_rating]

            # If we have test results, calculate actual score
            if test_results:
                effectiveness_score = rate_control_effectiveness(test_results)
                calculated_status = get_control_status(effectiveness_score)
                st.info(f"Calculated effectiveness based on test results: {effectiveness_score*100:.1f}% ({calculated_status})")

        with col2:
            # Visual effectiveness indicator
            if effectiveness_rating == "Effective":
                badge_class = "badge-effective"
            elif effectiveness_rating == "Satisfactory":
                badge_class = "badge-satisfactory"
            elif effectiveness_rating == "Needs Improvement":
                badge_class = "badge-needs-improvement"
            else:
                badge_class = "badge-ineffective"

            st.markdown(f"""
            <div style="text-align: center; padding: 1rem;">
                <span class="{badge_class}" style="font-size: 1.2rem; padding: 0.5rem 1.5rem;">
                    {effectiveness_rating}
                </span>
                <p style="margin-top: 1rem; color: #6c757d;">
                    Effectiveness Score: {effectiveness_score*100:.1f}%
                </p>
            </div>
            """, unsafe_allow_html=True)

        # Control Deficiency Documentation
        st.markdown("### Step 6: Deficiency Documentation")

        has_deficiency = effectiveness_rating in ["Needs Improvement", "Ineffective"]

        if has_deficiency:
            st.markdown("""
            <div class="warning-box">
                <strong>Deficiency Identified</strong><br>
                The control rating indicates potential deficiencies. Please document the issues found.
            </div>
            """, unsafe_allow_html=True)

        deficiency_description = st.text_area(
            "Deficiency Description (if applicable)",
            placeholder="Document any control deficiencies identified, including:\n- Nature of the deficiency\n- Root cause (if known)\n- Potential impact\n- Recommended remediation",
            height=120,
            key="deficiency_desc",
            disabled=not has_deficiency and effectiveness_rating != "Satisfactory"
        )

        # Submit Test Results
        st.divider()

        col1, col2, col3 = st.columns([1, 1, 2])
        with col1:
            test_date = st.date_input("Test Date", value=datetime.date.today(), key="test_date")

        with col3:
            if st.button("Submit Control Test", type="primary", use_container_width=True):
                # Validate inputs
                if not tester_name:
                    st.error("Please enter the tester name.")
                elif not walkthrough_observations:
                    st.error("Please document your walkthrough observations.")
                elif not evidence_description and not uploaded_file:
                    st.error("Please provide evidence description or upload evidence file.")
                elif not test_results:
                    st.error("Please complete at least one test procedure.")
                else:
                    # Create test record
                    test_record = {
                        'control_id': selected_control.control_id,
                        'control_name': selected_control.name,
                        'category': selected_control.category.value,
                        'test_date': test_date,
                        'tester': tester_name,
                        'rating': effectiveness_rating,
                        'effectiveness_score': effectiveness_score,
                        'observations': walkthrough_observations,
                        'evidence': evidence_description or f"File uploaded: {uploaded_file.name if uploaded_file else 'N/A'}",
                        'deficiency': deficiency_description if deficiency_description else None,
                        'test_results': test_results
                    }

                    # Check if this control was already tested, update or add
                    existing_idx = None
                    for idx, tc in enumerate(st.session_state.tested_controls):
                        if tc['control_id'] == selected_control.control_id:
                            existing_idx = idx
                            break

                    if existing_idx is not None:
                        st.session_state.tested_controls[existing_idx] = test_record
                        st.success(f"Control test for {selected_control.control_id} has been updated!")
                    else:
                        st.session_state.tested_controls.append(test_record)
                        st.success(f"Control test for {selected_control.control_id} has been recorded!")

                    st.rerun()

    # ==========================================================================
    # TAB 3: Test Results
    # ==========================================================================
    with tab3:
        st.markdown('<h2 class="section-header">Control Test Results</h2>', unsafe_allow_html=True)

        if not st.session_state.tested_controls:
            st.markdown("""
            <div class="loading-placeholder">
                <h3>No Control Tests Recorded</h3>
                <p>Navigate to the "Test a Control" tab to begin testing controls.</p>
                <p style="font-size: 0.9rem; color: #888;">
                    Enable Demo Mode in the sidebar to load sample test data.
                </p>
            </div>
            """, unsafe_allow_html=True)
        else:
            # Results summary
            summary = create_control_status_summary([
                {'name': tc['control_name'], 'effectiveness': tc['effectiveness_score']}
                for tc in st.session_state.tested_controls
            ])

            # Status distribution chart
            col1, col2 = st.columns([1, 2])

            with col1:
                st.markdown("**Status Distribution**")
                for status, count in summary['status_counts'].items():
                    if count > 0:
                        if status == "Effective":
                            color = "#28a745"
                        elif status == "Satisfactory":
                            color = "#17a2b8"
                        elif status == "Needs Improvement":
                            color = "#ffc107"
                        else:
                            color = "#dc3545"

                        percentage = (count / summary['total_controls']) * 100
                        st.markdown(f"""
                        <div style="margin-bottom: 0.5rem;">
                            <div style="display: flex; justify-content: space-between;">
                                <span>{status}</span>
                                <span>{count} ({percentage:.0f}%)</span>
                            </div>
                            <div style="background-color: #e9ecef; border-radius: 4px; height: 8px;">
                                <div style="background-color: {color}; width: {percentage}%; height: 100%; border-radius: 4px;"></div>
                            </div>
                        </div>
                        """, unsafe_allow_html=True)

            with col2:
                st.markdown("**Tested Controls by Category**")
                category_counts = {}
                for tc in st.session_state.tested_controls:
                    cat = tc['category'].replace('_', ' ').title()
                    category_counts[cat] = category_counts.get(cat, 0) + 1

                for cat, count in category_counts.items():
                    st.markdown(f"- **{cat}**: {count} controls tested")

            st.divider()

            # Detailed results table
            st.markdown("### Detailed Test Results")

            # Filter options
            filter_rating = st.selectbox(
                "Filter by Rating",
                options=["All Ratings", "Effective", "Satisfactory", "Needs Improvement", "Ineffective"],
                key="results_filter"
            )

            for tc in st.session_state.tested_controls:
                # Apply filter
                if filter_rating != "All Ratings" and tc['rating'] != filter_rating:
                    continue

                # Determine badge class
                if tc['rating'] == "Effective":
                    badge_html = '<span class="badge-effective">Effective</span>'
                elif tc['rating'] == "Satisfactory":
                    badge_html = '<span class="badge-satisfactory">Satisfactory</span>'
                elif tc['rating'] == "Needs Improvement":
                    badge_html = '<span class="badge-needs-improvement">Needs Improvement</span>'
                else:
                    badge_html = '<span class="badge-ineffective">Ineffective</span>'

                st.markdown(f"""
                <div class="audit-card">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <h4 style="margin: 0;">{tc['control_id']}: {tc['control_name']}</h4>
                        {badge_html}
                    </div>
                    <div style="display: flex; gap: 2rem; margin-top: 0.5rem; color: #5A6C7D;">
                        <span><strong>Tested:</strong> {tc['test_date']}</span>
                        <span><strong>Tester:</strong> {tc['tester']}</span>
                        <span><strong>Score:</strong> {tc['effectiveness_score']*100:.1f}%</span>
                    </div>
                </div>
                """, unsafe_allow_html=True)

                with st.expander(f"View Details - {tc['control_id']}"):
                    col1, col2 = st.columns(2)

                    with col1:
                        st.markdown("**Walkthrough Observations:**")
                        st.write(tc['observations'])

                        st.markdown("**Evidence Collected:**")
                        st.write(tc['evidence'])

                    with col2:
                        st.markdown("**Test Procedure Results:**")
                        for tr in tc['test_results']:
                            icon = "+" if tr['passed'] else "x"
                            color = "green" if tr['passed'] else "red"
                            st.markdown(f":{color}[{icon}] {tr['test']}")

                        if tc['deficiency']:
                            st.markdown("**Deficiency Documented:**")
                            st.markdown(f"""
                            <div class="warning-box">
                                {tc['deficiency']}
                            </div>
                            """, unsafe_allow_html=True)

            # Export option
            st.divider()
            if st.button("Export Test Results to CSV", key="export_results"):
                # Create DataFrame for export
                export_data = []
                for tc in st.session_state.tested_controls:
                    export_data.append({
                        'Control ID': tc['control_id'],
                        'Control Name': tc['control_name'],
                        'Category': tc['category'],
                        'Test Date': tc['test_date'],
                        'Tester': tc['tester'],
                        'Rating': tc['rating'],
                        'Effectiveness Score': tc['effectiveness_score'],
                        'Observations': tc['observations'],
                        'Evidence': tc['evidence'],
                        'Deficiency': tc['deficiency'] or 'None'
                    })

                df = pd.DataFrame(export_data)
                csv = df.to_csv(index=False)
                st.download_button(
                    label="Download CSV",
                    data=csv,
                    file_name=f"control_test_results_{datetime.date.today()}.csv",
                    mime="text/csv"
                )

    # ==========================================================================
    # TAB 4: Three Lines of Defense
    # ==========================================================================
    with tab4:
        st.markdown('<h2 class="section-header">Three Lines of Defense Model</h2>', unsafe_allow_html=True)

        st.markdown("""
        <div class="info-box">
            <strong>About the Three Lines Model</strong><br>
            The Three Lines of Defense model provides a structured approach to risk management and
            internal control, ensuring appropriate oversight and accountability across the organization.
            This framework is particularly important in crypto operations where custody, compliance,
            and security risks require multiple layers of protection.
        </div>
        """, unsafe_allow_html=True)

        # Visual representation
        st.markdown("### Visual Framework")

        col1, col2, col3 = st.columns(3)

        for idx, (key, line) in enumerate(THREE_LINES_OF_DEFENSE.items()):
            with [col1, col2, col3][idx]:
                st.markdown(f"""
                <div style="
                    background: linear-gradient(135deg, {line['color']}22 0%, {line['color']}11 100%);
                    border-left: 4px solid {line['color']};
                    border-radius: 8px;
                    padding: 1.5rem;
                    height: 100%;
                    min-height: 400px;
                ">
                    <h3 style="color: {line['color']}; margin-top: 0;">{line['name']}</h3>
                    <h4 style="color: #1E3A5F; margin-bottom: 1rem;">{line['title']}</h4>
                    <p style="color: #5A6C7D; font-size: 0.9rem;">{line['description']}</p>

                    <h5 style="margin-top: 1rem; color: #1E3A5F;">Key Responsibilities:</h5>
                    <ul style="color: #5A6C7D; font-size: 0.85rem; padding-left: 1.2rem;">
                        {''.join(f'<li>{r}</li>' for r in line['responsibilities'])}
                    </ul>
                </div>
                """, unsafe_allow_html=True)

        st.divider()

        # Detailed breakdown with crypto examples
        st.markdown("### Crypto-Specific Applications")

        for key, line in THREE_LINES_OF_DEFENSE.items():
            with st.expander(f"{line['name']}: {line['title']}", expanded=True):
                col1, col2 = st.columns([1, 1])

                with col1:
                    st.markdown("**Core Responsibilities:**")
                    for resp in line['responsibilities']:
                        st.markdown(f"- {resp}")

                with col2:
                    st.markdown("**Crypto/Blockchain Examples:**")
                    for example in line['crypto_examples']:
                        st.markdown(f"- {example}")

        # Control mapping to Three Lines
        st.divider()
        st.markdown("### Control Mapping to Three Lines")

        st.markdown("""
        The table below shows how the tested controls map to each line of defense based on their
        characteristics and ownership.
        """)

        if st.session_state.tested_controls:
            # Create mapping based on control characteristics
            mapping_data = []
            for tc in st.session_state.tested_controls:
                # Determine line based on control category and type
                control_id = tc['control_id']

                # Simple heuristic mapping based on control ID prefix and category
                if tc['category'] in ['wallet_management', 'transaction_approval']:
                    primary_line = "First Line"
                    secondary_line = "Second Line"
                elif tc['category'] in ['access_management', 'segregation_of_duties']:
                    primary_line = "Second Line"
                    secondary_line = "First Line"
                else:  # key_custody, change_management
                    primary_line = "First Line"
                    secondary_line = "Third Line"

                mapping_data.append({
                    'Control ID': tc['control_id'],
                    'Control Name': tc['control_name'],
                    'Primary Line': primary_line,
                    'Secondary Line': secondary_line,
                    'Rating': tc['rating']
                })

            df_mapping = pd.DataFrame(mapping_data)
            st.dataframe(df_mapping, use_container_width=True, hide_index=True)
        else:
            st.info("Test some controls to see the three lines mapping.")

        # Governance structure
        st.divider()
        st.markdown("### Governance Structure")

        st.markdown("""
        <div class="audit-card">
            <h4>Board / Audit Committee</h4>
            <p>Ultimate oversight responsibility for the organization's risk management and internal control systems.</p>
            <div style="display: flex; justify-content: space-around; margin-top: 1rem; text-align: center;">
                <div style="flex: 1; padding: 1rem; border-right: 1px solid #e9ecef;">
                    <strong style="color: #28a745;">First Line</strong><br>
                    <span style="color: #5A6C7D; font-size: 0.9rem;">Reports to Senior Management</span>
                </div>
                <div style="flex: 1; padding: 1rem; border-right: 1px solid #e9ecef;">
                    <strong style="color: #ffc107;">Second Line</strong><br>
                    <span style="color: #5A6C7D; font-size: 0.9rem;">Reports to Senior Management & Board</span>
                </div>
                <div style="flex: 1; padding: 1rem;">
                    <strong style="color: #dc3545;">Third Line</strong><br>
                    <span style="color: #5A6C7D; font-size: 0.9rem;">Reports to Audit Committee</span>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)


def render_data_analytics():
    """Render the Data Analytics section with full functionality."""

    st.markdown('<h1 class="main-header">Data Analytics</h1>', unsafe_allow_html=True)
    st.markdown(
        '<p class="sub-header">Statistical sampling, anomaly detection, and pattern analysis tools for transaction auditing</p>',
        unsafe_allow_html=True
    )

    # Initialize analytics results in session state if not present
    if 'analytics_results' not in st.session_state:
        st.session_state.analytics_results = {
            'samples': [],
            'anomalies': [],
            'statistics': {},
            'benford_analysis': None,
            'transaction_data': None
        }

    if 'transaction_data' not in st.session_state:
        st.session_state.transaction_data = None

    # -------------------------------------------------------------------------
    # SECTION 1: Transaction Data Generation
    # -------------------------------------------------------------------------
    st.markdown('<h2 class="section-header">1. Transaction Data Generation</h2>', unsafe_allow_html=True)

    col1, col2 = st.columns([2, 1])

    with col1:
        st.markdown("""
        <div class="info-box">
            <strong>Generate Sample Data:</strong> Create synthetic transaction data with built-in anomalies
            for demonstration purposes. The data includes normal transactions as well as anomalies like
            large amounts, off-hours activity, duplicates, and round numbers.
        </div>
        """, unsafe_allow_html=True)

    with col2:
        num_transactions = st.number_input(
            "Number of Transactions",
            min_value=50,
            max_value=10000,
            value=500,
            step=50,
            help="Number of sample transactions to generate"
        )

    col_btn1, col_btn2 = st.columns(2)

    with col_btn1:
        if st.button("Generate Sample Data", type="primary", use_container_width=True):
            st.session_state.transaction_data = generate_sample_transactions(num_transactions)
            st.success(f"Generated {num_transactions} sample transactions with embedded anomalies!")
            st.rerun()

    with col_btn2:
        if st.session_state.demo_mode and st.session_state.transaction_data is None:
            st.session_state.transaction_data = generate_sample_transactions(500)
            st.info("Demo mode: Loaded 500 sample transactions automatically.")
            st.rerun()

        if st.button("Clear Data", type="secondary", use_container_width=True):
            st.session_state.transaction_data = None
            st.session_state.analytics_results = {
                'samples': [],
                'anomalies': [],
                'statistics': {},
                'benford_analysis': None,
                'transaction_data': None
            }
            st.rerun()

    # Display current data status
    if st.session_state.transaction_data is not None:
        df = st.session_state.transaction_data

        # Key metrics
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total Transactions", f"{len(df):,}")
        with col2:
            st.metric("Total Value", f"${df['amount'].sum():,.2f}")
        with col3:
            st.metric("Avg Transaction", f"${df['amount'].mean():,.2f}")
        with col4:
            st.metric("Date Range", f"{(df['timestamp'].max() - df['timestamp'].min()).days} days")

        # Show sample of data
        with st.expander("Preview Transaction Data", expanded=False):
            st.dataframe(df.head(20), use_container_width=True)

        # -------------------------------------------------------------------------
        # SECTION 2: Transaction Pattern Analysis
        # -------------------------------------------------------------------------
        st.markdown('<h2 class="section-header">2. Transaction Pattern Analysis</h2>', unsafe_allow_html=True)

        tab1, tab2, tab3 = st.tabs(["Volume Over Time", "Amount Distribution", "Category Breakdown"])

        with tab1:
            # Daily transaction volume
            df_daily = df.copy()
            df_daily['date'] = df_daily['timestamp'].dt.date
            daily_volume = df_daily.groupby('date').agg({
                'amount': ['sum', 'count', 'mean']
            }).reset_index()
            daily_volume.columns = ['date', 'total_amount', 'count', 'avg_amount']
            daily_volume['date'] = pd.to_datetime(daily_volume['date'])

            st.markdown("#### Daily Transaction Volume")
            chart_data = daily_volume.set_index('date')[['count']]
            st.line_chart(chart_data, use_container_width=True)

            st.markdown("#### Daily Transaction Value")
            value_chart_data = daily_volume.set_index('date')[['total_amount']]
            st.area_chart(value_chart_data, use_container_width=True)

        with tab2:
            # Amount distribution
            st.markdown("#### Transaction Amount Distribution")

            # Create amount bins
            df_amounts = df.copy()
            bins = [0, 100, 500, 1000, 5000, 10000, 50000, float('inf')]
            labels = ['$0-100', '$100-500', '$500-1K', '$1K-5K', '$5K-10K', '$10K-50K', '$50K+']
            df_amounts['amount_range'] = pd.cut(df_amounts['amount'], bins=bins, labels=labels)
            amount_dist = df_amounts['amount_range'].value_counts().sort_index()

            st.bar_chart(amount_dist)

            # Statistics summary
            col1, col2 = st.columns(2)
            with col1:
                stats = calculate_statistics(df['amount'])
                st.markdown("#### Amount Statistics")
                st.markdown(f"""
                | Metric | Value |
                |--------|-------|
                | Mean | ${stats['mean']:,.2f} |
                | Median | ${stats['median']:,.2f} |
                | Std Dev | ${stats['std']:,.2f} |
                | Min | ${stats['min']:,.2f} |
                | Max | ${stats['max']:,.2f} |
                """)

            with col2:
                st.markdown("#### Distribution Shape")
                st.markdown(f"""
                | Metric | Value |
                |--------|-------|
                | Skewness | {stats['skewness']:.3f} |
                | Kurtosis | {stats['kurtosis']:.3f} |
                | Variance | ${stats['variance']:,.2f} |
                | Total Sum | ${stats['sum']:,.2f} |
                """)

        with tab3:
            # Category and type breakdown
            col1, col2 = st.columns(2)

            with col1:
                st.markdown("#### By Transaction Type")
                type_dist = df['tx_type'].value_counts()
                st.bar_chart(type_dist)

            with col2:
                st.markdown("#### By Category")
                cat_dist = df['category'].value_counts()
                st.bar_chart(cat_dist)

            # Hourly distribution
            st.markdown("#### Hourly Transaction Distribution")
            df_hourly = df.copy()
            df_hourly['hour'] = df_hourly['timestamp'].dt.hour
            hourly_dist = df_hourly['hour'].value_counts().sort_index()
            st.bar_chart(hourly_dist)

        # -------------------------------------------------------------------------
        # SECTION 3: Statistical Sampling Interface
        # -------------------------------------------------------------------------
        st.markdown('<h2 class="section-header">3. Statistical Sampling</h2>', unsafe_allow_html=True)

        col1, col2, col3 = st.columns(3)

        with col1:
            sampling_method = st.selectbox(
                "Sampling Method",
                options=["Random", "Stratified", "Monetary Unit (MUS)"],
                help="Select the statistical sampling method to use"
            )

        with col2:
            population_size = len(df)
            st.metric("Population Size", f"{population_size:,}")

        with col3:
            sample_size = st.slider(
                "Sample Size",
                min_value=5,
                max_value=min(100, population_size),
                value=min(25, population_size),
                help="Number of transactions to sample"
            )

        # Additional options based on method
        strata_column = 'tx_type'
        if sampling_method == "Stratified":
            strata_column = st.selectbox(
                "Stratification Column",
                options=['tx_type', 'category'],
                help="Column to use for stratification"
            )

        if st.button("Select Sample", type="primary", use_container_width=True):
            with st.spinner("Selecting sample..."):
                if sampling_method == "Random":
                    sample_df = random_sampling(df, sample_size)
                elif sampling_method == "Stratified":
                    sample_df = stratified_sampling(df, strata_column, sample_size)
                else:  # MUS
                    sample_df = monetary_unit_sampling(df, 'amount', sample_size)

                st.session_state.analytics_results['samples'] = sample_df
                st.success(f"Selected {len(sample_df)} transactions using {sampling_method} sampling!")

        # -------------------------------------------------------------------------
        # SECTION 4: Sample Selection and Display
        # -------------------------------------------------------------------------
        if isinstance(st.session_state.analytics_results.get('samples'), pd.DataFrame) and \
           len(st.session_state.analytics_results['samples']) > 0:

            st.markdown('<h2 class="section-header">4. Selected Sample</h2>', unsafe_allow_html=True)

            sample_df = st.session_state.analytics_results['samples']

            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("Sample Size", len(sample_df))
            with col2:
                st.metric("Sample Value", f"${sample_df['amount'].sum():,.2f}")
            with col3:
                coverage = (sample_df['amount'].sum() / df['amount'].sum()) * 100
                st.metric("Value Coverage", f"{coverage:.1f}%")
            with col4:
                st.metric("Avg Sample Amount", f"${sample_df['amount'].mean():,.2f}")

            st.dataframe(sample_df, use_container_width=True)

            # Download sample
            csv = sample_df.to_csv(index=False)
            st.download_button(
                label="Download Sample as CSV",
                data=csv,
                file_name="audit_sample.csv",
                mime="text/csv"
            )

        # -------------------------------------------------------------------------
        # SECTION 5: Anomaly Detection
        # -------------------------------------------------------------------------
        st.markdown('<h2 class="section-header">5. Anomaly Detection</h2>', unsafe_allow_html=True)

        col1, col2 = st.columns(2)

        with col1:
            zscore_threshold = st.slider(
                "Z-Score Threshold",
                min_value=1.5,
                max_value=4.0,
                value=3.0,
                step=0.1,
                help="Standard deviations from mean to flag as outlier"
            )

        with col2:
            detection_method = st.multiselect(
                "Detection Methods",
                options=["Z-Score", "IQR", "Round Numbers"],
                default=["Z-Score", "IQR"],
                help="Select anomaly detection methods to run"
            )

        if st.button("Run Anomaly Detection", type="primary", use_container_width=True):
            with st.spinner("Detecting anomalies..."):
                anomalies = []

                if "Z-Score" in detection_method:
                    zscore_results = detect_outliers_zscore(df['amount'], threshold=zscore_threshold)
                    for idx in zscore_results['outlier_indices']:
                        anomalies.append({
                            'id': df.iloc[idx]['id'],
                            'amount': df.iloc[idx]['amount'],
                            'method': 'Z-Score',
                            'z_score': zscore_results['z_scores'][idx],
                            'timestamp': df.iloc[idx]['timestamp']
                        })

                if "IQR" in detection_method:
                    iqr_results = detect_outliers_iqr(df['amount'])
                    for idx in iqr_results['outlier_indices']:
                        if not any(a['id'] == df.iloc[idx]['id'] for a in anomalies):
                            anomalies.append({
                                'id': df.iloc[idx]['id'],
                                'amount': df.iloc[idx]['amount'],
                                'method': 'IQR',
                                'bounds': f"[{iqr_results['lower_bound']:.2f}, {iqr_results['upper_bound']:.2f}]",
                                'timestamp': df.iloc[idx]['timestamp']
                            })

                if "Round Numbers" in detection_method:
                    round_results = flag_round_numbers(df['amount'], threshold=1000)
                    for idx in round_results['flagged_indices']:
                        if not any(a['id'] == df.iloc[idx]['id'] for a in anomalies):
                            anomalies.append({
                                'id': df.iloc[idx]['id'],
                                'amount': df.iloc[idx]['amount'],
                                'method': 'Round Number',
                                'note': 'Divisible by 1000',
                                'timestamp': df.iloc[idx]['timestamp']
                            })

                st.session_state.analytics_results['anomalies'] = anomalies
                st.success(f"Detected {len(anomalies)} potential anomalies!")

        # Display anomalies
        if st.session_state.analytics_results.get('anomalies'):
            anomalies = st.session_state.analytics_results['anomalies']

            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Total Anomalies", len(anomalies))
            with col2:
                anomaly_value = sum(a['amount'] for a in anomalies)
                st.metric("Anomaly Value", f"${anomaly_value:,.2f}")
            with col3:
                pct = (len(anomalies) / len(df)) * 100
                st.metric("Anomaly Rate", f"{pct:.2f}%")

            anomaly_df = pd.DataFrame(anomalies)
            st.dataframe(anomaly_df, use_container_width=True)

        # -------------------------------------------------------------------------
        # SECTION 6: Benford's Law Analysis
        # -------------------------------------------------------------------------
        st.markdown('<h2 class="section-header">6. Benford\'s Law Analysis</h2>', unsafe_allow_html=True)

        st.markdown("""
        <div class="info-box">
            <strong>Benford's Law:</strong> In naturally occurring datasets, the first digit follows a predictable
            distribution where 1 appears ~30.1% of the time, 2 appears ~17.6%, etc. Deviations may indicate
            data manipulation or fraud.
        </div>
        """, unsafe_allow_html=True)

        if st.button("Run Benford's Law Analysis", type="primary", use_container_width=True):
            with st.spinner("Analyzing first digit distribution..."):
                benford_results = benford_law_analysis(df['amount'])
                st.session_state.analytics_results['benford_analysis'] = benford_results

        if st.session_state.analytics_results.get('benford_analysis'):
            results = st.session_state.analytics_results['benford_analysis']

            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Chi-Square Statistic", f"{results['chi_square']:.2f}")
            with col2:
                conformity_pct = results['conformity_score'] * 100
                st.metric("Conformity Score", f"{conformity_pct:.1f}%")
            with col3:
                if results['chi_square'] < 15.51:
                    st.metric("Result", "PASS", delta="Conforms to Benford's Law")
                else:
                    st.metric("Result", "REVIEW", delta="Potential anomaly", delta_color="inverse")

            # Create comparison chart
            st.markdown("#### Observed vs Expected Distribution")

            observed = results['observed_distribution']
            expected = results['expected_distribution']

            comparison_df = pd.DataFrame({
                'Digit': list(range(1, 10)),
                'Observed': [observed.get(d, 0) * 100 for d in range(1, 10)],
                'Expected (Benford)': [expected[d] * 100 for d in range(1, 10)]
            })
            comparison_df = comparison_df.set_index('Digit')

            st.bar_chart(comparison_df)

            # Detailed table
            with st.expander("Detailed Benford's Law Results"):
                detail_df = pd.DataFrame({
                    'First Digit': list(range(1, 10)),
                    'Count': [results['digit_counts'].get(d, 0) for d in range(1, 10)],
                    'Observed %': [f"{observed.get(d, 0) * 100:.2f}%" for d in range(1, 10)],
                    'Expected %': [f"{expected[d] * 100:.2f}%" for d in range(1, 10)],
                    'Difference': [f"{(observed.get(d, 0) - expected[d]) * 100:+.2f}%" for d in range(1, 10)]
                })
                st.dataframe(detail_df, use_container_width=True)

        # -------------------------------------------------------------------------
        # SECTION 7: Duplicate Transaction Detection
        # -------------------------------------------------------------------------
        st.markdown('<h2 class="section-header">7. Duplicate Transaction Detection</h2>', unsafe_allow_html=True)

        col1, col2 = st.columns(2)

        with col1:
            dup_columns = st.multiselect(
                "Columns to Check for Duplicates",
                options=['amount', 'from_address', 'to_address', 'tx_type', 'category'],
                default=['amount', 'from_address', 'to_address'],
                help="Select columns to use for duplicate detection"
            )

        with col2:
            time_window = st.selectbox(
                "Time Window",
                options=["Same Day", "Same Hour", "Any Time"],
                help="Time proximity for duplicate consideration"
            )

        if st.button("Find Duplicates", type="primary", use_container_width=True):
            if dup_columns:
                with st.spinner("Searching for duplicates..."):
                    # Add time-based column if needed
                    df_dup = df.copy()
                    check_cols = dup_columns.copy()

                    if time_window == "Same Day":
                        df_dup['_date'] = df_dup['timestamp'].dt.date
                        check_cols.append('_date')
                    elif time_window == "Same Hour":
                        df_dup['_hour'] = df_dup['timestamp'].dt.floor('H')
                        check_cols.append('_hour')

                    duplicates = detect_duplicates(df_dup, check_cols)

                    # Remove helper columns
                    if '_date' in duplicates.columns:
                        duplicates = duplicates.drop(columns=['_date'])
                    if '_hour' in duplicates.columns:
                        duplicates = duplicates.drop(columns=['_hour'])

                    st.session_state.analytics_results['duplicates'] = duplicates

                    if len(duplicates) > 0:
                        st.warning(f"Found {len(duplicates)} potential duplicate transactions!")
                    else:
                        st.success("No duplicate transactions found.")
            else:
                st.error("Please select at least one column to check for duplicates.")

        if 'duplicates' in st.session_state.analytics_results and \
           len(st.session_state.analytics_results['duplicates']) > 0:

            duplicates = st.session_state.analytics_results['duplicates']

            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Duplicate Records", len(duplicates))
            with col2:
                st.metric("Duplicate Value", f"${duplicates['amount'].sum():,.2f}")
            with col3:
                pct = (len(duplicates) / len(df)) * 100
                st.metric("Duplicate Rate", f"{pct:.2f}%")

            st.dataframe(duplicates, use_container_width=True)

        # -------------------------------------------------------------------------
        # SECTION 8: Unusual Timing Analysis
        # -------------------------------------------------------------------------
        st.markdown('<h2 class="section-header">8. Unusual Timing Analysis</h2>', unsafe_allow_html=True)

        col1, col2 = st.columns(2)

        with col1:
            business_start = st.slider("Business Hours Start", 0, 23, 9, help="Start of business hours (24h format)")

        with col2:
            business_end = st.slider("Business Hours End", 0, 23, 17, help="End of business hours (24h format)")

        if st.button("Analyze Timing Patterns", type="primary", use_container_width=True):
            with st.spinner("Analyzing timing patterns..."):
                # Off-hours detection
                off_hours = detect_off_hours_transactions(df, business_hours=(business_start, business_end))

                # Weekend detection
                weekend = detect_weekend_transactions(df)

                st.session_state.analytics_results['off_hours'] = off_hours
                st.session_state.analytics_results['weekend'] = weekend

        if 'off_hours' in st.session_state.analytics_results:
            off_hours = st.session_state.analytics_results['off_hours']
            weekend = st.session_state.analytics_results['weekend']

            col1, col2, col3, col4 = st.columns(4)

            with col1:
                st.metric(
                    "Off-Hours Transactions",
                    off_hours['flagged_count'],
                    delta=f"{off_hours['percentage']:.1f}%"
                )

            with col2:
                off_hours_value = df.iloc[off_hours['flagged_indices']]['amount'].sum() if off_hours['flagged_indices'] else 0
                st.metric("Off-Hours Value", f"${off_hours_value:,.2f}")

            with col3:
                st.metric(
                    "Weekend Transactions",
                    weekend['flagged_count'],
                    delta=f"{weekend['percentage']:.1f}%"
                )

            with col4:
                weekend_value = df.iloc[weekend['flagged_indices']]['amount'].sum() if weekend['flagged_indices'] else 0
                st.metric("Weekend Value", f"${weekend_value:,.2f}")

            # Show flagged transactions
            tab1, tab2 = st.tabs(["Off-Hours Transactions", "Weekend Transactions"])

            with tab1:
                if off_hours['flagged_indices']:
                    off_hours_df = df.iloc[off_hours['flagged_indices']].copy()
                    off_hours_df['hour'] = off_hours_df['timestamp'].dt.hour
                    st.dataframe(off_hours_df[['id', 'timestamp', 'hour', 'amount', 'tx_type', 'from_address', 'to_address']],
                                use_container_width=True)

                    # Hour distribution chart
                    st.markdown("#### Off-Hours Distribution by Hour")
                    hour_dist = off_hours_df['hour'].value_counts().sort_index()
                    st.bar_chart(hour_dist)
                else:
                    st.info("No off-hours transactions detected.")

            with tab2:
                if weekend['flagged_indices']:
                    weekend_df = df.iloc[weekend['flagged_indices']].copy()
                    weekend_df['day_name'] = weekend_df['timestamp'].dt.day_name()
                    st.dataframe(weekend_df[['id', 'timestamp', 'day_name', 'amount', 'tx_type', 'from_address', 'to_address']],
                                use_container_width=True)

                    # Day distribution
                    st.markdown("#### Weekend Distribution")
                    day_dist = weekend_df['day_name'].value_counts()
                    st.bar_chart(day_dist)
                else:
                    st.info("No weekend transactions detected.")

        # -------------------------------------------------------------------------
        # Summary Dashboard
        # -------------------------------------------------------------------------
        st.markdown('<h2 class="section-header">Analytics Summary Dashboard</h2>', unsafe_allow_html=True)

        col1, col2, col3 = st.columns(3)

        with col1:
            st.markdown("""
            <div class="metric-card">
                <div class="metric-label">TOTAL TRANSACTIONS</div>
                <div class="metric-value">{:,}</div>
            </div>
            """.format(len(df)), unsafe_allow_html=True)

        with col2:
            anomaly_count = len(st.session_state.analytics_results.get('anomalies', []))
            st.markdown("""
            <div class="metric-card">
                <div class="metric-label">ANOMALIES DETECTED</div>
                <div class="metric-value">{}</div>
            </div>
            """.format(anomaly_count), unsafe_allow_html=True)

        with col3:
            sample_count = len(st.session_state.analytics_results.get('samples', []))
            st.markdown("""
            <div class="metric-card">
                <div class="metric-label">SAMPLED ITEMS</div>
                <div class="metric-value">{}</div>
            </div>
            """.format(sample_count), unsafe_allow_html=True)

    else:
        # No data loaded yet
        st.markdown("""
        <div class="warning-box">
            <strong>No Transaction Data:</strong> Please generate sample data or enable demo mode to begin analysis.
            Click "Generate Sample Data" above to create synthetic transaction data with embedded anomalies.
        </div>
        """, unsafe_allow_html=True)

        # Show demo mode reminder
        if not st.session_state.demo_mode:
            st.info("Tip: Enable Demo Mode in the sidebar to automatically load sample data.")


def generate_sample_transactions(n: int = 500) -> pd.DataFrame:
    """
    Generate sample transaction data with embedded anomalies for demonstration.

    Args:
        n: Number of transactions to generate

    Returns:
        DataFrame with sample transaction data including some anomalies
    """
    np.random.seed(42)
    random.seed(42)

    # Define address pools
    internal_addresses = [f"0x{''.join(random.choices('0123456789abcdef', k=40))}" for _ in range(20)]
    external_addresses = [f"0x{''.join(random.choices('0123456789abcdef', k=40))}" for _ in range(50)]

    # Transaction types and categories
    tx_types = ['transfer', 'swap', 'deposit', 'withdrawal', 'stake', 'unstake']
    categories = ['trading', 'treasury', 'payroll', 'vendor', 'fee', 'interest', 'other']

    # Generate base timestamps (last 90 days, mostly business hours)
    end_date = datetime.datetime.now()
    start_date = end_date - datetime.timedelta(days=90)

    transactions = []

    for i in range(n):
        # Generate timestamp - mostly business hours, some off-hours
        if random.random() < 0.85:  # 85% during business hours
            hour = random.randint(9, 16)
            day_offset = random.randint(0, 89)
            # Bias towards weekdays
            base_date = start_date + datetime.timedelta(days=day_offset)
            while base_date.weekday() >= 5 and random.random() < 0.8:  # 80% chance to skip weekend
                day_offset = random.randint(0, 89)
                base_date = start_date + datetime.timedelta(days=day_offset)
        else:  # 15% off-hours (anomalies)
            hour = random.choice([0, 1, 2, 3, 4, 5, 22, 23])
            day_offset = random.randint(0, 89)
            base_date = start_date + datetime.timedelta(days=day_offset)

        timestamp = base_date.replace(
            hour=hour,
            minute=random.randint(0, 59),
            second=random.randint(0, 59)
        )

        # Generate amount - mostly normal, some anomalies
        if random.random() < 0.90:  # 90% normal amounts
            amount = abs(np.random.lognormal(mean=6, sigma=1.5))  # Log-normal distribution
        elif random.random() < 0.5:  # 5% large anomalies
            amount = random.uniform(50000, 500000)
        else:  # 5% round number anomalies
            amount = random.choice([1000, 5000, 10000, 25000, 50000, 100000])

        # Select addresses
        from_addr = random.choice(internal_addresses + external_addresses)
        to_addr = random.choice(internal_addresses + external_addresses)
        while to_addr == from_addr:
            to_addr = random.choice(internal_addresses + external_addresses)

        # Select type and category
        tx_type = random.choice(tx_types)
        category = random.choice(categories)

        transactions.append({
            'id': f"TX-{i+1:06d}",
            'timestamp': timestamp,
            'amount': round(amount, 2),
            'from_address': from_addr,
            'to_address': to_addr,
            'tx_type': tx_type,
            'category': category
        })

    # Add some explicit duplicates (about 2% of transactions)
    num_duplicates = max(1, n // 50)
    for _ in range(num_duplicates):
        original_idx = random.randint(0, len(transactions) - 1)
        original = transactions[original_idx].copy()
        # Same amount, addresses but different ID and slightly different time
        original['id'] = f"TX-{len(transactions)+1:06d}"
        original['timestamp'] = original['timestamp'] + datetime.timedelta(minutes=random.randint(1, 30))
        transactions.append(original)

    df = pd.DataFrame(transactions)
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    df = df.sort_values('timestamp').reset_index(drop=True)

    return df


def render_wallet_reconciliation():
    """Render the Wallet Reconciliation module with full functionality."""

    import json

    # =============================================================================
    # MOCK BLOCKCHAIN API FUNCTIONS
    # =============================================================================

    def get_mock_blockchain_balance(wallet_address: str, crypto: str) -> Dict[str, Any]:
        """
        Simulate blockchain API lookup for wallet balance.
        In production, this would call actual blockchain APIs like:
        - BTC: Blockstream, Blockchain.com, or Bitcoin Core RPC
        - ETH: Etherscan, Infura, or Alchemy
        - SOL: Solana RPC or Solscan
        """
        # Generate deterministic but realistic balance based on wallet address hash
        seed_value = hash(wallet_address + crypto) % 10000
        random.seed(seed_value)

        # Base balances vary by crypto
        base_balances = {
            "BTC": random.uniform(0.5, 25.0),
            "ETH": random.uniform(5.0, 500.0),
            "SOL": random.uniform(50.0, 5000.0),
            "USDC": random.uniform(10000.0, 1000000.0),
            "USDT": random.uniform(10000.0, 1000000.0),
        }

        balance = base_balances.get(crypto, random.uniform(10.0, 1000.0))

        # Add small variance to simulate real blockchain state
        variance_factor = random.uniform(-0.02, 0.02)
        blockchain_balance = balance * (1 + variance_factor)

        return {
            "wallet_address": wallet_address,
            "crypto": crypto,
            "balance": round(blockchain_balance, 8),
            "last_updated": datetime.datetime.now().isoformat(),
            "block_height": random.randint(800000, 900000),
            "confirmation_status": "confirmed"
        }

    def get_mock_historical_balances(wallet_address: str, crypto: str, days: int = 30) -> List[Dict]:
        """Generate mock historical balance data for trend analysis."""
        seed_value = hash(wallet_address + crypto) % 10000
        random.seed(seed_value)

        base_balance = {
            "BTC": random.uniform(5.0, 20.0),
            "ETH": random.uniform(50.0, 400.0),
            "SOL": random.uniform(500.0, 4000.0),
            "USDC": random.uniform(50000.0, 500000.0),
            "USDT": random.uniform(50000.0, 500000.0),
        }.get(crypto, random.uniform(100.0, 1000.0))

        historical_data = []
        current_balance = base_balance

        for i in range(days, 0, -1):
            date = datetime.date.today() - datetime.timedelta(days=i)
            # Add realistic daily fluctuation
            daily_change = random.uniform(-0.05, 0.07)
            current_balance = max(0.1, current_balance * (1 + daily_change))

            historical_data.append({
                "date": date.isoformat(),
                "balance": round(current_balance, 8),
                "crypto": crypto
            })

        return historical_data

    def get_crypto_usd_price(crypto: str) -> float:
        """Get mock USD price for cryptocurrency."""
        prices = {
            "BTC": 67500.00,
            "ETH": 3450.00,
            "SOL": 145.00,
            "USDC": 1.00,
            "USDT": 1.00,
        }
        return prices.get(crypto, 100.0)

    def get_demo_wallet_data() -> List[Dict]:
        """Return demo wallet data when demo mode is enabled."""
        return [
            {
                "wallet_id": "WALLET-001",
                "wallet_name": "Hot Wallet - Operations",
                "wallet_address": "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh",
                "crypto": "BTC",
                "recorded_balance": 12.45678901,
                "custodian": "Internal Treasury",
                "last_reconciled": "2024-01-15"
            },
            {
                "wallet_id": "WALLET-002",
                "wallet_name": "Cold Storage - Reserve",
                "wallet_address": "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
                "crypto": "BTC",
                "recorded_balance": 156.78901234,
                "custodian": "Coinbase Custody",
                "last_reconciled": "2024-01-14"
            },
            {
                "wallet_id": "WALLET-003",
                "wallet_name": "Trading Wallet - ETH",
                "wallet_address": "0x742d35Cc6634C0532925a3b844Bc9e7595f8fBe2",
                "crypto": "ETH",
                "recorded_balance": 245.67891234,
                "custodian": "Internal Treasury",
                "last_reconciled": "2024-01-15"
            },
            {
                "wallet_id": "WALLET-004",
                "wallet_name": "DeFi Operations - ETH",
                "wallet_address": "0x8Ba1f109551bD432803012645Ac136ddd64DBA72",
                "crypto": "ETH",
                "recorded_balance": 89.12345678,
                "custodian": "Internal DeFi Ops",
                "last_reconciled": "2024-01-13"
            },
            {
                "wallet_id": "WALLET-005",
                "wallet_name": "Solana Treasury",
                "wallet_address": "DRpbCBMxVnDK7maPMoqAj1wE7K2oZKTu3s3vZcZjp5Nr",
                "crypto": "SOL",
                "recorded_balance": 2456.78901234,
                "custodian": "Internal Treasury",
                "last_reconciled": "2024-01-15"
            },
            {
                "wallet_id": "WALLET-006",
                "wallet_name": "Stablecoin Reserve - USDC",
                "wallet_address": "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD",
                "crypto": "USDC",
                "recorded_balance": 1250000.00,
                "custodian": "Circle Reserve",
                "last_reconciled": "2024-01-15"
            },
        ]

    # =============================================================================
    # INITIALIZE SESSION STATE FOR RECONCILIATION
    # =============================================================================

    if 'wallet_entries' not in st.session_state:
        st.session_state.wallet_entries = []

    if 'reconciliation_results' not in st.session_state:
        st.session_state.reconciliation_results = []

    if 'reconciling_items' not in st.session_state:
        st.session_state.reconciling_items = {}

    if 'historical_data_cache' not in st.session_state:
        st.session_state.historical_data_cache = {}

    # Load demo data if demo mode is enabled and no data exists
    if st.session_state.demo_mode and not st.session_state.wallet_entries:
        st.session_state.wallet_entries = get_demo_wallet_data()

    # =============================================================================
    # PAGE HEADER
    # =============================================================================

    st.markdown('<h1 class="main-header">Wallet Reconciliation</h1>', unsafe_allow_html=True)
    st.markdown(
        '<p class="sub-header">Verify blockchain balances against recorded balances and document reconciling items</p>',
        unsafe_allow_html=True
    )

    # Demo mode indicator
    if st.session_state.demo_mode:
        st.markdown("""
        <div class="info-box">
            <strong>Demo Mode Active</strong> - Sample wallet data has been loaded for demonstration.
            Blockchain balances are simulated using mock data.
        </div>
        """, unsafe_allow_html=True)

    # =============================================================================
    # TABS FOR DIFFERENT FUNCTIONS
    # =============================================================================

    tab1, tab2, tab3, tab4 = st.tabs([
        "Wallet Entry",
        "Reconciliation",
        "Historical Trends",
        "Aggregated View"
    ])

    # =============================================================================
    # TAB 1: WALLET ENTRY
    # =============================================================================

    with tab1:
        st.markdown('<h3 class="section-header">Record Wallet Balances</h3>', unsafe_allow_html=True)

        col1, col2 = st.columns([2, 1])

        with col1:
            with st.form("wallet_entry_form", clear_on_submit=True):
                st.markdown("**Add New Wallet Entry**")

                form_col1, form_col2 = st.columns(2)

                with form_col1:
                    wallet_id = st.text_input(
                        "Wallet ID",
                        placeholder="e.g., WALLET-001",
                        help="Unique identifier for this wallet"
                    )

                    wallet_name = st.text_input(
                        "Wallet Name/Description",
                        placeholder="e.g., Hot Wallet - Operations",
                        help="Descriptive name for the wallet"
                    )

                    crypto = st.selectbox(
                        "Cryptocurrency",
                        options=["BTC", "ETH", "SOL", "USDC", "USDT"],
                        help="Select the cryptocurrency type"
                    )

                    custodian = st.text_input(
                        "Custodian",
                        placeholder="e.g., Coinbase Custody, Internal Treasury",
                        help="Entity holding custody of the wallet"
                    )

                with form_col2:
                    wallet_address = st.text_input(
                        "Wallet Address",
                        placeholder="Enter blockchain wallet address",
                        help="The public blockchain address"
                    )

                    recorded_balance = st.number_input(
                        "Recorded Balance (Client Books)",
                        min_value=0.0,
                        step=0.00000001,
                        format="%.8f",
                        help="Balance per client's accounting records"
                    )

                    last_reconciled = st.date_input(
                        "Last Reconciliation Date",
                        value=datetime.date.today(),
                        help="Date of last reconciliation"
                    )

                submitted = st.form_submit_button("Add Wallet", type="primary", use_container_width=True)

                if submitted:
                    if wallet_id and wallet_address and recorded_balance >= 0:
                        new_entry = {
                            "wallet_id": wallet_id,
                            "wallet_name": wallet_name,
                            "wallet_address": wallet_address,
                            "crypto": crypto,
                            "recorded_balance": recorded_balance,
                            "custodian": custodian,
                            "last_reconciled": last_reconciled.isoformat()
                        }
                        st.session_state.wallet_entries.append(new_entry)
                        st.success(f"Wallet {wallet_id} added successfully!")
                        st.rerun()
                    else:
                        st.error("Please fill in Wallet ID, Address, and Balance.")

        with col2:
            st.markdown("""
            <div class="audit-card">
                <h4>Quick Actions</h4>
            </div>
            """, unsafe_allow_html=True)

            if st.button("Load Demo Wallets", use_container_width=True):
                st.session_state.wallet_entries = get_demo_wallet_data()
                st.success("Demo wallets loaded!")
                st.rerun()

            if st.button("Clear All Wallets", use_container_width=True, type="secondary"):
                st.session_state.wallet_entries = []
                st.session_state.reconciliation_results = []
                st.rerun()

        # Display current wallet entries
        if st.session_state.wallet_entries:
            st.markdown('<h3 class="section-header">Recorded Wallets</h3>', unsafe_allow_html=True)

            wallet_df = pd.DataFrame(st.session_state.wallet_entries)
            wallet_df['recorded_balance'] = wallet_df['recorded_balance'].apply(lambda x: f"{x:,.8f}")

            st.dataframe(
                wallet_df[['wallet_id', 'wallet_name', 'crypto', 'recorded_balance', 'custodian', 'last_reconciled']],
                use_container_width=True,
                hide_index=True
            )

            # Delete wallet option
            wallet_to_delete = st.selectbox(
                "Select wallet to remove",
                options=[""] + [w['wallet_id'] for w in st.session_state.wallet_entries],
                format_func=lambda x: "Select..." if x == "" else x
            )

            if wallet_to_delete and st.button("Remove Selected Wallet", type="secondary"):
                st.session_state.wallet_entries = [
                    w for w in st.session_state.wallet_entries
                    if w['wallet_id'] != wallet_to_delete
                ]
                st.success(f"Wallet {wallet_to_delete} removed.")
                st.rerun()

    # =============================================================================
    # TAB 2: RECONCILIATION
    # =============================================================================

    with tab2:
        st.markdown('<h3 class="section-header">Balance Reconciliation</h3>', unsafe_allow_html=True)

        if not st.session_state.wallet_entries:
            st.warning("No wallets entered. Please add wallets in the 'Wallet Entry' tab first.")
        else:
            # Run reconciliation button
            col1, col2, col3 = st.columns([2, 1, 1])

            with col1:
                if st.button("Run Blockchain Verification", type="primary", use_container_width=True):
                    with st.spinner("Fetching blockchain balances..."):
                        results = []

                        for wallet in st.session_state.wallet_entries:
                            # Get blockchain balance (mock)
                            blockchain_data = get_mock_blockchain_balance(
                                wallet['wallet_address'],
                                wallet['crypto']
                            )

                            recorded = wallet['recorded_balance']
                            blockchain = blockchain_data['balance']

                            # Calculate variance
                            variance_abs = blockchain - recorded
                            variance_pct = (variance_abs / recorded * 100) if recorded != 0 else 0

                            # Determine status
                            if abs(variance_pct) <= 0.01:
                                status = "Match"
                                status_color = "green"
                            elif abs(variance_pct) <= 1.0:
                                status = "Minor Variance"
                                status_color = "yellow"
                            else:
                                status = "Significant Variance"
                                status_color = "red"

                            # Get USD value
                            usd_price = get_crypto_usd_price(wallet['crypto'])
                            usd_value = blockchain * usd_price
                            variance_usd = variance_abs * usd_price

                            results.append({
                                "wallet_id": wallet['wallet_id'],
                                "wallet_name": wallet['wallet_name'],
                                "crypto": wallet['crypto'],
                                "wallet_address": wallet['wallet_address'],
                                "recorded_balance": recorded,
                                "blockchain_balance": blockchain,
                                "variance_abs": variance_abs,
                                "variance_pct": variance_pct,
                                "variance_usd": variance_usd,
                                "usd_value": usd_value,
                                "status": status,
                                "status_color": status_color,
                                "block_height": blockchain_data['block_height'],
                                "verification_time": datetime.datetime.now().isoformat(),
                                "custodian": wallet['custodian']
                            })

                        st.session_state.reconciliation_results = results
                        st.success("Blockchain verification complete!")
                        st.rerun()

            with col2:
                variance_threshold = st.number_input(
                    "Variance Alert Threshold (%)",
                    min_value=0.01,
                    max_value=10.0,
                    value=1.0,
                    step=0.1,
                    help="Flag variances above this percentage"
                )

            with col3:
                st.metric(
                    "Wallets to Reconcile",
                    len(st.session_state.wallet_entries)
                )

            # Display reconciliation results
            if st.session_state.reconciliation_results:
                st.markdown('<h3 class="section-header">Reconciliation Results</h3>', unsafe_allow_html=True)

                # Summary metrics
                results = st.session_state.reconciliation_results
                total_wallets = len(results)
                matches = len([r for r in results if r['status'] == "Match"])
                minor_variances = len([r for r in results if r['status'] == "Minor Variance"])
                significant_variances = len([r for r in results if r['status'] == "Significant Variance"])
                total_variance_usd = sum(abs(r['variance_usd']) for r in results)
                total_usd_value = sum(r['usd_value'] for r in results)

                col1, col2, col3, col4, col5 = st.columns(5)

                with col1:
                    st.markdown(f"""
                    <div class="metric-card">
                        <div class="metric-value">{total_wallets}</div>
                        <div class="metric-label">Total Wallets</div>
                    </div>
                    """, unsafe_allow_html=True)

                with col2:
                    st.markdown(f"""
                    <div class="metric-card">
                        <div class="metric-value" style="color: #28a745;">{matches}</div>
                        <div class="metric-label">Matched</div>
                    </div>
                    """, unsafe_allow_html=True)

                with col3:
                    st.markdown(f"""
                    <div class="metric-card">
                        <div class="metric-value" style="color: #ffc107;">{minor_variances}</div>
                        <div class="metric-label">Minor Variances</div>
                    </div>
                    """, unsafe_allow_html=True)

                with col4:
                    st.markdown(f"""
                    <div class="metric-card">
                        <div class="metric-value" style="color: #dc3545;">{significant_variances}</div>
                        <div class="metric-label">Significant</div>
                    </div>
                    """, unsafe_allow_html=True)

                with col5:
                    st.markdown(f"""
                    <div class="metric-card">
                        <div class="metric-value">${total_usd_value:,.0f}</div>
                        <div class="metric-label">Total USD Value</div>
                    </div>
                    """, unsafe_allow_html=True)

                st.markdown("---")

                # Detailed results for each wallet
                st.markdown("**Detailed Wallet Comparison**")

                for result in results:
                    # Color coding based on status
                    if result['status'] == "Match":
                        border_color = "#28a745"
                        bg_color = "#d4edda"
                    elif result['status'] == "Minor Variance":
                        border_color = "#ffc107"
                        bg_color = "#fff3cd"
                    else:
                        border_color = "#dc3545"
                        bg_color = "#f8d7da"

                    with st.expander(
                        f"{result['crypto']} | {result['wallet_id']} - {result['wallet_name']} | Status: {result['status']}",
                        expanded=(result['status'] == "Significant Variance")
                    ):
                        col1, col2, col3 = st.columns(3)

                        with col1:
                            st.markdown("**Recorded Balance (Books)**")
                            st.markdown(f"### {result['recorded_balance']:,.8f} {result['crypto']}")
                            st.caption(f"USD Value: ${result['recorded_balance'] * get_crypto_usd_price(result['crypto']):,.2f}")

                        with col2:
                            st.markdown("**Blockchain Balance**")
                            st.markdown(f"### {result['blockchain_balance']:,.8f} {result['crypto']}")
                            st.caption(f"USD Value: ${result['usd_value']:,.2f}")
                            st.caption(f"Block Height: {result['block_height']:,}")

                        with col3:
                            st.markdown("**Variance**")
                            variance_sign = "+" if result['variance_abs'] >= 0 else ""
                            st.markdown(f"### {variance_sign}{result['variance_abs']:,.8f} {result['crypto']}")
                            st.markdown(f"**{variance_sign}{result['variance_pct']:.4f}%**")
                            st.caption(f"USD Impact: ${result['variance_usd']:,.2f}")

                        st.markdown("---")

                        # Wallet details
                        detail_col1, detail_col2 = st.columns(2)

                        with detail_col1:
                            st.markdown("**Wallet Details**")
                            st.text(f"Address: {result['wallet_address']}")
                            st.text(f"Custodian: {result['custodian']}")
                            st.text(f"Verified: {result['verification_time'][:19]}")

                        with detail_col2:
                            # Reconciling items documentation
                            st.markdown("**Reconciling Items**")
                            reconciling_key = result['wallet_id']

                            current_notes = st.session_state.reconciling_items.get(reconciling_key, "")

                            notes = st.text_area(
                                "Document any reconciling items or explanations",
                                value=current_notes,
                                key=f"notes_{result['wallet_id']}",
                                height=100,
                                placeholder="e.g., Pending transaction not yet confirmed, timing difference, etc."
                            )

                            if notes != current_notes:
                                st.session_state.reconciling_items[reconciling_key] = notes

                # Export functionality
                st.markdown('<h3 class="section-header">Export Reconciliation Workpaper</h3>', unsafe_allow_html=True)

                col1, col2 = st.columns(2)

                with col1:
                    # Prepare export data
                    export_data = []
                    for r in results:
                        export_data.append({
                            "Wallet ID": r['wallet_id'],
                            "Wallet Name": r['wallet_name'],
                            "Cryptocurrency": r['crypto'],
                            "Wallet Address": r['wallet_address'],
                            "Custodian": r['custodian'],
                            "Recorded Balance": r['recorded_balance'],
                            "Blockchain Balance": r['blockchain_balance'],
                            "Variance (Absolute)": r['variance_abs'],
                            "Variance (%)": r['variance_pct'],
                            "Variance (USD)": r['variance_usd'],
                            "Total USD Value": r['usd_value'],
                            "Status": r['status'],
                            "Block Height": r['block_height'],
                            "Verification Time": r['verification_time'],
                            "Reconciling Items": st.session_state.reconciling_items.get(r['wallet_id'], "")
                        })

                    export_df = pd.DataFrame(export_data)

                    # CSV download
                    csv_data = export_df.to_csv(index=False)
                    st.download_button(
                        label="Download CSV Workpaper",
                        data=csv_data,
                        file_name=f"wallet_reconciliation_{datetime.date.today().isoformat()}.csv",
                        mime="text/csv",
                        use_container_width=True
                    )

                with col2:
                    # JSON download
                    json_export = {
                        "reconciliation_date": datetime.datetime.now().isoformat(),
                        "engagement_id": st.session_state.audit_engagement.get('id', 'N/A'),
                        "auditor": st.session_state.audit_engagement.get('auditor', 'N/A'),
                        "total_wallets": total_wallets,
                        "summary": {
                            "matches": matches,
                            "minor_variances": minor_variances,
                            "significant_variances": significant_variances,
                            "total_variance_usd": total_variance_usd,
                            "total_usd_value": total_usd_value
                        },
                        "results": results,
                        "reconciling_items": st.session_state.reconciling_items
                    }

                    st.download_button(
                        label="Download JSON Workpaper",
                        data=json.dumps(json_export, indent=2, default=str),
                        file_name=f"wallet_reconciliation_{datetime.date.today().isoformat()}.json",
                        mime="application/json",
                        use_container_width=True
                    )

    # =============================================================================
    # TAB 3: HISTORICAL TRENDS
    # =============================================================================

    with tab3:
        st.markdown('<h3 class="section-header">Historical Balance Trends</h3>', unsafe_allow_html=True)

        if not st.session_state.wallet_entries:
            st.warning("No wallets entered. Please add wallets in the 'Wallet Entry' tab first.")
        else:
            col1, col2 = st.columns([1, 2])

            with col1:
                # Wallet selection
                selected_wallet = st.selectbox(
                    "Select Wallet for Analysis",
                    options=[f"{w['wallet_id']} - {w['wallet_name']}" for w in st.session_state.wallet_entries],
                    key="historical_wallet_select"
                )

                days_to_show = st.slider(
                    "Historical Period (Days)",
                    min_value=7,
                    max_value=90,
                    value=30,
                    step=7
                )

                if st.button("Generate Historical Data", type="primary", use_container_width=True):
                    # Find selected wallet
                    wallet_id = selected_wallet.split(" - ")[0]
                    wallet = next((w for w in st.session_state.wallet_entries if w['wallet_id'] == wallet_id), None)

                    if wallet:
                        historical = get_mock_historical_balances(
                            wallet['wallet_address'],
                            wallet['crypto'],
                            days_to_show
                        )
                        st.session_state.historical_data_cache[wallet_id] = {
                            "data": historical,
                            "crypto": wallet['crypto'],
                            "wallet_name": wallet['wallet_name']
                        }
                        st.rerun()

            with col2:
                # Display chart if data exists
                wallet_id = selected_wallet.split(" - ")[0] if selected_wallet else None

                if wallet_id and wallet_id in st.session_state.historical_data_cache:
                    cache = st.session_state.historical_data_cache[wallet_id]
                    hist_df = pd.DataFrame(cache['data'])
                    hist_df['date'] = pd.to_datetime(hist_df['date'])

                    st.markdown(f"**{cache['wallet_name']} - {cache['crypto']} Balance History**")

                    # Create line chart
                    st.line_chart(
                        hist_df.set_index('date')['balance'],
                        use_container_width=True
                    )

                    # Statistics
                    stat_col1, stat_col2, stat_col3, stat_col4 = st.columns(4)

                    with stat_col1:
                        st.metric("Current Balance", f"{hist_df['balance'].iloc[-1]:,.4f}")

                    with stat_col2:
                        st.metric("Average Balance", f"{hist_df['balance'].mean():,.4f}")

                    with stat_col3:
                        st.metric("Max Balance", f"{hist_df['balance'].max():,.4f}")

                    with stat_col4:
                        st.metric("Min Balance", f"{hist_df['balance'].min():,.4f}")

                    # Show data table
                    with st.expander("View Historical Data Table"):
                        display_df = hist_df.copy()
                        display_df['balance'] = display_df['balance'].apply(lambda x: f"{x:,.8f}")
                        st.dataframe(display_df, use_container_width=True, hide_index=True)
                else:
                    st.info("Select a wallet and click 'Generate Historical Data' to view balance trends.")

    # =============================================================================
    # TAB 4: AGGREGATED VIEW
    # =============================================================================

    with tab4:
        st.markdown('<h3 class="section-header">Multi-Wallet Aggregation</h3>', unsafe_allow_html=True)

        if not st.session_state.reconciliation_results:
            st.warning("Please run reconciliation first in the 'Reconciliation' tab to view aggregated data.")
        else:
            results = st.session_state.reconciliation_results

            # Aggregate by cryptocurrency
            st.markdown("**Aggregated Balances by Cryptocurrency**")

            crypto_aggregates = {}
            for r in results:
                crypto = r['crypto']
                if crypto not in crypto_aggregates:
                    crypto_aggregates[crypto] = {
                        "recorded_total": 0,
                        "blockchain_total": 0,
                        "usd_value": 0,
                        "variance_usd": 0,
                        "wallet_count": 0
                    }

                crypto_aggregates[crypto]['recorded_total'] += r['recorded_balance']
                crypto_aggregates[crypto]['blockchain_total'] += r['blockchain_balance']
                crypto_aggregates[crypto]['usd_value'] += r['usd_value']
                crypto_aggregates[crypto]['variance_usd'] += r['variance_usd']
                crypto_aggregates[crypto]['wallet_count'] += 1

            # Display aggregate cards
            cols = st.columns(len(crypto_aggregates))

            for idx, (crypto, data) in enumerate(crypto_aggregates.items()):
                with cols[idx]:
                    variance_pct = ((data['blockchain_total'] - data['recorded_total']) /
                                   data['recorded_total'] * 100) if data['recorded_total'] != 0 else 0

                    if abs(variance_pct) <= 0.01:
                        status_color = "#28a745"
                    elif abs(variance_pct) <= 1.0:
                        status_color = "#ffc107"
                    else:
                        status_color = "#dc3545"

                    st.markdown(f"""
                    <div class="audit-card" style="border-left-color: {status_color};">
                        <h3>{crypto}</h3>
                        <p><strong>Wallets:</strong> {data['wallet_count']}</p>
                        <p><strong>Recorded:</strong> {data['recorded_total']:,.4f}</p>
                        <p><strong>Blockchain:</strong> {data['blockchain_total']:,.4f}</p>
                        <p><strong>USD Value:</strong> ${data['usd_value']:,.2f}</p>
                        <p><strong>Variance:</strong> <span style="color: {status_color};">{variance_pct:.4f}%</span></p>
                    </div>
                    """, unsafe_allow_html=True)

            st.markdown("---")

            # Aggregate by Custodian
            st.markdown("**Aggregated Balances by Custodian**")

            custodian_aggregates = {}
            for r in results:
                custodian = r['custodian'] or "Unknown"
                if custodian not in custodian_aggregates:
                    custodian_aggregates[custodian] = {
                        "usd_value": 0,
                        "variance_usd": 0,
                        "wallet_count": 0,
                        "cryptos": set()
                    }

                custodian_aggregates[custodian]['usd_value'] += r['usd_value']
                custodian_aggregates[custodian]['variance_usd'] += r['variance_usd']
                custodian_aggregates[custodian]['wallet_count'] += 1
                custodian_aggregates[custodian]['cryptos'].add(r['crypto'])

            # Create custodian table
            custodian_data = []
            for custodian, data in custodian_aggregates.items():
                custodian_data.append({
                    "Custodian": custodian,
                    "Wallet Count": data['wallet_count'],
                    "Cryptocurrencies": ", ".join(sorted(data['cryptos'])),
                    "Total USD Value": f"${data['usd_value']:,.2f}",
                    "Total Variance (USD)": f"${data['variance_usd']:,.2f}"
                })

            custodian_df = pd.DataFrame(custodian_data)
            st.dataframe(custodian_df, use_container_width=True, hide_index=True)

            # Grand totals
            st.markdown("---")
            st.markdown("**Grand Totals**")

            grand_col1, grand_col2, grand_col3 = st.columns(3)

            total_usd = sum(data['usd_value'] for data in crypto_aggregates.values())
            total_variance = sum(data['variance_usd'] for data in crypto_aggregates.values())
            total_wallets = len(results)

            with grand_col1:
                st.markdown(f"""
                <div class="metric-card">
                    <div class="metric-value">${total_usd:,.0f}</div>
                    <div class="metric-label">Total Assets Under Custody</div>
                </div>
                """, unsafe_allow_html=True)

            with grand_col2:
                variance_color = "#28a745" if abs(total_variance) < 1000 else "#dc3545"
                st.markdown(f"""
                <div class="metric-card">
                    <div class="metric-value" style="color: {variance_color};">${abs(total_variance):,.2f}</div>
                    <div class="metric-label">Total Absolute Variance</div>
                </div>
                """, unsafe_allow_html=True)

            with grand_col3:
                st.markdown(f"""
                <div class="metric-card">
                    <div class="metric-value">{total_wallets}</div>
                    <div class="metric-label">Wallets Reconciled</div>
                </div>
                """, unsafe_allow_html=True)

            # Proof of Reserves Summary
            st.markdown('<h3 class="section-header">Proof of Reserves Summary</h3>', unsafe_allow_html=True)

            por_col1, por_col2 = st.columns([2, 1])

            with por_col1:
                st.markdown("""
                <div class="info-box">
                    <strong>Reconciliation Summary Statement</strong><br><br>
                    Based on the blockchain verification performed, the recorded balances have been
                    compared against the on-chain balances for all wallets under custody. This
                    reconciliation supports the proof of reserves assertion by providing independent
                    verification of asset existence and ownership.
                </div>
                """, unsafe_allow_html=True)

                # Summary table
                summary_data = {
                    "Metric": [
                        "Total Wallets Verified",
                        "Total Recorded Balance (USD)",
                        "Total Blockchain Balance (USD)",
                        "Net Variance (USD)",
                        "Variance Percentage",
                        "Wallets with Significant Variance"
                    ],
                    "Value": [
                        str(total_wallets),
                        f"${sum(r['recorded_balance'] * get_crypto_usd_price(r['crypto']) for r in results):,.2f}",
                        f"${total_usd:,.2f}",
                        f"${total_variance:,.2f}",
                        f"{(total_variance / total_usd * 100) if total_usd else 0:.4f}%",
                        str(len([r for r in results if r['status'] == 'Significant Variance']))
                    ]
                }

                st.table(pd.DataFrame(summary_data))

            with por_col2:
                # Reconciliation sign-off
                st.markdown("""
                <div class="audit-card">
                    <h4>Reconciliation Sign-Off</h4>
                </div>
                """, unsafe_allow_html=True)

                prepared_by = st.text_input(
                    "Prepared By",
                    value=st.session_state.audit_engagement.get('auditor', ''),
                    key="por_prepared_by"
                )

                reviewed_by = st.text_input(
                    "Reviewed By",
                    placeholder="Enter reviewer name",
                    key="por_reviewed_by"
                )

                sign_off_date = st.date_input(
                    "Sign-Off Date",
                    value=datetime.date.today(),
                    key="por_date"
                )

                if st.button("Generate POR Certificate", type="primary", use_container_width=True):
                    certificate = {
                        "certificate_type": "Proof of Reserves Reconciliation",
                        "date": sign_off_date.isoformat(),
                        "prepared_by": prepared_by,
                        "reviewed_by": reviewed_by,
                        "engagement_id": st.session_state.audit_engagement.get('id', 'N/A'),
                        "total_assets_usd": total_usd,
                        "total_wallets": total_wallets,
                        "variance_usd": total_variance,
                        "conclusion": "Blockchain balances verified" if abs(total_variance / total_usd * 100) < 1 else "Variances require investigation"
                    }

                    st.download_button(
                        label="Download POR Certificate",
                        data=json.dumps(certificate, indent=2),
                        file_name=f"por_certificate_{sign_off_date.isoformat()}.json",
                        mime="application/json",
                        use_container_width=True
                    )


def render_compliance_dashboard():
    """Render the Compliance Dashboard section with full functionality."""

    # Import additional data structures needed for compliance
    from audit_data import (
        REGULATORY_COMPLIANCE_CHECKLISTS,
        SAMPLE_AUDIT_FINDINGS,
        FindingSeverity,
        RemediationStatus,
        SEVERITY_DEFINITIONS,
        ComplianceRequirement,
        AuditFinding,
        COSOComponent,
        ControlCategory,
    )
    from datetime import date, timedelta
    import json

    # Initialize session state for compliance tracking
    if 'compliance_items' not in st.session_state:
        st.session_state.compliance_items = {}

    if 'audit_findings' not in st.session_state:
        st.session_state.audit_findings = []

    # Load demo data if demo mode is enabled
    if st.session_state.demo_mode and not st.session_state.audit_findings:
        st.session_state.audit_findings = [finding_to_dict(f) for f in SAMPLE_AUDIT_FINDINGS]
        # Initialize some demo compliance assessments
        for reg_key, reg_data in REGULATORY_COMPLIANCE_CHECKLISTS.items():
            for req in reg_data.get('requirements', []):
                if req.requirement_id not in st.session_state.compliance_items:
                    # Randomly assign statuses for demo
                    demo_statuses = ['Compliant', 'Compliant', 'Compliant', 'Partial', 'Not Assessed']
                    st.session_state.compliance_items[req.requirement_id] = {
                        'status': random.choice(demo_statuses),
                        'notes': '',
                        'last_assessed': datetime.date.today() - datetime.timedelta(days=random.randint(0, 90)),
                        'assessor': 'Demo Auditor'
                    }

    # Page Header
    st.markdown('<h1 class="main-header">Compliance Dashboard</h1>', unsafe_allow_html=True)
    st.markdown(
        '<p class="sub-header">Regulatory compliance tracking, assessment management, and audit findings oversight</p>',
        unsafe_allow_html=True
    )

    # =========================================================================
    # COMPLIANCE METRICS DASHBOARD - KPIs at the top
    # =========================================================================
    st.markdown('<h2 class="section-header">Compliance Metrics Overview</h2>', unsafe_allow_html=True)

    # Calculate compliance metrics
    total_requirements = 0
    compliant_count = 0
    partial_count = 0
    non_compliant_count = 0
    not_assessed_count = 0

    for reg_key, reg_data in REGULATORY_COMPLIANCE_CHECKLISTS.items():
        for req in reg_data.get('requirements', []):
            total_requirements += 1
            status = st.session_state.compliance_items.get(req.requirement_id, {}).get('status', 'Not Assessed')
            if status == 'Compliant':
                compliant_count += 1
            elif status == 'Partial':
                partial_count += 1
            elif status == 'Non-Compliant':
                non_compliant_count += 1
            else:
                not_assessed_count += 1

    # Calculate findings metrics
    open_findings = len([f for f in st.session_state.audit_findings
                        if f.status in [RemediationStatus.OPEN, RemediationStatus.IN_PROGRESS]])
    critical_findings = len([f for f in st.session_state.audit_findings
                            if f.severity == FindingSeverity.CRITICAL and f.status != RemediationStatus.CLOSED])
    overdue_findings = len([f for f in st.session_state.audit_findings
                           if f.target_remediation_date < datetime.date.today() and f.status not in [RemediationStatus.CLOSED, RemediationStatus.RISK_ACCEPTED]])

    compliance_rate = (compliant_count / total_requirements * 100) if total_requirements > 0 else 0

    # Display KPI cards
    col1, col2, col3, col4, col5 = st.columns(5)

    with col1:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value" style="color: {'#28a745' if compliance_rate >= 80 else '#ffc107' if compliance_rate >= 60 else '#dc3545'};">{compliance_rate:.1f}%</div>
            <div class="metric-label">Compliance Rate</div>
        </div>
        """, unsafe_allow_html=True)

    with col2:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value">{total_requirements}</div>
            <div class="metric-label">Total Requirements</div>
        </div>
        """, unsafe_allow_html=True)

    with col3:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value" style="color: {'#dc3545' if open_findings > 5 else '#ffc107' if open_findings > 0 else '#28a745'};">{open_findings}</div>
            <div class="metric-label">Open Findings</div>
        </div>
        """, unsafe_allow_html=True)

    with col4:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value" style="color: {'#dc3545' if critical_findings > 0 else '#28a745'};">{critical_findings}</div>
            <div class="metric-label">Critical Issues</div>
        </div>
        """, unsafe_allow_html=True)

    with col5:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value" style="color: {'#dc3545' if overdue_findings > 0 else '#28a745'};">{overdue_findings}</div>
            <div class="metric-label">Overdue Items</div>
        </div>
        """, unsafe_allow_html=True)

    # Compliance Status Progress Bars
    st.markdown("#### Compliance Status Distribution")
    col1, col2 = st.columns([3, 1])

    with col1:
        if total_requirements > 0:
            compliant_pct = compliant_count / total_requirements
            partial_pct = partial_count / total_requirements
            non_compliant_pct = non_compliant_count / total_requirements
            not_assessed_pct = not_assessed_count / total_requirements

            st.markdown(f"""
            <div style="display: flex; height: 30px; border-radius: 5px; overflow: hidden; margin-bottom: 10px;">
                <div style="width: {compliant_pct*100}%; background-color: #28a745;" title="Compliant: {compliant_count}"></div>
                <div style="width: {partial_pct*100}%; background-color: #ffc107;" title="Partial: {partial_count}"></div>
                <div style="width: {non_compliant_pct*100}%; background-color: #dc3545;" title="Non-Compliant: {non_compliant_count}"></div>
                <div style="width: {not_assessed_pct*100}%; background-color: #6c757d;" title="Not Assessed: {not_assessed_count}"></div>
            </div>
            """, unsafe_allow_html=True)

    with col2:
        st.markdown(f"""
        <div style="font-size: 0.85rem;">
            <span style="color: #28a745;">&#9632;</span> Compliant: {compliant_count}<br>
            <span style="color: #ffc107;">&#9632;</span> Partial: {partial_count}<br>
            <span style="color: #dc3545;">&#9632;</span> Non-Compliant: {non_compliant_count}<br>
            <span style="color: #6c757d;">&#9632;</span> Not Assessed: {not_assessed_count}
        </div>
        """, unsafe_allow_html=True)

    st.divider()

    # =========================================================================
    # MAIN TABS FOR COMPLIANCE AREAS
    # =========================================================================

    main_tabs = st.tabs([
        "Regulatory Checklists",
        "Findings Tracker",
        "Issue Aging Analysis",
        "Exam Preparation",
        "Reports & Export"
    ])

    # =========================================================================
    # TAB 1: REGULATORY REQUIREMENT CHECKLISTS
    # =========================================================================
    with main_tabs[0]:
        st.markdown('<h3 class="section-header">Regulatory Compliance Checklists</h3>', unsafe_allow_html=True)

        # Create sub-tabs for each regulation
        regulation_tabs = st.tabs([
            reg_data.get('regulation_name', reg_key)[:20] + '...' if len(reg_data.get('regulation_name', reg_key)) > 20 else reg_data.get('regulation_name', reg_key)
            for reg_key, reg_data in REGULATORY_COMPLIANCE_CHECKLISTS.items()
        ])

        for idx, (reg_key, reg_data) in enumerate(REGULATORY_COMPLIANCE_CHECKLISTS.items()):
            with regulation_tabs[idx]:
                reg_name = reg_data.get('regulation_name', reg_key)
                authority = reg_data.get('authority', 'N/A')
                requirements = reg_data.get('requirements', [])

                # Regulation header info
                st.markdown(f"""
                <div class="info-box">
                    <strong>{reg_name}</strong><br>
                    <span style="color: #5A6C7D;">Regulatory Authority: {authority}</span><br>
                    <span style="color: #5A6C7D;">Total Requirements: {len(requirements)}</span>
                </div>
                """, unsafe_allow_html=True)

                # Calculate regulation-specific compliance rate
                reg_compliant = sum(1 for req in requirements
                                   if st.session_state.compliance_items.get(req.requirement_id, {}).get('status') == 'Compliant')
                reg_rate = (reg_compliant / len(requirements) * 100) if requirements else 0

                st.progress(reg_rate / 100, text=f"Compliance Rate: {reg_rate:.1f}%")

                # Display each requirement with interactive assessment
                for req in requirements:
                    req_id = req.requirement_id
                    current_assessment = st.session_state.compliance_items.get(req_id, {
                        'status': 'Not Assessed',
                        'notes': '',
                        'last_assessed': None,
                        'assessor': ''
                    })

                    with st.expander(f"{req_id}: {req.requirement}", expanded=False):
                        col1, col2 = st.columns([2, 1])

                        with col1:
                            st.markdown(f"**Description:** {req.description}")
                            st.markdown(f"**Frequency:** {req.frequency}")
                            st.markdown(f"**Applicability:** {req.applicability}")

                            st.markdown("**Testing Procedures:**")
                            for proc in req.testing_procedures:
                                st.markdown(f"- {proc}")

                            st.markdown("**Evidence Required:**")
                            for evidence in req.evidence_required:
                                st.markdown(f"- {evidence}")

                        with col2:
                            # Status selection with color-coded badges
                            status_options = ['Not Assessed', 'Compliant', 'Partial', 'Non-Compliant']
                            current_status = current_assessment.get('status', 'Not Assessed')

                            # Display current status badge
                            status_colors = {
                                'Compliant': '#28a745',
                                'Partial': '#ffc107',
                                'Non-Compliant': '#dc3545',
                                'Not Assessed': '#6c757d'
                            }
                            st.markdown(f"""
                            <div style="background-color: {status_colors.get(current_status, '#6c757d')};
                                        color: {'white' if current_status != 'Partial' else '#212529'};
                                        padding: 0.5rem 1rem;
                                        border-radius: 20px;
                                        text-align: center;
                                        font-weight: 600;
                                        margin-bottom: 1rem;">
                                {current_status}
                            </div>
                            """, unsafe_allow_html=True)

                            # Interactive assessment form
                            new_status = st.selectbox(
                                "Update Status",
                                options=status_options,
                                index=status_options.index(current_status),
                                key=f"status_{req_id}"
                            )

                            new_notes = st.text_area(
                                "Assessment Notes",
                                value=current_assessment.get('notes', ''),
                                key=f"notes_{req_id}",
                                height=100
                            )

                            assessor_name = st.text_input(
                                "Assessor Name",
                                value=current_assessment.get('assessor', ''),
                                key=f"assessor_{req_id}"
                            )

                            if st.button("Save Assessment", key=f"save_{req_id}", type="primary"):
                                st.session_state.compliance_items[req_id] = {
                                    'status': new_status,
                                    'notes': new_notes,
                                    'last_assessed': datetime.date.today(),
                                    'assessor': assessor_name
                                }
                                st.success(f"Assessment saved for {req_id}")
                                st.rerun()

                            # Show last assessment date if available
                            if current_assessment.get('last_assessed'):
                                st.caption(f"Last assessed: {current_assessment['last_assessed']}")

    # =========================================================================
    # TAB 2: FINDINGS TRACKER
    # =========================================================================
    with main_tabs[1]:
        st.markdown('<h3 class="section-header">Audit Findings Tracker</h3>', unsafe_allow_html=True)

        # Filters for findings
        col1, col2, col3 = st.columns(3)

        with col1:
            severity_filter = st.multiselect(
                "Filter by Severity",
                options=['Critical', 'High', 'Medium', 'Low'],
                default=['Critical', 'High', 'Medium', 'Low']
            )

        with col2:
            status_filter = st.multiselect(
                "Filter by Status",
                options=['Open', 'In Progress', 'Pending Validation', 'Closed', 'Risk Accepted'],
                default=['Open', 'In Progress', 'Pending Validation']
            )

        with col3:
            sort_option = st.selectbox(
                "Sort By",
                options=['Severity (High to Low)', 'Date (Newest First)', 'Target Date', 'Status']
            )

        # Map display values to enum values
        severity_map = {
            'Critical': FindingSeverity.CRITICAL,
            'High': FindingSeverity.HIGH,
            'Medium': FindingSeverity.MEDIUM,
            'Low': FindingSeverity.LOW
        }

        status_map = {
            'Open': RemediationStatus.OPEN,
            'In Progress': RemediationStatus.IN_PROGRESS,
            'Pending Validation': RemediationStatus.PENDING_VALIDATION,
            'Closed': RemediationStatus.CLOSED,
            'Risk Accepted': RemediationStatus.RISK_ACCEPTED
        }

        # Filter findings
        filtered_findings = [
            f for f in st.session_state.audit_findings
            if f.severity in [severity_map.get(s) for s in severity_filter]
            and f.status in [status_map.get(s) for s in status_filter]
        ]

        # Sort findings
        if sort_option == 'Severity (High to Low)':
            severity_order = {FindingSeverity.CRITICAL: 0, FindingSeverity.HIGH: 1, FindingSeverity.MEDIUM: 2, FindingSeverity.LOW: 3}
            filtered_findings.sort(key=lambda x: severity_order.get(x.severity, 4))
        elif sort_option == 'Date (Newest First)':
            filtered_findings.sort(key=lambda x: x.identified_date, reverse=True)
        elif sort_option == 'Target Date':
            filtered_findings.sort(key=lambda x: x.target_remediation_date)

        st.markdown(f"**Showing {len(filtered_findings)} of {len(st.session_state.audit_findings)} findings**")

        # Display findings
        for finding in filtered_findings:
            # Determine severity badge color
            severity_colors = {
                FindingSeverity.CRITICAL: ('#dc3545', 'white'),
                FindingSeverity.HIGH: ('#fd7e14', 'white'),
                FindingSeverity.MEDIUM: ('#ffc107', '#212529'),
                FindingSeverity.LOW: ('#28a745', 'white')
            }

            status_colors = {
                RemediationStatus.OPEN: ('#dc3545', 'white'),
                RemediationStatus.IN_PROGRESS: ('#17a2b8', 'white'),
                RemediationStatus.PENDING_VALIDATION: ('#6f42c1', 'white'),
                RemediationStatus.CLOSED: ('#28a745', 'white'),
                RemediationStatus.RISK_ACCEPTED: ('#6c757d', 'white'),
                RemediationStatus.OVERDUE: ('#dc3545', 'white')
            }

            sev_bg, sev_fg = severity_colors.get(finding.severity, ('#6c757d', 'white'))
            stat_bg, stat_fg = status_colors.get(finding.status, ('#6c757d', 'white'))

            # Check if overdue
            is_overdue = finding.target_remediation_date < datetime.date.today() and finding.status not in [RemediationStatus.CLOSED, RemediationStatus.RISK_ACCEPTED]
            days_remaining = (finding.target_remediation_date - datetime.date.today()).days

            with st.expander(f"{finding.finding_id}: {finding.title}", expanded=False):
                # Header with badges
                col1, col2, col3, col4 = st.columns([2, 1, 1, 1])

                with col1:
                    st.markdown(f"**{finding.title}**")

                with col2:
                    st.markdown(f"""
                    <span style="background-color: {sev_bg}; color: {sev_fg}; padding: 0.25rem 0.75rem; border-radius: 20px; font-size: 0.8rem; font-weight: 600;">
                        {finding.severity.value.upper()}
                    </span>
                    """, unsafe_allow_html=True)

                with col3:
                    st.markdown(f"""
                    <span style="background-color: {stat_bg}; color: {stat_fg}; padding: 0.25rem 0.75rem; border-radius: 20px; font-size: 0.8rem; font-weight: 600;">
                        {finding.status.value.replace('_', ' ').upper()}
                    </span>
                    """, unsafe_allow_html=True)

                with col4:
                    if is_overdue:
                        st.markdown(f"""
                        <span style="background-color: #dc3545; color: white; padding: 0.25rem 0.75rem; border-radius: 20px; font-size: 0.8rem; font-weight: 600;">
                            OVERDUE ({abs(days_remaining)}d)
                        </span>
                        """, unsafe_allow_html=True)
                    elif days_remaining <= 7 and finding.status not in [RemediationStatus.CLOSED, RemediationStatus.RISK_ACCEPTED]:
                        st.markdown(f"""
                        <span style="background-color: #ffc107; color: #212529; padding: 0.25rem 0.75rem; border-radius: 20px; font-size: 0.8rem; font-weight: 600;">
                            DUE SOON ({days_remaining}d)
                        </span>
                        """, unsafe_allow_html=True)

                st.divider()

                # Finding details in columns
                col1, col2 = st.columns(2)

                with col1:
                    st.markdown("**Condition (What was found):**")
                    st.markdown(f"<div style='background-color: #f8f9fa; padding: 0.75rem; border-radius: 8px; margin-bottom: 1rem;'>{finding.condition}</div>", unsafe_allow_html=True)

                    st.markdown("**Criteria (What should be):**")
                    st.markdown(f"<div style='background-color: #f8f9fa; padding: 0.75rem; border-radius: 8px; margin-bottom: 1rem;'>{finding.criteria}</div>", unsafe_allow_html=True)

                    st.markdown("**Cause (Root cause):**")
                    st.markdown(f"<div style='background-color: #f8f9fa; padding: 0.75rem; border-radius: 8px; margin-bottom: 1rem;'>{finding.cause}</div>", unsafe_allow_html=True)

                with col2:
                    st.markdown("**Effect (Risk/Impact):**")
                    st.markdown(f"<div style='background-color: #fff3e0; padding: 0.75rem; border-radius: 8px; margin-bottom: 1rem; border-left: 3px solid #ff9800;'>{finding.effect}</div>", unsafe_allow_html=True)

                    st.markdown("**Recommendation:**")
                    st.markdown(f"<div style='background-color: #e7f3ff; padding: 0.75rem; border-radius: 8px; margin-bottom: 1rem; border-left: 3px solid #0066cc;'>{finding.recommendation}</div>", unsafe_allow_html=True)

                    if finding.management_response:
                        st.markdown("**Management Response:**")
                        st.markdown(f"<div style='background-color: #e8f5e9; padding: 0.75rem; border-radius: 8px; margin-bottom: 1rem; border-left: 3px solid #28a745;'>{finding.management_response}</div>", unsafe_allow_html=True)

                # Metadata
                st.divider()
                meta_col1, meta_col2, meta_col3, meta_col4 = st.columns(4)

                with meta_col1:
                    st.markdown(f"**Identified:** {finding.identified_date}")
                with meta_col2:
                    st.markdown(f"**Target Date:** {finding.target_remediation_date}")
                with meta_col3:
                    st.markdown(f"**Process Owner:** {finding.process_owner}")
                with meta_col4:
                    st.markdown(f"**Audit Owner:** {finding.audit_owner}")

                if finding.regulatory_reference:
                    st.markdown(f"**Regulatory Reference:** {finding.regulatory_reference}")

        # Add new finding section
        st.divider()
        st.markdown("#### Add New Finding")

        with st.form("new_finding_form"):
            col1, col2 = st.columns(2)

            with col1:
                new_finding_title = st.text_input("Finding Title")
                new_finding_severity = st.selectbox("Severity", ['Critical', 'High', 'Medium', 'Low'])
                new_finding_condition = st.text_area("Condition (What was found)", height=100)
                new_finding_criteria = st.text_area("Criteria (What should be)", height=100)

            with col2:
                new_finding_cause = st.text_area("Cause (Root cause)", height=100)
                new_finding_effect = st.text_area("Effect (Risk/Impact)", height=100)
                new_finding_recommendation = st.text_area("Recommendation", height=100)
                new_finding_target_date = st.date_input("Target Remediation Date", value=datetime.date.today() + datetime.timedelta(days=30))

            col3, col4 = st.columns(2)
            with col3:
                new_finding_owner = st.text_input("Process Owner")
            with col4:
                new_finding_auditor = st.text_input("Audit Owner")

            if st.form_submit_button("Add Finding", type="primary"):
                if new_finding_title and new_finding_condition:
                    new_id = f"FINDING-{datetime.date.today().year}-{len(st.session_state.audit_findings) + 1:03d}"

                    new_finding = AuditFinding(
                        finding_id=new_id,
                        title=new_finding_title,
                        severity=severity_map.get(new_finding_severity, FindingSeverity.MEDIUM),
                        status=RemediationStatus.OPEN,
                        identified_date=datetime.date.today(),
                        target_remediation_date=new_finding_target_date,
                        actual_remediation_date=None,
                        condition=new_finding_condition,
                        criteria=new_finding_criteria,
                        cause=new_finding_cause,
                        effect=new_finding_effect,
                        recommendation=new_finding_recommendation,
                        coso_component=COSOComponent.CONTROL_ACTIVITIES,
                        control_category=ControlCategory.WALLET_MANAGEMENT,
                        regulatory_reference=None,
                        process_owner=new_finding_owner,
                        audit_owner=new_finding_auditor,
                        management_response=None,
                        management_action_plan=None
                    )

                    st.session_state.audit_findings.append(new_finding)
                    st.success(f"Finding {new_id} added successfully!")
                    st.rerun()
                else:
                    st.error("Please provide at least a title and condition for the finding.")

    # =========================================================================
    # TAB 3: AUDIT ISSUE AGING ANALYSIS
    # =========================================================================
    with main_tabs[2]:
        st.markdown('<h3 class="section-header">Audit Issue Aging Analysis</h3>', unsafe_allow_html=True)

        # Get open findings for aging analysis
        open_findings_list = [f for f in st.session_state.audit_findings
                            if f.status not in [RemediationStatus.CLOSED, RemediationStatus.RISK_ACCEPTED]]

        if not open_findings_list:
            st.info("No open findings to analyze. All issues are closed or risk accepted.")
        else:
            # Calculate aging buckets
            today = datetime.date.today()

            aging_buckets = {
                '0-30 days': [],
                '31-60 days': [],
                '61-90 days': [],
                '91-180 days': [],
                '180+ days': []
            }

            for finding in open_findings_list:
                days_open = (today - finding.identified_date).days

                if days_open <= 30:
                    aging_buckets['0-30 days'].append(finding)
                elif days_open <= 60:
                    aging_buckets['31-60 days'].append(finding)
                elif days_open <= 90:
                    aging_buckets['61-90 days'].append(finding)
                elif days_open <= 180:
                    aging_buckets['91-180 days'].append(finding)
                else:
                    aging_buckets['180+ days'].append(finding)

            # Display aging summary
            st.markdown("#### Aging Summary")

            cols = st.columns(5)
            bucket_colors = ['#28a745', '#17a2b8', '#ffc107', '#fd7e14', '#dc3545']

            for idx, (bucket, findings) in enumerate(aging_buckets.items()):
                with cols[idx]:
                    st.markdown(f"""
                    <div style="background-color: {bucket_colors[idx]};
                                color: {'white' if idx != 2 else '#212529'};
                                padding: 1rem;
                                border-radius: 10px;
                                text-align: center;">
                        <div style="font-size: 2rem; font-weight: 700;">{len(findings)}</div>
                        <div style="font-size: 0.85rem;">{bucket}</div>
                    </div>
                    """, unsafe_allow_html=True)

            st.divider()

            # Aging by severity
            st.markdown("#### Aging by Severity")

            # Create aging data for visualization
            aging_data = []
            for bucket, findings in aging_buckets.items():
                for sev in [FindingSeverity.CRITICAL, FindingSeverity.HIGH, FindingSeverity.MEDIUM, FindingSeverity.LOW]:
                    count = len([f for f in findings if f.severity == sev])
                    if count > 0:
                        aging_data.append({
                            'Aging Bucket': bucket,
                            'Severity': sev.value.capitalize(),
                            'Count': count
                        })

            if aging_data:
                aging_df = pd.DataFrame(aging_data)

                # Display as a pivot table style
                pivot_data = {}
                for bucket in aging_buckets.keys():
                    pivot_data[bucket] = {}
                    for sev in ['Critical', 'High', 'Medium', 'Low']:
                        count = len([f for f in aging_buckets[bucket] if f.severity.value.capitalize() == sev])
                        pivot_data[bucket][sev] = count

                pivot_df = pd.DataFrame(pivot_data).T
                pivot_df['Total'] = pivot_df.sum(axis=1)

                # Style the dataframe
                def highlight_cells(val):
                    if isinstance(val, (int, float)):
                        if val > 0:
                            return 'background-color: #fff3e0'
                    return ''

                st.dataframe(pivot_df, use_container_width=True)

            st.divider()

            # Detailed aging list
            st.markdown("#### Detailed Open Issues")

            for finding in sorted(open_findings_list, key=lambda x: (x.identified_date)):
                days_open = (today - finding.identified_date).days
                days_to_target = (finding.target_remediation_date - today).days

                # Determine visual indicator
                if days_to_target < 0:
                    indicator_color = '#dc3545'
                    indicator_text = f"OVERDUE by {abs(days_to_target)} days"
                elif days_to_target <= 7:
                    indicator_color = '#ffc107'
                    indicator_text = f"Due in {days_to_target} days"
                else:
                    indicator_color = '#28a745'
                    indicator_text = f"Due in {days_to_target} days"

                sev_colors = {
                    FindingSeverity.CRITICAL: '#dc3545',
                    FindingSeverity.HIGH: '#fd7e14',
                    FindingSeverity.MEDIUM: '#ffc107',
                    FindingSeverity.LOW: '#28a745'
                }

                st.markdown(f"""
                <div style="background-color: #f8f9fa; padding: 1rem; border-radius: 8px; margin-bottom: 0.5rem; border-left: 4px solid {sev_colors.get(finding.severity, '#6c757d')};">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <div>
                            <strong>{finding.finding_id}</strong>: {finding.title}<br>
                            <span style="color: #6c757d; font-size: 0.85rem;">Owner: {finding.process_owner} | Open for {days_open} days</span>
                        </div>
                        <div style="text-align: right;">
                            <span style="background-color: {sev_colors.get(finding.severity, '#6c757d')}; color: white; padding: 0.25rem 0.5rem; border-radius: 15px; font-size: 0.75rem;">{finding.severity.value.upper()}</span>
                            <br>
                            <span style="color: {indicator_color}; font-size: 0.85rem; font-weight: 600;">{indicator_text}</span>
                        </div>
                    </div>
                </div>
                """, unsafe_allow_html=True)

    # =========================================================================
    # TAB 4: REGULATORY EXAMINATION PREPARATION
    # =========================================================================
    with main_tabs[3]:
        st.markdown('<h3 class="section-header">Regulatory Examination Preparation Checklist</h3>', unsafe_allow_html=True)

        st.markdown("""
        <div class="info-box">
            <strong>Preparation Guide</strong><br>
            Use this checklist to ensure readiness for regulatory examinations.
            Track preparation status for common examination areas across crypto regulatory frameworks.
        </div>
        """, unsafe_allow_html=True)

        # Initialize exam prep checklist in session state
        if 'exam_prep_checklist' not in st.session_state:
            st.session_state.exam_prep_checklist = {}

        exam_prep_categories = {
            "Governance & Organization": [
                "Board minutes documenting crypto oversight discussions",
                "Organizational chart showing crypto operations reporting lines",
                "Job descriptions for key crypto personnel",
                "Evidence of Board-approved risk appetite for crypto activities",
                "Committee charters for crypto-related committees"
            ],
            "Policies & Procedures": [
                "Crypto custody policy and procedures",
                "Key management procedures",
                "Transaction approval matrix",
                "AML/BSA program documentation",
                "Incident response procedures",
                "Business continuity and disaster recovery plans"
            ],
            "Risk Management": [
                "Enterprise risk assessment including crypto risks",
                "Crypto-specific risk assessment",
                "Control self-assessment results",
                "Risk register with crypto exposures",
                "Third-party risk assessments for crypto vendors"
            ],
            "Compliance": [
                "Compliance monitoring schedule and results",
                "Training completion records",
                "SAR filing logs and statistics",
                "OFAC screening procedures and evidence",
                "State license compliance documentation"
            ],
            "Operations & Technology": [
                "Wallet inventory and configuration documentation",
                "Multi-signature setup verification",
                "Key ceremony documentation",
                "System access reviews",
                "Change management records",
                "Penetration testing and vulnerability assessment reports"
            ],
            "Financial & Reporting": [
                "Proof of reserves documentation",
                "Reconciliation reports (daily/monthly)",
                "Financial statements with crypto disclosures",
                "Valuation methodology documentation",
                "Customer liability reports"
            ],
            "Internal Audit": [
                "Internal audit plan covering crypto operations",
                "Completed audit reports",
                "Finding tracking and remediation status",
                "Independence documentation",
                "Quality assurance reviews"
            ]
        }

        # Calculate overall preparation progress
        total_items = sum(len(items) for items in exam_prep_categories.values())
        completed_items = sum(1 for k, v in st.session_state.exam_prep_checklist.items() if v.get('status') == 'Complete')
        overall_progress = (completed_items / total_items * 100) if total_items > 0 else 0

        st.progress(overall_progress / 100, text=f"Overall Preparation Progress: {overall_progress:.1f}% ({completed_items}/{total_items} items)")

        st.divider()

        for category, items in exam_prep_categories.items():
            # Calculate category progress
            cat_completed = sum(1 for item in items if st.session_state.exam_prep_checklist.get(f"{category}_{item}", {}).get('status') == 'Complete')
            cat_progress = (cat_completed / len(items) * 100) if items else 0

            with st.expander(f"{category} ({cat_completed}/{len(items)} complete)", expanded=False):
                st.progress(cat_progress / 100)

                for item in items:
                    item_key = f"{category}_{item}"
                    current_status = st.session_state.exam_prep_checklist.get(item_key, {})

                    col1, col2, col3 = st.columns([3, 1, 1])

                    with col1:
                        st.markdown(f"- {item}")

                    with col2:
                        status = st.selectbox(
                            "Status",
                            options=['Not Started', 'In Progress', 'Complete'],
                            index=['Not Started', 'In Progress', 'Complete'].index(current_status.get('status', 'Not Started')),
                            key=f"prep_status_{item_key}",
                            label_visibility="collapsed"
                        )

                    with col3:
                        if status == 'Complete':
                            st.markdown('<span style="color: #28a745;">&#10004; Ready</span>', unsafe_allow_html=True)
                        elif status == 'In Progress':
                            st.markdown('<span style="color: #ffc107;">&#9711; Working</span>', unsafe_allow_html=True)
                        else:
                            st.markdown('<span style="color: #dc3545;">&#10060; Pending</span>', unsafe_allow_html=True)

                    # Update session state
                    st.session_state.exam_prep_checklist[item_key] = {'status': status}

    # =========================================================================
    # TAB 5: REPORTS & EXPORT
    # =========================================================================
    with main_tabs[4]:
        st.markdown('<h3 class="section-header">Compliance Reports & Export</h3>', unsafe_allow_html=True)

        st.markdown("""
        <div class="info-box">
            Generate and download compliance reports for management review, regulatory submissions, or audit documentation.
        </div>
        """, unsafe_allow_html=True)

        report_type = st.selectbox(
            "Select Report Type",
            options=[
                "Compliance Status Summary",
                "Open Findings Report",
                "Aging Analysis Report",
                "Full Compliance Assessment Export",
                "Examination Readiness Report"
            ]
        )

        st.divider()

        if report_type == "Compliance Status Summary":
            st.markdown("#### Compliance Status Summary Report")

            report_data = []
            for reg_key, reg_data in REGULATORY_COMPLIANCE_CHECKLISTS.items():
                for req in reg_data.get('requirements', []):
                    assessment = st.session_state.compliance_items.get(req.requirement_id, {})
                    report_data.append({
                        'Regulation': reg_data.get('regulation_name', reg_key),
                        'Requirement ID': req.requirement_id,
                        'Requirement': req.requirement,
                        'Status': assessment.get('status', 'Not Assessed'),
                        'Last Assessed': str(assessment.get('last_assessed', 'N/A')),
                        'Assessor': assessment.get('assessor', 'N/A'),
                        'Notes': assessment.get('notes', '')
                    })

            report_df = pd.DataFrame(report_data)
            st.dataframe(report_df, use_container_width=True, hide_index=True)

            # Download button
            csv = report_df.to_csv(index=False)
            st.download_button(
                label="Download CSV",
                data=csv,
                file_name=f"compliance_status_{datetime.date.today()}.csv",
                mime="text/csv"
            )

        elif report_type == "Open Findings Report":
            st.markdown("#### Open Findings Report")

            open_findings_data = []
            for finding in st.session_state.audit_findings:
                if finding.status not in [RemediationStatus.CLOSED, RemediationStatus.RISK_ACCEPTED]:
                    days_open = (datetime.date.today() - finding.identified_date).days
                    days_to_target = (finding.target_remediation_date - datetime.date.today()).days

                    open_findings_data.append({
                        'Finding ID': finding.finding_id,
                        'Title': finding.title,
                        'Severity': finding.severity.value.capitalize(),
                        'Status': finding.status.value.replace('_', ' ').title(),
                        'Days Open': days_open,
                        'Days to Target': days_to_target,
                        'Overdue': 'Yes' if days_to_target < 0 else 'No',
                        'Process Owner': finding.process_owner,
                        'Target Date': str(finding.target_remediation_date)
                    })

            if open_findings_data:
                findings_df = pd.DataFrame(open_findings_data)
                st.dataframe(findings_df, use_container_width=True, hide_index=True)

                csv = findings_df.to_csv(index=False)
                st.download_button(
                    label="Download CSV",
                    data=csv,
                    file_name=f"open_findings_{datetime.date.today()}.csv",
                    mime="text/csv"
                )
            else:
                st.success("No open findings to report!")

        elif report_type == "Aging Analysis Report":
            st.markdown("#### Aging Analysis Report")

            aging_data = []
            today = datetime.date.today()

            for finding in st.session_state.audit_findings:
                if finding.status not in [RemediationStatus.CLOSED, RemediationStatus.RISK_ACCEPTED]:
                    days_open = (today - finding.identified_date).days

                    if days_open <= 30:
                        bucket = '0-30 days'
                    elif days_open <= 60:
                        bucket = '31-60 days'
                    elif days_open <= 90:
                        bucket = '61-90 days'
                    elif days_open <= 180:
                        bucket = '91-180 days'
                    else:
                        bucket = '180+ days'

                    aging_data.append({
                        'Finding ID': finding.finding_id,
                        'Title': finding.title,
                        'Severity': finding.severity.value.capitalize(),
                        'Identified Date': str(finding.identified_date),
                        'Days Open': days_open,
                        'Aging Bucket': bucket,
                        'Target Date': str(finding.target_remediation_date),
                        'Process Owner': finding.process_owner
                    })

            if aging_data:
                aging_df = pd.DataFrame(aging_data)
                st.dataframe(aging_df, use_container_width=True, hide_index=True)

                csv = aging_df.to_csv(index=False)
                st.download_button(
                    label="Download CSV",
                    data=csv,
                    file_name=f"aging_analysis_{datetime.date.today()}.csv",
                    mime="text/csv"
                )
            else:
                st.success("No open findings for aging analysis!")

        elif report_type == "Full Compliance Assessment Export":
            st.markdown("#### Full Compliance Assessment Export")
            st.markdown("This export includes all compliance requirements with their current assessment status and notes.")

            full_export = []
            for reg_key, reg_data in REGULATORY_COMPLIANCE_CHECKLISTS.items():
                for req in reg_data.get('requirements', []):
                    assessment = st.session_state.compliance_items.get(req.requirement_id, {})
                    full_export.append({
                        'Regulation Key': reg_key,
                        'Regulation Name': reg_data.get('regulation_name', reg_key),
                        'Authority': reg_data.get('authority', 'N/A'),
                        'Requirement ID': req.requirement_id,
                        'Requirement': req.requirement,
                        'Description': req.description,
                        'Frequency': req.frequency,
                        'Applicability': req.applicability,
                        'Assessment Status': assessment.get('status', 'Not Assessed'),
                        'Last Assessed': str(assessment.get('last_assessed', 'N/A')),
                        'Assessor': assessment.get('assessor', 'N/A'),
                        'Assessment Notes': assessment.get('notes', ''),
                        'Testing Procedures': ' | '.join(req.testing_procedures),
                        'Evidence Required': ' | '.join(req.evidence_required)
                    })

            full_df = pd.DataFrame(full_export)
            st.dataframe(full_df, use_container_width=True, hide_index=True)

            csv = full_df.to_csv(index=False)
            st.download_button(
                label="Download Full Export (CSV)",
                data=csv,
                file_name=f"full_compliance_export_{datetime.date.today()}.csv",
                mime="text/csv"
            )

        elif report_type == "Examination Readiness Report":
            st.markdown("#### Examination Readiness Report")

            prep_data = []
            for category, items in exam_prep_categories.items():
                for item in items:
                    item_key = f"{category}_{item}"
                    status = st.session_state.exam_prep_checklist.get(item_key, {}).get('status', 'Not Started')
                    prep_data.append({
                        'Category': category,
                        'Item': item,
                        'Status': status
                    })

            prep_df = pd.DataFrame(prep_data)
            st.dataframe(prep_df, use_container_width=True, hide_index=True)

            csv = prep_df.to_csv(index=False)
            st.download_button(
                label="Download CSV",
                data=csv,
                file_name=f"exam_readiness_{datetime.date.today()}.csv",
                mime="text/csv"
            )

        st.divider()

        # Quick actions
        st.markdown("#### Quick Actions")

        col1, col2, col3 = st.columns(3)

        with col1:
            if st.button("Reset All Assessments", type="secondary"):
                st.session_state.compliance_items = {}
                st.success("All assessments have been reset.")
                st.rerun()

        with col2:
            if st.button("Clear All Findings", type="secondary"):
                st.session_state.audit_findings = []
                st.success("All findings have been cleared.")
                st.rerun()

        with col3:
            if st.button("Reset Exam Prep Checklist", type="secondary"):
                st.session_state.exam_prep_checklist = {}
                st.success("Examination preparation checklist has been reset.")
                st.rerun()


# =============================================================================
# REPORT GENERATION HELPER FUNCTIONS
# =============================================================================

def generate_executive_summary() -> tuple:
    """Generate an executive summary based on all audit findings and results."""
    engagement = st.session_state.audit_engagement
    risks = st.session_state.identified_risks
    controls = st.session_state.tested_controls
    findings = st.session_state.audit_findings
    reconciliation = st.session_state.reconciliation_results
    analytics = st.session_state.analytics_results
    compliance = st.session_state.compliance_items

    # Count risk ratings
    high_risks = len([r for r in risks if r.get('rating', '').lower() in ['high', 'critical']])
    medium_risks = len([r for r in risks if r.get('rating', '').lower() == 'medium'])
    low_risks = len([r for r in risks if r.get('rating', '').lower() == 'low'])

    # Count control effectiveness
    effective_controls = len([c for c in controls if c.get('rating', '').lower() == 'effective'])
    needs_improvement = len([c for c in controls if c.get('rating', '').lower() == 'needs improvement'])
    ineffective_controls = len([c for c in controls if c.get('rating', '').lower() == 'ineffective'])

    # Count findings by severity - handle both list and dict formats
    if isinstance(findings, list):
        critical_findings = len([f for f in findings if f.get('severity', '').lower() == 'critical'])
        high_findings = len([f for f in findings if f.get('severity', '').lower() == 'high'])
        findings_count = len(findings)
    else:
        critical_findings = 0
        high_findings = 0
        findings_count = 0

    # Handle compliance items (can be dict or list)
    if isinstance(compliance, dict):
        compliance_count = len(compliance)
    else:
        compliance_count = len(compliance) if compliance else 0

    # Determine overall audit opinion
    if critical_findings > 0 or ineffective_controls > 2:
        opinion = "Unsatisfactory"
        opinion_color = "#dc3545"
    elif high_findings > 2 or needs_improvement > 3:
        opinion = "Needs Improvement"
        opinion_color = "#ffc107"
    elif high_risks > 3 or needs_improvement > 1:
        opinion = "Satisfactory with Exceptions"
        opinion_color = "#17a2b8"
    else:
        opinion = "Satisfactory"
        opinion_color = "#28a745"

    summary = f"""
## EXECUTIVE SUMMARY

### Engagement Overview
- **Engagement ID:** {engagement.get('id', 'Not Assigned')}
- **Client:** {engagement.get('client', 'Not Specified')}
- **Lead Auditor:** {engagement.get('auditor', 'Not Specified')}
- **Audit Period:** {engagement.get('start_date', 'N/A')} to {engagement.get('end_date', 'N/A')}
- **Report Date:** {datetime.date.today().strftime('%B %d, %Y')}

### Overall Audit Opinion: **{opinion}**

### Key Statistics
| Area | Count | Status |
|------|-------|--------|
| Risks Identified | {len(risks)} | {high_risks} High/Critical |
| Controls Tested | {len(controls)} | {effective_controls} Effective |
| Audit Findings | {findings_count} | {critical_findings} Critical, {high_findings} High |
| Reconciliations | {len(reconciliation)} | Completed |
| Compliance Items | {compliance_count} | Tracked |

### Key Findings Summary
"""

    # Add top findings
    if isinstance(findings, list) and findings:
        critical_and_high = [f for f in findings if f.get('severity', '').lower() in ['critical', 'high']]
        if critical_and_high:
            summary += "\n**Critical and High Priority Findings:**\n"
            for i, finding in enumerate(critical_and_high[:5], 1):
                summary += f"- {finding.get('title', 'Untitled Finding')} ({finding.get('severity', 'N/A')})\n"
        else:
            summary += "\n*No critical or high priority findings identified.*\n"
    else:
        summary += "\n*No formal findings documented in this engagement.*\n"

    # Add control deficiencies
    deficient_controls = [c for c in controls if c.get('deficiency')]
    if deficient_controls:
        summary += "\n**Control Deficiencies Identified:**\n"
        for ctrl in deficient_controls[:5]:
            deficiency_text = ctrl.get('deficiency', 'N/A')
            if len(deficiency_text) > 100:
                deficiency_text = deficiency_text[:100] + "..."
            summary += f"- {ctrl.get('control_name', 'Unknown Control')}: {deficiency_text}\n"

    summary += f"""

### Recommendations
Based on the audit work performed, management should:
1. Address all critical and high-priority findings within the agreed timeframes
2. Enhance controls rated as 'Needs Improvement' or 'Ineffective'
3. Continue monitoring identified risks with regular reassessment
4. Implement remediation plans for all documented deficiencies

---
*This executive summary was generated on {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*
"""

    return summary, opinion, opinion_color


def generate_full_report(template_type: str = "Full Audit Report") -> str:
    """Generate a complete audit report based on the selected template."""
    engagement = st.session_state.audit_engagement
    risks = st.session_state.identified_risks
    controls = st.session_state.tested_controls
    findings = st.session_state.audit_findings
    reconciliation = st.session_state.reconciliation_results
    analytics = st.session_state.analytics_results
    compliance = st.session_state.compliance_items

    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    report_date = datetime.date.today().strftime('%B %d, %Y')

    # Header section (common to all templates)
    header = f"""
================================================================================
                    CRYPTO INTERNAL AUDIT TOOLKIT
                    {template_type.upper()}
================================================================================

Engagement ID: {engagement.get('id', 'Not Assigned')}
Client: {engagement.get('client', 'Not Specified')}
Lead Auditor: {engagement.get('auditor', 'Not Specified')}
Audit Period: {engagement.get('start_date', 'N/A')} to {engagement.get('end_date', 'N/A')}
Report Generated: {timestamp}
Scope: {engagement.get('scope', 'Not Defined')}

================================================================================
"""

    # Build report sections based on template type
    sections = []

    # SECTION 1: Executive Summary
    if template_type in ["Full Audit Report", "Executive Summary"]:
        exec_summary, opinion, _ = generate_executive_summary()
        sections.append(exec_summary)

    # SECTION 2: Scope and Objectives
    if template_type in ["Full Audit Report", "Executive Summary"]:
        scope_section = f"""
## SCOPE AND OBJECTIVES

### Audit Scope
{engagement.get('scope', 'The scope of this audit engagement has not been formally defined.')}

### Audit Objectives
1. Assess the design and operating effectiveness of internal controls
2. Identify and evaluate risks related to cryptocurrency operations
3. Test compliance with applicable regulations and internal policies
4. Evaluate the accuracy of financial records and wallet reconciliations
5. Provide recommendations for process improvements

### Methodology
This audit was conducted in accordance with the International Standards for the Professional Practice of Internal Auditing (IIA Standards) and utilized:
- Risk-based audit approach aligned with COSO framework
- Statistical sampling for transaction testing
- Blockchain verification for wallet reconciliation
- Control effectiveness testing procedures
"""
        sections.append(scope_section)

    # SECTION 3: Risk Assessment Summary
    if template_type in ["Full Audit Report", "Risk Assessment Report"]:
        risk_section = f"""
## RISK ASSESSMENT SUMMARY

### Risk Overview
Total Risks Identified: {len(risks)}

"""
        if risks:
            # Categorize risks
            risk_by_rating = {}
            for risk in risks:
                rating = risk.get('rating', 'Unrated')
                if rating not in risk_by_rating:
                    risk_by_rating[rating] = []
                risk_by_rating[rating].append(risk)

            for rating in ['Critical', 'High', 'Medium', 'Low']:
                if rating in risk_by_rating:
                    risk_section += f"\n### {rating} Risks ({len(risk_by_rating[rating])})\n"
                    for risk in risk_by_rating[rating]:
                        risk_section += f"""
**{risk.get('name', 'Unnamed Risk')}**
- Category: {risk.get('category', 'N/A')}
- Likelihood: {risk.get('likelihood', 'N/A')}/5
- Impact: {risk.get('impact', 'N/A')}/5
- Risk Score: {risk.get('risk_score', 'N/A')}
- Owner: {risk.get('owner', 'Not Assigned')}
- Status: {risk.get('status', 'Open')}
- Description: {risk.get('description', 'No description provided.')}
"""
        else:
            risk_section += "*No risks have been formally identified in this engagement.*\n"

        sections.append(risk_section)

    # SECTION 4: Control Testing Results
    if template_type in ["Full Audit Report", "Control Testing Report"]:
        control_section = f"""
## CONTROL TESTING RESULTS

### Controls Tested: {len(controls)}
"""
        if controls:
            # Summarize by rating
            ratings = {}
            for ctrl in controls:
                rating = ctrl.get('rating', 'Not Rated')
                ratings[rating] = ratings.get(rating, 0) + 1

            control_section += "\n### Rating Summary\n"
            for rating, count in ratings.items():
                control_section += f"- {rating}: {count} controls\n"

            control_section += "\n### Control Details\n"
            for ctrl in controls:
                control_section += f"""
**{ctrl.get('control_id', 'N/A')}: {ctrl.get('control_name', 'Unnamed Control')}**
- Category: {ctrl.get('category', 'N/A')}
- Test Date: {ctrl.get('test_date', 'N/A')}
- Tested By: {ctrl.get('tester', 'N/A')}
- Rating: {ctrl.get('rating', 'Not Rated')}
- Effectiveness Score: {ctrl.get('effectiveness_score', 0) * 100:.0f}%
- Observations: {ctrl.get('observations', 'None documented.')}
- Evidence: {ctrl.get('evidence', 'None documented.')}
"""
                if ctrl.get('deficiency'):
                    control_section += f"- **DEFICIENCY NOTED:** {ctrl.get('deficiency')}\n"

                if ctrl.get('test_results'):
                    control_section += "- Test Results:\n"
                    for test in ctrl['test_results']:
                        status = "PASS" if test.get('passed') else "FAIL"
                        control_section += f"  - [{status}] {test.get('test', 'Unnamed test')}\n"
        else:
            control_section += "*No controls have been tested in this engagement.*\n"

        sections.append(control_section)

    # SECTION 5: Data Analytics Findings
    if template_type in ["Full Audit Report"]:
        analytics_section = """
## DATA ANALYTICS FINDINGS

### Analytics Overview
"""
        if analytics.get('statistics'):
            stats = analytics['statistics']
            analytics_section += f"""
### Statistical Summary
- Population analyzed with data analytics procedures
- Sampling methods applied: Random, Stratified, and/or Monetary Unit Sampling
"""

        if analytics.get('anomalies'):
            analytics_section += f"\n### Anomalies Detected: {len(analytics['anomalies'])}\n"
            for i, anomaly in enumerate(analytics['anomalies'][:10], 1):
                analytics_section += f"{i}. {anomaly}\n"

        if analytics.get('samples'):
            analytics_section += f"\n### Samples Selected: {len(analytics['samples'])}\n"
            analytics_section += "Sample transactions were selected and tested per audit procedures.\n"

        if analytics.get('benford_analysis'):
            analytics_section += "\n### Benford's Law Analysis\n"
            analytics_section += "Benford's Law analysis was performed on transaction amounts.\n"

        if not any([analytics.get('statistics'), analytics.get('anomalies'), analytics.get('samples')]):
            analytics_section += "*No data analytics procedures have been performed in this engagement.*\n"

        sections.append(analytics_section)

    # SECTION 6: Wallet Reconciliation Results
    if template_type in ["Full Audit Report"]:
        recon_section = f"""
## WALLET RECONCILIATION RESULTS

### Reconciliations Performed: {len(reconciliation)}
"""
        if reconciliation:
            recon_section += "\n| Wallet ID | Crypto | Recorded Balance | Blockchain Balance | Variance | Status |\n"
            recon_section += "|-----------|--------|------------------|-------------------|----------|--------|\n"
            for recon in reconciliation:
                variance = recon.get('variance', 0)
                status = "Reconciled" if abs(variance) < 0.0001 else "Variance Noted"
                recon_section += f"| {recon.get('wallet_id', 'N/A')} | {recon.get('crypto', 'N/A')} | {recon.get('recorded_balance', 0):.8f} | {recon.get('blockchain_balance', 0):.8f} | {variance:.8f} | {status} |\n"
        else:
            recon_section += "*No wallet reconciliations have been performed in this engagement.*\n"

        sections.append(recon_section)

    # SECTION 7: Compliance Status
    if template_type in ["Full Audit Report"]:
        # Handle compliance as dict or list
        if isinstance(compliance, dict):
            compliance_count = len(compliance)
            compliant = len([c for c in compliance.values() if c.get('status', '').lower() == 'compliant'])
            non_compliant = len([c for c in compliance.values() if c.get('status', '').lower() == 'non-compliant'])
            in_progress = len([c for c in compliance.values() if c.get('status', '').lower() in ['partial', 'in progress']])
        else:
            compliance_count = len(compliance) if compliance else 0
            compliant = len([c for c in compliance if c.get('status', '').lower() == 'compliant']) if compliance else 0
            non_compliant = len([c for c in compliance if c.get('status', '').lower() == 'non-compliant']) if compliance else 0
            in_progress = len([c for c in compliance if c.get('status', '').lower() in ['partial', 'in progress']]) if compliance else 0

        compliance_section = f"""
## COMPLIANCE STATUS

### Compliance Items Tracked: {compliance_count}
"""
        if compliance_count > 0:
            compliance_section += f"""
### Summary
- Compliant: {compliant}
- Non-Compliant: {non_compliant}
- In Progress/Partial: {in_progress}

### Details
"""
            if isinstance(compliance, dict):
                for req_id, item in list(compliance.items())[:20]:
                    compliance_section += f"- **{req_id}**: {item.get('status', 'Unknown')} - {item.get('notes', 'No notes')}\n"
            else:
                for item in compliance[:20]:
                    compliance_section += f"- **{item.get('requirement', 'Unknown')}**: {item.get('status', 'Unknown')} - {item.get('notes', 'No notes')}\n"
        else:
            compliance_section += "*No compliance items have been tracked in this engagement.*\n"

        sections.append(compliance_section)

    # SECTION 8: Findings Only (for Findings Only template)
    if template_type == "Findings Only":
        # Handle findings as list
        findings_list = findings if isinstance(findings, list) else []
        findings_section = f"""
## AUDIT FINDINGS

### Total Findings: {len(findings_list)}
"""
        if findings_list:
            for i, finding in enumerate(findings_list, 1):
                findings_section += f"""
### Finding {i}: {finding.get('title', 'Untitled Finding')}
- **Severity:** {finding.get('severity', 'Not Rated')}
- **Category:** {finding.get('category', 'N/A')}
- **Status:** {finding.get('status', 'Open')}
- **Risk Rating:** {finding.get('risk_rating', 'N/A')}

**Condition:**
{finding.get('condition', 'Not documented.')}

**Criteria:**
{finding.get('criteria', 'Not documented.')}

**Cause:**
{finding.get('cause', 'Not documented.')}

**Effect:**
{finding.get('effect', 'Not documented.')}

**Recommendation:**
{finding.get('recommendation', 'Not documented.')}

**Management Response:**
{finding.get('management_response', 'Pending management response.')}

**Target Remediation Date:** {finding.get('target_date', 'Not set')}
---
"""
        else:
            findings_section += "*No formal findings have been documented in this engagement.*\n"

        sections.append(findings_section)

    # SECTION 9: Conclusions and Recommendations
    if template_type in ["Full Audit Report", "Executive Summary"]:
        conclusion_section = """
## CONCLUSIONS AND RECOMMENDATIONS

### Overall Conclusion
Based on the audit procedures performed, the internal control environment over cryptocurrency operations
has been assessed. Areas requiring management attention have been documented in this report.

### Key Recommendations
1. Address all critical and high-priority findings within agreed-upon timeframes
2. Strengthen controls identified as needing improvement
3. Continue regular monitoring of identified risks
4. Maintain documentation to support control effectiveness
5. Conduct periodic reassessment of the risk environment

### Follow-Up Actions
- Management action plans due within 30 days of report issuance
- Follow-up testing to be scheduled based on finding severity
- Quarterly status updates required for critical findings
"""
        sections.append(conclusion_section)

    # Footer
    footer = f"""

================================================================================
                            REPORT FOOTER
================================================================================

Report Generated: {timestamp}
Engagement Status: {engagement.get('status', 'In Progress')}

CONFIDENTIALITY NOTICE:
This audit report contains confidential information intended only for the use
of authorized personnel. Unauthorized distribution is prohibited.

--------------------------------------------------------------------------------
Co-Authored-By: Claude AI Assistant
This report was generated with AI assistance using the Crypto Internal Audit
Toolkit. All findings and recommendations should be reviewed and validated
by qualified audit professionals before distribution.
--------------------------------------------------------------------------------

================================================================================
                    END OF {template_type.upper()}
================================================================================
"""

    # Combine all sections
    full_report = header + "\n".join(sections) + footer
    return full_report


def generate_workpaper_index() -> str:
    """Generate an index of all workpapers created during the audit."""
    engagement = st.session_state.audit_engagement
    risks = st.session_state.identified_risks
    controls = st.session_state.tested_controls
    findings = st.session_state.audit_findings
    reconciliation = st.session_state.reconciliation_results
    analytics = st.session_state.analytics_results
    compliance = st.session_state.compliance_items

    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # Handle compliance and findings as dict or list
    compliance_count = len(compliance) if isinstance(compliance, (dict, list)) else 0
    findings_count = len(findings) if isinstance(findings, list) else 0

    index = f"""
================================================================================
                    WORKPAPER INDEX
================================================================================

Engagement ID: {engagement.get('id', 'Not Assigned')}
Client: {engagement.get('client', 'Not Specified')}
Index Generated: {timestamp}

================================================================================

## A. PLANNING WORKPAPERS

| Ref # | Description | Status | Preparer |
|-------|-------------|--------|----------|
| A-1 | Engagement Letter | Complete | {engagement.get('auditor', 'N/A')} |
| A-2 | Audit Planning Memo | Complete | {engagement.get('auditor', 'N/A')} |
| A-3 | Risk Assessment Summary | {'Complete' if risks else 'Pending'} | {engagement.get('auditor', 'N/A')} |
| A-4 | Audit Program | Complete | {engagement.get('auditor', 'N/A')} |

## B. RISK ASSESSMENT WORKPAPERS

| Ref # | Description | Count | Status |
|-------|-------------|-------|--------|
| B-1 | Risk Universe Documentation | {len(risks)} risks | {'Complete' if risks else 'Pending'} |
| B-2 | Risk Scoring Matrix | N/A | {'Complete' if risks else 'Pending'} |
| B-3 | Risk Heat Map | N/A | {'Complete' if risks else 'Pending'} |
"""

    # Add individual risk workpapers
    if risks:
        index += "\n### Individual Risk Workpapers:\n"
        for i, risk in enumerate(risks, 1):
            index += f"| B-1.{i} | {risk.get('name', 'Unnamed Risk')[:40]} | Score: {risk.get('risk_score', 'N/A')} | Documented |\n"

    index += f"""
## C. CONTROL TESTING WORKPAPERS

| Ref # | Description | Count | Status |
|-------|-------------|-------|--------|
| C-1 | Control Library | {len(controls)} controls | {'Complete' if controls else 'Pending'} |
| C-2 | Control Testing Summary | N/A | {'Complete' if controls else 'Pending'} |
| C-3 | Control Deficiency Log | N/A | {'Complete' if controls else 'Pending'} |
"""

    # Add individual control workpapers
    if controls:
        index += "\n### Individual Control Test Workpapers:\n"
        for i, ctrl in enumerate(controls, 1):
            index += f"| C-1.{i} | {ctrl.get('control_id', 'N/A')}: {ctrl.get('control_name', 'Unnamed')[:30]} | {ctrl.get('rating', 'N/A')} | Tested |\n"

    index += f"""
## D. DATA ANALYTICS WORKPAPERS

| Ref # | Description | Details | Status |
|-------|-------------|---------|--------|
| D-1 | Transaction Population | {len(analytics.get('samples', []))} samples | {'Complete' if analytics.get('samples') else 'Pending'} |
| D-2 | Anomaly Detection Results | {len(analytics.get('anomalies', []))} anomalies | {'Complete' if analytics.get('anomalies') else 'Pending'} |
| D-3 | Benford's Law Analysis | N/A | {'Complete' if analytics.get('benford_analysis') else 'Pending'} |
| D-4 | Statistical Analysis | N/A | {'Complete' if analytics.get('statistics') else 'Pending'} |

## E. WALLET RECONCILIATION WORKPAPERS

| Ref # | Description | Count | Status |
|-------|-------------|-------|--------|
| E-1 | Wallet Inventory | {len(reconciliation)} wallets | {'Complete' if reconciliation else 'Pending'} |
| E-2 | Reconciliation Summary | N/A | {'Complete' if reconciliation else 'Pending'} |
| E-3 | Variance Analysis | N/A | {'Complete' if reconciliation else 'Pending'} |
"""

    # Add individual reconciliation workpapers
    if reconciliation:
        index += "\n### Individual Reconciliation Workpapers:\n"
        for i, recon in enumerate(reconciliation, 1):
            index += f"| E-1.{i} | {recon.get('wallet_id', 'N/A')} Reconciliation | {recon.get('crypto', 'N/A')} | Reconciled |\n"

    index += f"""
## F. COMPLIANCE WORKPAPERS

| Ref # | Description | Count | Status |
|-------|-------------|-------|--------|
| F-1 | Compliance Checklist | {compliance_count} items | {'Complete' if compliance_count > 0 else 'Pending'} |
| F-2 | Regulatory Requirements Matrix | N/A | {'Complete' if compliance_count > 0 else 'Pending'} |
| F-3 | Policy Compliance Testing | N/A | {'Complete' if compliance_count > 0 else 'Pending'} |

## G. FINDINGS AND REPORTING WORKPAPERS

| Ref # | Description | Count | Status |
|-------|-------------|-------|--------|
| G-1 | Findings Summary | {findings_count} findings | {'Complete' if findings_count > 0 else 'Pending'} |
| G-2 | Draft Audit Report | N/A | In Progress |
| G-3 | Management Responses | N/A | Pending |
| G-4 | Final Audit Report | N/A | Pending |
"""

    # Add individual findings workpapers
    if isinstance(findings, list) and findings:
        index += "\n### Individual Finding Workpapers:\n"
        for i, finding in enumerate(findings, 1):
            index += f"| G-1.{i} | {finding.get('title', 'Untitled')[:40]} | {finding.get('severity', 'N/A')} | Documented |\n"

    total_workpapers = len(risks) + len(controls) + len(reconciliation) + compliance_count + findings_count + 15

    index += f"""

================================================================================
                    WORKPAPER SUMMARY
================================================================================

Total Workpapers: {total_workpapers}
- Planning: 4
- Risk Assessment: {len(risks) + 3}
- Control Testing: {len(controls) + 3}
- Data Analytics: 4
- Wallet Reconciliation: {len(reconciliation) + 3}
- Compliance: 3
- Findings & Reporting: {findings_count + 4}

================================================================================
Index Generated: {timestamp}
Co-Authored-By: Claude AI Assistant
================================================================================
"""

    return index


def generate_audit_trail() -> list:
    """Generate an audit trail of all activities performed."""
    engagement = st.session_state.audit_engagement
    risks = st.session_state.identified_risks
    controls = st.session_state.tested_controls
    findings = st.session_state.audit_findings
    reconciliation = st.session_state.reconciliation_results
    compliance = st.session_state.compliance_items

    audit_trail = []

    # Engagement start
    if engagement.get('id'):
        audit_trail.append({
            'timestamp': engagement.get('start_date', datetime.date.today()),
            'activity': 'Engagement Initiated',
            'category': 'Planning',
            'details': f"Engagement {engagement.get('id')} created for {engagement.get('client', 'Unknown Client')}",
            'user': engagement.get('auditor', 'System')
        })

    # Risk identification activities
    for risk in risks:
        audit_trail.append({
            'timestamp': risk.get('identified_date', datetime.date.today()),
            'activity': 'Risk Identified',
            'category': 'Risk Assessment',
            'details': f"Risk '{risk.get('name', 'Unknown')}' identified with rating: {risk.get('rating', 'N/A')}",
            'user': risk.get('identified_by', engagement.get('auditor', 'Unknown'))
        })

    # Control testing activities
    for ctrl in controls:
        audit_trail.append({
            'timestamp': ctrl.get('test_date', datetime.date.today()),
            'activity': 'Control Tested',
            'category': 'Control Testing',
            'details': f"Control '{ctrl.get('control_name', 'Unknown')}' tested with result: {ctrl.get('rating', 'N/A')}",
            'user': ctrl.get('tester', engagement.get('auditor', 'Unknown'))
        })

    # Reconciliation activities
    for recon in reconciliation:
        audit_trail.append({
            'timestamp': recon.get('recon_date', datetime.date.today()),
            'activity': 'Wallet Reconciliation',
            'category': 'Reconciliation',
            'details': f"Wallet '{recon.get('wallet_id', 'Unknown')}' reconciled for {recon.get('crypto', 'N/A')}",
            'user': engagement.get('auditor', 'Unknown')
        })

    # Finding documentation
    if isinstance(findings, list):
        for finding in findings:
            audit_trail.append({
                'timestamp': finding.get('identified_date', datetime.date.today()),
                'activity': 'Finding Documented',
                'category': 'Findings',
                'details': f"Finding '{finding.get('title', 'Unknown')}' documented with severity: {finding.get('severity', 'N/A')}",
                'user': finding.get('author', engagement.get('auditor', 'Unknown'))
            })

    # Compliance tracking
    if isinstance(compliance, dict):
        for req_id, item in compliance.items():
            audit_trail.append({
                'timestamp': item.get('last_assessed', datetime.date.today()),
                'activity': 'Compliance Item Assessed',
                'category': 'Compliance',
                'details': f"Compliance item '{req_id}' assessed as: {item.get('status', 'N/A')}",
                'user': item.get('assessor', engagement.get('auditor', 'Unknown'))
            })
    elif isinstance(compliance, list):
        for item in compliance:
            audit_trail.append({
                'timestamp': item.get('assessed_date', datetime.date.today()),
                'activity': 'Compliance Item Assessed',
                'category': 'Compliance',
                'details': f"Compliance item '{item.get('requirement', 'Unknown')}' assessed as: {item.get('status', 'N/A')}",
                'user': engagement.get('auditor', 'Unknown')
            })

    # Sort by timestamp
    audit_trail.sort(key=lambda x: str(x.get('timestamp', '')), reverse=True)

    return audit_trail


def render_report_generation():
    """Render the Report Generation section with full functionality."""

    # Page Header
    st.markdown('<h1 class="main-header">Report Generation</h1>', unsafe_allow_html=True)
    st.markdown(
        '<p class="sub-header">Professional audit report creation, workpaper documentation, and export capabilities</p>',
        unsafe_allow_html=True
    )

    # Get engagement info for display
    engagement = st.session_state.audit_engagement

    # Display engagement summary at the top
    if engagement.get('id'):
        st.markdown(f"""
        <div class="info-box">
            <strong>Current Engagement:</strong> {engagement.get('id', 'Not Set')} |
            <strong>Client:</strong> {engagement.get('client', 'Not Set')} |
            <strong>Auditor:</strong> {engagement.get('auditor', 'Not Set')} |
            <strong>Status:</strong> {engagement.get('status', 'In Progress')}
        </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown("""
        <div class="warning-box">
            <strong>Note:</strong> No engagement has been set up yet. Please configure engagement details on the Home page
            for complete report generation. Reports can still be generated with available data.
        </div>
        """, unsafe_allow_html=True)

    # Handle compliance and findings counts (can be dict or list)
    compliance = st.session_state.compliance_items
    findings = st.session_state.audit_findings
    compliance_count = len(compliance) if isinstance(compliance, (dict, list)) else 0
    findings_count = len(findings) if isinstance(findings, list) else 0

    # Quick Stats Row
    col1, col2, col3, col4, col5 = st.columns(5)

    with col1:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value">{len(st.session_state.identified_risks)}</div>
            <div class="metric-label">Risks Identified</div>
        </div>
        """, unsafe_allow_html=True)

    with col2:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value">{len(st.session_state.tested_controls)}</div>
            <div class="metric-label">Controls Tested</div>
        </div>
        """, unsafe_allow_html=True)

    with col3:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value">{findings_count}</div>
            <div class="metric-label">Findings</div>
        </div>
        """, unsafe_allow_html=True)

    with col4:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value">{len(st.session_state.reconciliation_results)}</div>
            <div class="metric-label">Reconciliations</div>
        </div>
        """, unsafe_allow_html=True)

    with col5:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value">{compliance_count}</div>
            <div class="metric-label">Compliance Items</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("---")

    # Main tabs for report generation
    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "Report Builder",
        "Report Preview",
        "Workpaper Index",
        "Audit Trail",
        "Export Center"
    ])

    # ==========================================================================
    # TAB 1: REPORT BUILDER
    # ==========================================================================
    with tab1:
        st.markdown('<h2 class="section-header">Report Builder</h2>', unsafe_allow_html=True)

        col1, col2 = st.columns([1, 2])

        with col1:
            st.markdown("### Report Template")

            template_options = [
                "Full Audit Report",
                "Executive Summary",
                "Findings Only",
                "Risk Assessment Report",
                "Control Testing Report"
            ]

            selected_template = st.selectbox(
                "Select Report Template",
                options=template_options,
                help="Choose the type of report to generate"
            )

            # Template descriptions
            template_descriptions = {
                "Full Audit Report": "Comprehensive report including all sections: executive summary, scope, risks, controls, analytics, reconciliation, compliance, and conclusions.",
                "Executive Summary": "High-level summary for management with key findings, statistics, and recommendations.",
                "Findings Only": "Detailed documentation of all audit findings with condition, criteria, cause, effect, and recommendations.",
                "Risk Assessment Report": "Focused report on identified risks, risk scoring, and risk mitigation status.",
                "Control Testing Report": "Detailed report on control testing procedures, results, and deficiencies identified."
            }

            st.markdown(f"""
            <div class="audit-card">
                <h4>Template Description</h4>
                <p style="font-size: 0.9rem; color: #5A6C7D;">
                    {template_descriptions.get(selected_template, '')}
                </p>
            </div>
            """, unsafe_allow_html=True)

            # Report customization options
            st.markdown("### Report Options")

            include_appendices = st.checkbox("Include Appendices", value=True)
            include_charts = st.checkbox("Include Charts/Visuals Description", value=True)
            include_mgmt_responses = st.checkbox("Include Management Response Sections", value=True)
            confidential_marking = st.checkbox("Mark as Confidential", value=True)

        with col2:
            st.markdown("### Data Sources Summary")

            # Show what data is available for the report
            data_sources = [
                {
                    "source": "Audit Engagement",
                    "status": "Configured" if engagement.get('id') else "Not Set",
                    "items": 1 if engagement.get('id') else 0,
                    "icon": "check" if engagement.get('id') else "warning"
                },
                {
                    "source": "Identified Risks",
                    "status": f"{len(st.session_state.identified_risks)} risks",
                    "items": len(st.session_state.identified_risks),
                    "icon": "check" if st.session_state.identified_risks else "info"
                },
                {
                    "source": "Tested Controls",
                    "status": f"{len(st.session_state.tested_controls)} controls",
                    "items": len(st.session_state.tested_controls),
                    "icon": "check" if st.session_state.tested_controls else "info"
                },
                {
                    "source": "Analytics Results",
                    "status": "Available" if st.session_state.analytics_results.get('samples') else "No data",
                    "items": len(st.session_state.analytics_results.get('samples', [])),
                    "icon": "check" if st.session_state.analytics_results.get('samples') else "info"
                },
                {
                    "source": "Reconciliation Results",
                    "status": f"{len(st.session_state.reconciliation_results)} reconciliations",
                    "items": len(st.session_state.reconciliation_results),
                    "icon": "check" if st.session_state.reconciliation_results else "info"
                },
                {
                    "source": "Compliance Items",
                    "status": f"{compliance_count} items",
                    "items": compliance_count,
                    "icon": "check" if compliance_count > 0 else "info"
                },
                {
                    "source": "Audit Findings",
                    "status": f"{findings_count} findings",
                    "items": findings_count,
                    "icon": "check" if findings_count > 0 else "info"
                }
            ]

            for source in data_sources:
                icon_color = "#28a745" if source['icon'] == 'check' else ("#ffc107" if source['icon'] == 'warning' else "#17a2b8")
                st.markdown(f"""
                <div class="capability-item" style="display: flex; justify-content: space-between; align-items: center;">
                    <span><strong>{source['source']}</strong></span>
                    <span style="color: {icon_color};">{source['status']}</span>
                </div>
                """, unsafe_allow_html=True)

            # Generate report button
            st.markdown("---")

            if st.button("Generate Report", type="primary", use_container_width=True):
                with st.spinner("Generating report..."):
                    # Store the generated report in session state
                    st.session_state.generated_report = generate_full_report(selected_template)
                    st.session_state.selected_template = selected_template
                    st.success(f"{selected_template} generated successfully! View it in the Report Preview tab.")

    # ==========================================================================
    # TAB 2: REPORT PREVIEW
    # ==========================================================================
    with tab2:
        st.markdown('<h2 class="section-header">Report Preview</h2>', unsafe_allow_html=True)

        # Check if a report has been generated
        if 'generated_report' in st.session_state and st.session_state.generated_report:
            # Display report metadata
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Report Type", st.session_state.get('selected_template', 'Full Audit Report'))
            with col2:
                st.metric("Generated", datetime.datetime.now().strftime('%Y-%m-%d %H:%M'))
            with col3:
                report_length = len(st.session_state.generated_report)
                st.metric("Report Length", f"{report_length:,} characters")

            st.markdown("---")

            # Create sub-tabs for different views
            preview_tab1, preview_tab2 = st.tabs(["Formatted View", "Raw Text"])

            with preview_tab1:
                # Parse and display the report in sections
                report_content = st.session_state.generated_report

                # Display the executive summary with special formatting
                exec_summary, opinion, opinion_color = generate_executive_summary()

                # Opinion banner
                st.markdown(f"""
                <div style="background-color: {opinion_color}; color: white; padding: 1rem; border-radius: 8px; text-align: center; margin-bottom: 1rem;">
                    <h3 style="margin: 0; color: white;">Overall Audit Opinion: {opinion}</h3>
                </div>
                """, unsafe_allow_html=True)

                # Display formatted report sections
                st.markdown(exec_summary)

                with st.expander("View Full Report Content", expanded=False):
                    st.text(report_content)

            with preview_tab2:
                st.text_area(
                    "Raw Report Content",
                    value=st.session_state.generated_report,
                    height=600,
                    disabled=True
                )

        else:
            st.markdown("""
            <div class="info-box">
                <strong>No Report Generated Yet</strong><br>
                Please use the Report Builder tab to generate a report first.
            </div>
            """, unsafe_allow_html=True)

            # Quick generate option
            st.markdown("### Quick Generate")
            quick_template = st.selectbox(
                "Select Template for Quick Generate",
                options=["Full Audit Report", "Executive Summary", "Findings Only", "Risk Assessment Report", "Control Testing Report"],
                key="quick_template"
            )

            if st.button("Quick Generate Report", type="secondary"):
                with st.spinner("Generating report..."):
                    st.session_state.generated_report = generate_full_report(quick_template)
                    st.session_state.selected_template = quick_template
                    st.rerun()

    # ==========================================================================
    # TAB 3: WORKPAPER INDEX
    # ==========================================================================
    with tab3:
        st.markdown('<h2 class="section-header">Workpaper Index</h2>', unsafe_allow_html=True)

        st.markdown("""
        <div class="info-box">
            <strong>About the Workpaper Index:</strong> This index provides a comprehensive listing of all workpapers
            created during the audit engagement. Each workpaper is assigned a reference number for easy tracking
            and cross-referencing within the audit documentation.
        </div>
        """, unsafe_allow_html=True)

        # Generate workpaper index
        workpaper_index = generate_workpaper_index()

        # Display statistics
        col1, col2, col3, col4 = st.columns(4)

        total_workpapers = (
            len(st.session_state.identified_risks) +
            len(st.session_state.tested_controls) +
            len(st.session_state.reconciliation_results) +
            compliance_count +
            findings_count + 15
        )

        with col1:
            st.metric("Total Workpapers", total_workpapers)
        with col2:
            st.metric("Planning", "4")
        with col3:
            complete_count = sum([
                1 if st.session_state.identified_risks else 0,
                1 if st.session_state.tested_controls else 0,
                1 if st.session_state.reconciliation_results else 0,
                1 if compliance_count > 0 else 0,
                1 if findings_count > 0 else 0
            ])
            st.metric("Sections Complete", f"{complete_count}/5")
        with col4:
            pending = 5 - complete_count
            st.metric("Sections Pending", pending)

        st.markdown("---")

        # Display index in expandable sections
        index_sections = {
            "A. Planning Workpapers": f"""
| Ref # | Description | Status |
|-------|-------------|--------|
| A-1 | Engagement Letter | Complete |
| A-2 | Audit Planning Memo | Complete |
| A-3 | Risk Assessment Summary | {'Complete' if st.session_state.identified_risks else 'Pending'} |
| A-4 | Audit Program | Complete |
""",
            "B. Risk Assessment Workpapers": f"Risk workpapers: {len(st.session_state.identified_risks)} items documented",
            "C. Control Testing Workpapers": f"Control workpapers: {len(st.session_state.tested_controls)} tests documented",
            "D. Data Analytics Workpapers": f"Analytics workpapers: {len(st.session_state.analytics_results.get('samples', []))} samples documented",
            "E. Reconciliation Workpapers": f"Reconciliation workpapers: {len(st.session_state.reconciliation_results)} reconciliations documented",
            "F. Compliance Workpapers": f"Compliance workpapers: {compliance_count} items documented",
            "G. Findings & Reporting": f"Findings workpapers: {findings_count} findings documented"
        }

        for section_title, section_content in index_sections.items():
            with st.expander(section_title, expanded=False):
                st.markdown(section_content)

        # Full index view
        with st.expander("View Complete Workpaper Index", expanded=False):
            st.text(workpaper_index)

        # Download button for workpaper index
        st.download_button(
            label="Download Workpaper Index (TXT)",
            data=workpaper_index,
            file_name=f"workpaper_index_{engagement.get('id', 'audit')}_{datetime.date.today().strftime('%Y%m%d')}.txt",
            mime="text/plain",
            use_container_width=True
        )

    # ==========================================================================
    # TAB 4: AUDIT TRAIL
    # ==========================================================================
    with tab4:
        st.markdown('<h2 class="section-header">Audit Trail</h2>', unsafe_allow_html=True)

        st.markdown("""
        <div class="info-box">
            <strong>Audit Trail Documentation:</strong> This section provides a chronological record of all
            audit activities performed during the engagement. The audit trail supports quality assurance
            and provides evidence of work performed.
        </div>
        """, unsafe_allow_html=True)

        # Generate audit trail
        audit_trail = generate_audit_trail()

        # Summary metrics
        col1, col2, col3, col4 = st.columns(4)

        with col1:
            st.metric("Total Activities", len(audit_trail))
        with col2:
            risk_activities = len([a for a in audit_trail if a['category'] == 'Risk Assessment'])
            st.metric("Risk Activities", risk_activities)
        with col3:
            control_activities = len([a for a in audit_trail if a['category'] == 'Control Testing'])
            st.metric("Control Activities", control_activities)
        with col4:
            finding_activities = len([a for a in audit_trail if a['category'] == 'Findings'])
            st.metric("Finding Activities", finding_activities)

        st.markdown("---")

        # Filter options
        col1, col2 = st.columns(2)
        with col1:
            category_filter = st.multiselect(
                "Filter by Category",
                options=['Planning', 'Risk Assessment', 'Control Testing', 'Reconciliation', 'Findings', 'Compliance'],
                default=['Planning', 'Risk Assessment', 'Control Testing', 'Reconciliation', 'Findings', 'Compliance']
            )
        with col2:
            sort_order = st.selectbox("Sort Order", options=["Newest First", "Oldest First"])

        # Filter and sort audit trail
        filtered_trail = [a for a in audit_trail if a['category'] in category_filter]
        if sort_order == "Oldest First":
            filtered_trail.reverse()

        # Display audit trail
        if filtered_trail:
            st.markdown("### Activity Timeline")

            for activity in filtered_trail:
                category_colors = {
                    'Planning': '#1E3A5F',
                    'Risk Assessment': '#dc3545',
                    'Control Testing': '#28a745',
                    'Reconciliation': '#17a2b8',
                    'Findings': '#fd7e14',
                    'Compliance': '#6f42c1'
                }

                color = category_colors.get(activity['category'], '#6c757d')

                st.markdown(f"""
                <div class="audit-card" style="border-left-color: {color};">
                    <div style="display: flex; justify-content: space-between; align-items: flex-start;">
                        <div>
                            <strong style="color: {color};">{activity['activity']}</strong>
                            <span style="background-color: {color}; color: white; padding: 2px 8px; border-radius: 12px; font-size: 0.75rem; margin-left: 10px;">
                                {activity['category']}
                            </span>
                        </div>
                        <span style="color: #6c757d; font-size: 0.85rem;">{activity['timestamp']}</span>
                    </div>
                    <p style="margin: 0.5rem 0 0 0; color: #5A6C7D; font-size: 0.9rem;">{activity['details']}</p>
                    <p style="margin: 0.25rem 0 0 0; color: #888; font-size: 0.8rem;">Performed by: {activity['user']}</p>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.markdown("""
            <div class="info-box">
                No activities recorded yet. Activities will appear here as you work through the audit engagement.
            </div>
            """, unsafe_allow_html=True)

        # Export audit trail
        if audit_trail:
            # Convert to DataFrame for export
            trail_df = pd.DataFrame(audit_trail)

            st.markdown("---")
            st.markdown("### Export Audit Trail")

            col1, col2 = st.columns(2)

            with col1:
                # CSV export
                csv_data = trail_df.to_csv(index=False)
                st.download_button(
                    label="Download Audit Trail (CSV)",
                    data=csv_data,
                    file_name=f"audit_trail_{engagement.get('id', 'audit')}_{datetime.date.today().strftime('%Y%m%d')}.csv",
                    mime="text/csv",
                    use_container_width=True
                )

            with col2:
                # Text export
                trail_text = "AUDIT TRAIL DOCUMENTATION\n"
                trail_text += f"Engagement: {engagement.get('id', 'Not Set')}\n"
                trail_text += f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
                trail_text += "=" * 80 + "\n\n"

                for activity in audit_trail:
                    trail_text += f"[{activity['timestamp']}] {activity['activity']}\n"
                    trail_text += f"Category: {activity['category']}\n"
                    trail_text += f"Details: {activity['details']}\n"
                    trail_text += f"User: {activity['user']}\n"
                    trail_text += "-" * 40 + "\n"

                st.download_button(
                    label="Download Audit Trail (TXT)",
                    data=trail_text,
                    file_name=f"audit_trail_{engagement.get('id', 'audit')}_{datetime.date.today().strftime('%Y%m%d')}.txt",
                    mime="text/plain",
                    use_container_width=True
                )

    # ==========================================================================
    # TAB 5: EXPORT CENTER
    # ==========================================================================
    with tab5:
        st.markdown('<h2 class="section-header">Export Center</h2>', unsafe_allow_html=True)

        st.markdown("""
        <div class="info-box">
            <strong>Export Your Audit Work:</strong> Download reports, workpapers, and data in various formats.
            All exports include timestamps and engagement information for proper documentation.
        </div>
        """, unsafe_allow_html=True)

        # Export options in columns
        col1, col2 = st.columns(2)

        with col1:
            st.markdown("### Report Exports")

            # Full Report Export
            st.markdown("#### Full Audit Report")
            report_template_export = st.selectbox(
                "Select Report Template",
                options=["Full Audit Report", "Executive Summary", "Findings Only", "Risk Assessment Report", "Control Testing Report"],
                key="export_template"
            )

            if st.button("Generate & Download Report", type="primary", use_container_width=True):
                report_content = generate_full_report(report_template_export)
                st.download_button(
                    label="Download Report (TXT/MD)",
                    data=report_content,
                    file_name=f"{report_template_export.lower().replace(' ', '_')}_{engagement.get('id', 'audit')}_{datetime.date.today().strftime('%Y%m%d')}.md",
                    mime="text/markdown",
                    use_container_width=True,
                    key="download_report"
                )

            st.markdown("---")

            # Executive Summary Quick Export
            st.markdown("#### Executive Summary")
            exec_summary, opinion, _ = generate_executive_summary()

            st.download_button(
                label="Download Executive Summary (MD)",
                data=exec_summary,
                file_name=f"executive_summary_{engagement.get('id', 'audit')}_{datetime.date.today().strftime('%Y%m%d')}.md",
                mime="text/markdown",
                use_container_width=True
            )

        with col2:
            st.markdown("### Data Exports (CSV)")

            # Risks Export
            st.markdown("#### Risk Register")
            if st.session_state.identified_risks:
                risks_df = pd.DataFrame(st.session_state.identified_risks)
                risks_csv = risks_df.to_csv(index=False)
                st.download_button(
                    label=f"Download Risks ({len(st.session_state.identified_risks)} items)",
                    data=risks_csv,
                    file_name=f"risk_register_{engagement.get('id', 'audit')}_{datetime.date.today().strftime('%Y%m%d')}.csv",
                    mime="text/csv",
                    use_container_width=True
                )
            else:
                st.markdown("*No risks to export*")

            st.markdown("---")

            # Controls Export
            st.markdown("#### Control Testing Results")
            if st.session_state.tested_controls:
                # Flatten test_results for CSV export
                controls_export = []
                for ctrl in st.session_state.tested_controls:
                    ctrl_copy = ctrl.copy()
                    if 'test_results' in ctrl_copy:
                        ctrl_copy['test_results'] = str(ctrl_copy['test_results'])
                    controls_export.append(ctrl_copy)

                controls_df = pd.DataFrame(controls_export)
                controls_csv = controls_df.to_csv(index=False)
                st.download_button(
                    label=f"Download Controls ({len(st.session_state.tested_controls)} items)",
                    data=controls_csv,
                    file_name=f"control_testing_{engagement.get('id', 'audit')}_{datetime.date.today().strftime('%Y%m%d')}.csv",
                    mime="text/csv",
                    use_container_width=True
                )
            else:
                st.markdown("*No controls to export*")

            st.markdown("---")

            # Findings Export
            st.markdown("#### Audit Findings")
            if isinstance(findings, list) and findings:
                findings_df = pd.DataFrame(findings)
                findings_csv = findings_df.to_csv(index=False)
                st.download_button(
                    label=f"Download Findings ({len(findings)} items)",
                    data=findings_csv,
                    file_name=f"audit_findings_{engagement.get('id', 'audit')}_{datetime.date.today().strftime('%Y%m%d')}.csv",
                    mime="text/csv",
                    use_container_width=True
                )
            else:
                st.markdown("*No findings to export*")

            st.markdown("---")

            # Reconciliation Export
            st.markdown("#### Reconciliation Results")
            if st.session_state.reconciliation_results:
                recon_df = pd.DataFrame(st.session_state.reconciliation_results)
                recon_csv = recon_df.to_csv(index=False)
                st.download_button(
                    label=f"Download Reconciliations ({len(st.session_state.reconciliation_results)} items)",
                    data=recon_csv,
                    file_name=f"reconciliation_{engagement.get('id', 'audit')}_{datetime.date.today().strftime('%Y%m%d')}.csv",
                    mime="text/csv",
                    use_container_width=True
                )
            else:
                st.markdown("*No reconciliations to export*")

        # Full data package export
        st.markdown("---")
        st.markdown("### Complete Data Package")

        st.markdown("""
        <div class="audit-card">
            <h4>Export All Audit Data</h4>
            <p style="font-size: 0.9rem; color: #5A6C7D;">
                Download a complete package containing all audit data including risks, controls, findings,
                reconciliation results, and the full audit report. Each component is saved as a separate file.
            </p>
        </div>
        """, unsafe_allow_html=True)

        if st.button("Generate Complete Data Package", type="secondary", use_container_width=True):
            # Create a summary of all available exports
            package_summary = f"""
CRYPTO INTERNAL AUDIT TOOLKIT
COMPLETE DATA PACKAGE SUMMARY
================================================================================

Engagement ID: {engagement.get('id', 'Not Assigned')}
Client: {engagement.get('client', 'Not Specified')}
Package Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

PACKAGE CONTENTS:
================================================================================

1. FULL AUDIT REPORT
   - Comprehensive audit report with all sections
   - Format: Markdown/Text

2. RISK REGISTER
   - Total Risks: {len(st.session_state.identified_risks)}
   - Format: CSV

3. CONTROL TESTING RESULTS
   - Total Controls Tested: {len(st.session_state.tested_controls)}
   - Format: CSV

4. AUDIT FINDINGS
   - Total Findings: {findings_count}
   - Format: CSV

5. RECONCILIATION RESULTS
   - Total Reconciliations: {len(st.session_state.reconciliation_results)}
   - Format: CSV

6. COMPLIANCE ITEMS
   - Total Items: {compliance_count}
   - Format: CSV

7. WORKPAPER INDEX
   - Complete index of all audit documentation
   - Format: Text

8. AUDIT TRAIL
   - Chronological record of audit activities
   - Format: CSV

================================================================================
CONFIDENTIALITY NOTICE:
This package contains confidential audit information. Unauthorized distribution
is prohibited.

Co-Authored-By: Claude AI Assistant
================================================================================
"""
            st.text_area("Package Summary", value=package_summary, height=400)
            st.download_button(
                label="Download Package Summary",
                data=package_summary,
                file_name=f"audit_package_summary_{engagement.get('id', 'audit')}_{datetime.date.today().strftime('%Y%m%d')}.txt",
                mime="text/plain",
                use_container_width=True
            )

        # Footer with AI assistance note
        st.markdown("---")
        st.markdown("""
        <div style="background-color: #f8f9fa; padding: 1rem; border-radius: 8px; text-align: center; margin-top: 2rem;">
            <p style="margin: 0; color: #6c757d; font-size: 0.85rem;">
                <strong>Co-Authored-By: Claude AI Assistant</strong><br>
                Reports and documentation generated with AI assistance. All outputs should be reviewed
                and validated by qualified audit professionals before distribution.
            </p>
        </div>
        """, unsafe_allow_html=True)


# =============================================================================
# MAIN APPLICATION ROUTING
# =============================================================================

def main():
    """Main application entry point with section routing."""

    section = st.session_state.current_section

    if section == "Home":
        render_home_page()
    elif section == "Risk Assessment":
        render_risk_assessment()
    elif section == "Control Testing":
        render_control_testing()
    elif section == "Data Analytics":
        render_data_analytics()
    elif section == "Wallet Reconciliation":
        render_wallet_reconciliation()
    elif section == "Compliance Dashboard":
        render_compliance_dashboard()
    elif section == "Report Generation":
        render_report_generation()
    else:
        render_home_page()


# =============================================================================
# RUN APPLICATION
# =============================================================================

if __name__ == "__main__":
    main()
