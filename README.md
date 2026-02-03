# Crypto Internal Audit Toolkit

A comprehensive Streamlit application demonstrating internal audit practices for cryptocurrency and digital asset ecosystems. Built to showcase audit methodologies including risk assessment, control testing, data analytics, wallet reconciliation, and compliance verification.

## Overview

This toolkit demonstrates how traditional internal audit methodologies can be adapted for the unique challenges of blockchain-based financial systems. It is aligned with the **COSO Internal Control Framework** and incorporates industry best practices for crypto asset custody, transaction monitoring, and regulatory compliance.

## Features

### 1. Risk Assessment
- **Risk Universe Display**: Crypto-specific risk categories (custody, trading, transfers, compliance, smart contracts, regulatory)
- **Interactive Risk Scoring**: 5x5 likelihood × impact matrix
- **Risk Heat Map**: Visual representation of risk concentration
- **Inherent vs Residual Risk**: Calculate risk reduction from controls
- **Risk Register**: Add, edit, and track identified risks
- **Export Workpapers**: Download risk assessment documentation

### 2. Control Testing
- **Control Library**: 30+ crypto-specific controls organized by COSO component
- **Test Documentation**: Walkthrough procedures and evidence collection
- **Effectiveness Rating**: Effective, Satisfactory, Needs Improvement, Ineffective
- **Deficiency Tracking**: Document control gaps and remediation plans
- **Three Lines of Defense**: Visual mapping of control ownership

### 3. Data Analytics
- **Transaction Analysis**: Volume, timing, and amount pattern visualization
- **Statistical Sampling**: Random, Stratified, and Monetary Unit Sampling (MUS)
- **Anomaly Detection**: Z-Score, IQR, and round number analysis
- **Benford's Law**: First-digit distribution analysis for fraud detection
- **Duplicate Detection**: Identify potential duplicate transactions
- **Timing Analysis**: Flag off-hours and weekend transactions

### 4. Wallet Reconciliation
- **Balance Verification**: Compare recorded balances to blockchain
- **Multi-Crypto Support**: BTC, ETH, SOL, USDC, USDT
- **Variance Analysis**: Absolute, percentage, and USD variance calculations
- **Historical Trends**: Balance history visualization
- **Proof of Reserves**: Aggregated custody verification
- **Export Workpapers**: Reconciliation documentation

### 5. Compliance Dashboard
- **Regulatory Checklists**: BSA/AML, KYC, SOX, State MTL, Custody requirements
- **Status Tracking**: Compliant, Partial, Non-Compliant, Not Assessed
- **Findings Tracker**: Manage audit findings lifecycle
- **Issue Aging**: Track and escalate overdue items
- **Exam Preparation**: Regulatory examination readiness checklist

### 6. Report Generation
- **Multiple Templates**: Full Report, Executive Summary, Findings Only
- **Automated Compilation**: Pull data from all audit sections
- **Professional Formatting**: IIA-aligned report structure
- **Workpaper Index**: Complete documentation inventory
- **Audit Trail**: Chronological activity log
- **Export Options**: Markdown, CSV, and text formats

## Installation

### Prerequisites
- Python 3.8+
- pip (Python package manager)

### Required Packages
```bash
pip install streamlit pandas numpy
```

### Optional (for enhanced features)
```bash
pip install plotly openpyxl
```

## Quick Start

1. **Navigate to the crypto directory**:
   ```bash
   cd crypto
   ```

2. **Run the application**:
   ```bash
   streamlit run internal_audit_app.py
   ```

3. **Open in browser**: The app will automatically open at `http://localhost:8501`

4. **Load Demo Data**: Click "Start Interactive Demo" on the Home page to populate all sections with sample data

## Project Structure

```
crypto/
├── internal_audit_app.py    # Main Streamlit application (7,000+ lines)
├── audit_data.py            # Data structures, frameworks, and sample data
├── audit_utils.py           # Calculation functions and algorithms
├── Staff-Internal-Auditor.md # Job requirements reference
└── README.md                # This file
```

### File Descriptions

#### `internal_audit_app.py`
The main application containing:
- Page configuration and custom CSS styling
- Session state management for audit engagement tracking
- Seven main sections (Home, Risk Assessment, Control Testing, Data Analytics, Wallet Reconciliation, Compliance Dashboard, Report Generation)
- Demo data loading functionality

#### `audit_data.py`
Data structures and reference data including:
- COSO Framework components and principles
- Crypto-specific controls library (30+ controls)
- Risk categories and sample risks
- Regulatory compliance checklists (BSA/AML, KYC, SOX, State MTL, Custody)
- Sample audit findings
- Severity and status enumerations

#### `audit_utils.py`
Utility functions for:
- Risk score calculations (inherent, residual)
- Control effectiveness ratings
- Statistical sampling algorithms (random, stratified, MUS)
- Anomaly detection (Z-score, IQR, pattern analysis)
- Benford's Law analysis
- Data visualization helpers

## Usage Guide

### Setting Up an Engagement
1. Go to the **Home** page
2. Fill in the engagement details (ID, auditor, client, scope, dates)
3. Click "Save Engagement"

### Using Demo Mode
- Toggle "Demo Mode" in the sidebar, OR
- Click "Start Interactive Demo" on the Home page
- All sections will be pre-populated with realistic sample data

### Workflow Recommendation
1. **Home**: Set up engagement and review methodology
2. **Risk Assessment**: Identify and score crypto-specific risks
3. **Control Testing**: Test controls that mitigate identified risks
4. **Data Analytics**: Analyze transaction data for anomalies
5. **Wallet Reconciliation**: Verify crypto balances
6. **Compliance Dashboard**: Assess regulatory compliance
7. **Report Generation**: Compile findings into professional reports

## Key Calculations

### Risk Scoring
```
Risk Score = Likelihood (1-5) × Impact (1-5)
Residual Risk = Inherent Risk × (1 - Control Effectiveness)
```

### Sampling
```
MUS Interval = Total Population Value / Sample Size
Stratified Sample = (Stratum %) × Total Sample Size
```

### Anomaly Detection
```
Z-Score = (Value - Mean) / Standard Deviation
IQR Outlier = Value < Q1-1.5×IQR or Value > Q3+1.5×IQR
```

### Benford's Law
```
Expected P(digit) = log₁₀(1 + 1/digit)
Chi-Square = Σ[(Observed - Expected)² / Expected]
```

## Frameworks & Standards

### COSO Internal Control Framework
The app implements all five COSO components:
1. **Control Environment**: Organizational culture and governance
2. **Risk Assessment**: Identifying and analyzing risks
3. **Control Activities**: Policies and procedures
4. **Information & Communication**: Data flow and reporting
5. **Monitoring Activities**: Ongoing evaluation

### Three Lines of Defense
- **First Line**: Business operations (risk ownership)
- **Second Line**: Risk management and compliance (oversight)
- **Third Line**: Internal audit (independent assurance)

### Regulatory Coverage
- **BSA/AML**: Bank Secrecy Act / Anti-Money Laundering
- **KYC**: Know Your Customer requirements
- **Travel Rule**: FATF requirements for transaction data sharing
- **State MTL**: Money Transmitter License requirements
- **Custody Rules**: Digital asset custody standards

## Customization

### Adding New Controls
Edit `audit_data.py` and add to `CRYPTO_CONTROLS_LIBRARY`:
```python
Control(
    control_id="XX-001",
    name="Control Name",
    description="Control description",
    category=ControlCategory.YOUR_CATEGORY,
    coso_component=COSOComponent.CONTROL_ACTIVITIES,
    control_type="Preventive",
    frequency="Daily",
    owner="Control Owner",
    test_procedures=["Step 1", "Step 2"],
    evidence_required=["Evidence 1", "Evidence 2"],
    risk_addressed=["Risk 1", "Risk 2"]
)
```

### Adding New Risk Categories
Edit `audit_data.py` and add to `RISK_CATEGORIES`:
```python
"new_category": {
    "name": "Category Name",
    "description": "Category description",
    "color": "#hexcolor",
    "sub_categories": ["Sub 1", "Sub 2"]
}
```

### Modifying Styling
Custom CSS is defined at the top of `internal_audit_app.py`. Key classes:
- `.audit-card`: Card containers
- `.metric-card`: KPI displays
- `.badge-*`: Status badges (low, medium, high, critical)
- `.section-header`: Section titles

## Troubleshooting

### Common Issues

**"Module not found" error**
```bash
pip install streamlit pandas numpy
```

**Port already in use**
```bash
streamlit run internal_audit_app.py --server.port 8502
```

**Session state errors**
- Clear browser cache
- Click "Clear Session" in the sidebar

### Streamlit Version Compatibility
- Minimum: Streamlit 1.23.0 (for `st.toggle`)
- Recommended: Streamlit 1.30.0+
- Note: `st.popover` requires 1.33.0+ (app uses `st.expander` instead)

## Technical Specifications

| Metric | Value |
|--------|-------|
| Total Lines of Code | ~10,700 |
| Main App Size | ~312 KB |
| Number of Controls | 30+ |
| Risk Categories | 6 |
| Compliance Frameworks | 5 |
| Sampling Methods | 3 |
| Anomaly Detection Methods | 5 |

## Contributing

This is a demonstration application. For enhancements:
1. Fork the repository
2. Create a feature branch
3. Make changes following existing code patterns
4. Test thoroughly with demo data
5. Submit a pull request

## License

This project is for educational and demonstration purposes.

## Acknowledgments

- COSO Framework - Committee of Sponsoring Organizations
- IIA Standards - Institute of Internal Auditors
- AICPA - Digital Asset Audit Guidance
- FinCEN - BSA/AML Requirements

---

## Quick Reference

### Run the App
```bash
streamlit run internal_audit_app.py
```

### Load Demo Data
Click "Start Interactive Demo" on the Home page

### Export Reports
Navigate to Report Generation → Export Center

### Key Shortcuts
- `Ctrl+R`: Refresh the page
- `Ctrl+Shift+R`: Hard refresh (clear cache)

---

*Built to demonstrate internal audit practices for cryptocurrency ecosystems*
