"""
Audit Data Module

This module provides comprehensive audit data structures for cryptocurrency
internal auditing, aligned with the COSO Internal Control Framework and
regulatory compliance requirements for crypto/payments auditing.

Designed to support SoFi Staff Internal Auditor job requirements for
crypto/payments auditing functions.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from enum import Enum
from datetime import datetime, date
import uuid


# =============================================================================
# COSO INTERNAL CONTROL FRAMEWORK COMPONENTS
# =============================================================================

class COSOComponent(Enum):
    """COSO Internal Control Framework - Five Components"""
    CONTROL_ENVIRONMENT = "control_environment"
    RISK_ASSESSMENT = "risk_assessment"
    CONTROL_ACTIVITIES = "control_activities"
    INFORMATION_COMMUNICATION = "information_communication"
    MONITORING_ACTIVITIES = "monitoring_activities"


COSO_FRAMEWORK = {
    COSOComponent.CONTROL_ENVIRONMENT: {
        "name": "Control Environment",
        "description": "The set of standards, processes, and structures that provide the basis for carrying out internal control across the organization.",
        "principles": [
            {
                "id": "CE-1",
                "principle": "Demonstrates commitment to integrity and ethical values",
                "crypto_considerations": [
                    "Code of conduct addressing crypto-specific conflicts of interest",
                    "Prohibition on front-running customer trades",
                    "Personal trading policies for crypto assets",
                    "Disclosure requirements for employee crypto holdings"
                ]
            },
            {
                "id": "CE-2",
                "principle": "Board exercises oversight responsibility",
                "crypto_considerations": [
                    "Board-level crypto risk committee",
                    "Regular reporting on crypto asset custody",
                    "Approval of crypto-related risk appetite",
                    "Oversight of key management procedures"
                ]
            },
            {
                "id": "CE-3",
                "principle": "Management establishes structures, reporting lines, and authorities",
                "crypto_considerations": [
                    "Clear organizational structure for crypto operations",
                    "Defined roles for key custodians and signers",
                    "Separation between trading and custody functions",
                    "Escalation paths for security incidents"
                ]
            },
            {
                "id": "CE-4",
                "principle": "Demonstrates commitment to competence",
                "crypto_considerations": [
                    "Crypto-specific training requirements",
                    "Certification requirements for key personnel",
                    "Technical competency assessments",
                    "Ongoing education on blockchain developments"
                ]
            },
            {
                "id": "CE-5",
                "principle": "Enforces accountability",
                "crypto_considerations": [
                    "Performance metrics for crypto operations",
                    "Accountability for wallet security",
                    "Incident response accountability",
                    "Regulatory compliance accountability"
                ]
            }
        ]
    },
    COSOComponent.RISK_ASSESSMENT: {
        "name": "Risk Assessment",
        "description": "A dynamic and iterative process for identifying and assessing risks to the achievement of objectives.",
        "principles": [
            {
                "id": "RA-1",
                "principle": "Specifies suitable objectives",
                "crypto_considerations": [
                    "Crypto asset custody objectives",
                    "Transaction processing objectives",
                    "Regulatory compliance objectives",
                    "Customer asset protection objectives"
                ]
            },
            {
                "id": "RA-2",
                "principle": "Identifies and analyzes risk",
                "crypto_considerations": [
                    "Smart contract risk assessment",
                    "Private key compromise risk",
                    "Exchange counterparty risk",
                    "Blockchain network risk",
                    "Regulatory change risk",
                    "Market manipulation risk"
                ]
            },
            {
                "id": "RA-3",
                "principle": "Assesses fraud risk",
                "crypto_considerations": [
                    "Unauthorized transaction risk",
                    "Insider theft risk",
                    "Social engineering risk",
                    "Wallet address substitution risk",
                    "Fake token/airdrop risk"
                ]
            },
            {
                "id": "RA-4",
                "principle": "Identifies and assesses changes",
                "crypto_considerations": [
                    "Blockchain protocol changes (forks)",
                    "Regulatory landscape changes",
                    "Technology changes",
                    "Market structure changes"
                ]
            }
        ]
    },
    COSOComponent.CONTROL_ACTIVITIES: {
        "name": "Control Activities",
        "description": "Actions established through policies and procedures that help ensure management directives to mitigate risks are carried out.",
        "principles": [
            {
                "id": "CA-1",
                "principle": "Selects and develops control activities",
                "crypto_considerations": [
                    "Multi-signature wallet controls",
                    "Transaction approval workflows",
                    "Wallet whitelist controls",
                    "Rate limiting controls"
                ]
            },
            {
                "id": "CA-2",
                "principle": "Selects and develops general controls over technology",
                "crypto_considerations": [
                    "Hardware security module (HSM) controls",
                    "Cold storage procedures",
                    "Key generation controls",
                    "Network security controls"
                ]
            },
            {
                "id": "CA-3",
                "principle": "Deploys control activities through policies and procedures",
                "crypto_considerations": [
                    "Crypto custody policy",
                    "Key management procedures",
                    "Transaction authorization procedures",
                    "Incident response procedures"
                ]
            }
        ]
    },
    COSOComponent.INFORMATION_COMMUNICATION: {
        "name": "Information & Communication",
        "description": "Information is necessary for the entity to carry out internal control responsibilities. Communication occurs both internally and externally.",
        "principles": [
            {
                "id": "IC-1",
                "principle": "Uses relevant information",
                "crypto_considerations": [
                    "Real-time blockchain monitoring",
                    "On-chain analytics integration",
                    "Market data feeds",
                    "Regulatory news monitoring"
                ]
            },
            {
                "id": "IC-2",
                "principle": "Communicates internally",
                "crypto_considerations": [
                    "Security incident communication protocols",
                    "Risk escalation procedures",
                    "Crypto position reporting",
                    "Compliance updates"
                ]
            },
            {
                "id": "IC-3",
                "principle": "Communicates externally",
                "crypto_considerations": [
                    "Customer transaction notifications",
                    "Regulatory reporting",
                    "Audit trail maintenance",
                    "Public disclosures"
                ]
            }
        ]
    },
    COSOComponent.MONITORING_ACTIVITIES: {
        "name": "Monitoring Activities",
        "description": "Ongoing evaluations, separate evaluations, or some combination to ascertain whether components of internal control are present and functioning.",
        "principles": [
            {
                "id": "MA-1",
                "principle": "Conducts ongoing and/or separate evaluations",
                "crypto_considerations": [
                    "Continuous transaction monitoring",
                    "Periodic proof of reserves audits",
                    "Wallet reconciliation reviews",
                    "Control effectiveness testing"
                ]
            },
            {
                "id": "MA-2",
                "principle": "Evaluates and communicates deficiencies",
                "crypto_considerations": [
                    "Security vulnerability assessments",
                    "Control gap analysis",
                    "Remediation tracking",
                    "Board reporting on deficiencies"
                ]
            }
        ]
    }
}


# =============================================================================
# CRYPTO-SPECIFIC CONTROLS LIBRARY
# =============================================================================

class ControlCategory(Enum):
    """Categories for crypto-specific controls"""
    WALLET_MANAGEMENT = "wallet_management"
    KEY_CUSTODY = "key_custody"
    TRANSACTION_APPROVAL = "transaction_approval"
    SEGREGATION_OF_DUTIES = "segregation_of_duties"
    ACCESS_MANAGEMENT = "access_management"
    CHANGE_MANAGEMENT = "change_management"


@dataclass
class Control:
    """Data class representing an internal control"""
    control_id: str
    name: str
    description: str
    category: ControlCategory
    coso_component: COSOComponent
    control_type: str  # Preventive, Detective, Corrective
    frequency: str  # Continuous, Daily, Weekly, Monthly, As-needed
    owner: str
    test_procedures: List[str]
    evidence_required: List[str]
    risk_addressed: List[str]


CRYPTO_CONTROLS_LIBRARY = {
    ControlCategory.WALLET_MANAGEMENT: [
        Control(
            control_id="WM-001",
            name="Multi-Signature Wallet Configuration",
            description="All hot and cold wallets must be configured with multi-signature requirements (minimum 2-of-3 for hot wallets, 3-of-5 for cold storage).",
            category=ControlCategory.WALLET_MANAGEMENT,
            coso_component=COSOComponent.CONTROL_ACTIVITIES,
            control_type="Preventive",
            frequency="Continuous",
            owner="Crypto Operations Manager",
            test_procedures=[
                "Review wallet configuration documentation",
                "Verify multi-sig setup on blockchain",
                "Test transaction approval workflow",
                "Review signatory access lists"
            ],
            evidence_required=[
                "Wallet configuration screenshots",
                "Multi-sig policy documentation",
                "Signatory authorization matrix",
                "Blockchain explorer verification"
            ],
            risk_addressed=[
                "Unauthorized fund transfer",
                "Single point of failure",
                "Insider theft"
            ]
        ),
        Control(
            control_id="WM-002",
            name="Wallet Address Whitelist",
            description="All outbound transactions must be directed to pre-approved whitelisted addresses only.",
            category=ControlCategory.WALLET_MANAGEMENT,
            coso_component=COSOComponent.CONTROL_ACTIVITIES,
            control_type="Preventive",
            frequency="Continuous",
            owner="Compliance Officer",
            test_procedures=[
                "Review whitelist management procedures",
                "Test whitelist enforcement controls",
                "Verify whitelist approval workflow",
                "Sample test unauthorized address rejection"
            ],
            evidence_required=[
                "Whitelist policy documentation",
                "Whitelist change logs",
                "Approval records for whitelist additions",
                "System configuration evidence"
            ],
            risk_addressed=[
                "Fund misdirection",
                "Address substitution attacks",
                "Compliance violations"
            ]
        ),
        Control(
            control_id="WM-003",
            name="Hot/Cold Wallet Segregation",
            description="Maintain strict segregation between hot wallets (operational) and cold storage (reserve) with defined thresholds.",
            category=ControlCategory.WALLET_MANAGEMENT,
            coso_component=COSOComponent.CONTROL_ACTIVITIES,
            control_type="Preventive",
            frequency="Daily",
            owner="Treasury Manager",
            test_procedures=[
                "Review hot/cold wallet policy",
                "Verify balance thresholds are maintained",
                "Test automated rebalancing controls",
                "Review daily reconciliation reports"
            ],
            evidence_required=[
                "Hot/cold wallet policy",
                "Daily balance reports",
                "Rebalancing transaction logs",
                "Threshold breach alerts"
            ],
            risk_addressed=[
                "Excessive hot wallet exposure",
                "Liquidity risk",
                "Security breach impact"
            ]
        ),
        Control(
            control_id="WM-004",
            name="Wallet Reconciliation",
            description="Daily reconciliation of all wallet balances against internal records and blockchain state.",
            category=ControlCategory.WALLET_MANAGEMENT,
            coso_component=COSOComponent.MONITORING_ACTIVITIES,
            control_type="Detective",
            frequency="Daily",
            owner="Finance Operations",
            test_procedures=[
                "Review reconciliation procedures",
                "Verify reconciliation is performed daily",
                "Test reconciliation accuracy",
                "Review exception handling process"
            ],
            evidence_required=[
                "Daily reconciliation reports",
                "Exception reports",
                "Blockchain verification evidence",
                "Resolution documentation"
            ],
            risk_addressed=[
                "Undetected unauthorized transactions",
                "Balance discrepancies",
                "Accounting errors"
            ]
        )
    ],
    ControlCategory.KEY_CUSTODY: [
        Control(
            control_id="KC-001",
            name="Hardware Security Module (HSM) Usage",
            description="All private keys for institutional wallets must be generated and stored in FIPS 140-2 Level 3 certified HSMs.",
            category=ControlCategory.KEY_CUSTODY,
            coso_component=COSOComponent.CONTROL_ACTIVITIES,
            control_type="Preventive",
            frequency="Continuous",
            owner="Security Operations",
            test_procedures=[
                "Verify HSM certification documentation",
                "Review HSM access controls",
                "Test key generation procedures",
                "Verify tamper-evident seals"
            ],
            evidence_required=[
                "HSM certification certificates",
                "Key generation ceremony documentation",
                "Access logs",
                "Physical security inspection reports"
            ],
            risk_addressed=[
                "Private key extraction",
                "Key compromise",
                "Unauthorized key access"
            ]
        ),
        Control(
            control_id="KC-002",
            name="Key Ceremony Procedures",
            description="New key generation must follow documented ceremony procedures with multiple authorized personnel present.",
            category=ControlCategory.KEY_CUSTODY,
            coso_component=COSOComponent.CONTROL_ACTIVITIES,
            control_type="Preventive",
            frequency="As-needed",
            owner="Security Operations Manager",
            test_procedures=[
                "Review key ceremony documentation",
                "Verify attendance requirements",
                "Review ceremony video recordings",
                "Test key backup procedures"
            ],
            evidence_required=[
                "Key ceremony procedures",
                "Attendance logs",
                "Video recordings",
                "Key backup verification"
            ],
            risk_addressed=[
                "Unauthorized key generation",
                "Key ceremony manipulation",
                "Insufficient key backup"
            ]
        ),
        Control(
            control_id="KC-003",
            name="Key Shard Distribution",
            description="Private key shards must be distributed to geographically separated custodians with no single custodian holding a quorum.",
            category=ControlCategory.KEY_CUSTODY,
            coso_component=COSOComponent.CONTROL_ACTIVITIES,
            control_type="Preventive",
            frequency="Continuous",
            owner="Chief Security Officer",
            test_procedures=[
                "Review shard distribution documentation",
                "Verify geographic separation",
                "Test recovery procedures",
                "Review custodian background checks"
            ],
            evidence_required=[
                "Shard distribution matrix",
                "Geographic location documentation",
                "Recovery test results",
                "Custodian vetting records"
            ],
            risk_addressed=[
                "Single point of failure",
                "Collusion risk",
                "Geographic disaster risk"
            ]
        ),
        Control(
            control_id="KC-004",
            name="Key Rotation Policy",
            description="Implement periodic key rotation for operational wallets and immediate rotation upon personnel changes.",
            category=ControlCategory.KEY_CUSTODY,
            coso_component=COSOComponent.CONTROL_ACTIVITIES,
            control_type="Preventive",
            frequency="Quarterly",
            owner="Security Operations",
            test_procedures=[
                "Review key rotation policy",
                "Verify rotation schedule compliance",
                "Test rotation procedures",
                "Review personnel change triggers"
            ],
            evidence_required=[
                "Key rotation policy",
                "Rotation execution logs",
                "Personnel change notifications",
                "New key verification"
            ],
            risk_addressed=[
                "Stale key compromise",
                "Former employee access",
                "Key exposure over time"
            ]
        )
    ],
    ControlCategory.TRANSACTION_APPROVAL: [
        Control(
            control_id="TA-001",
            name="Transaction Approval Matrix",
            description="All transactions must be approved according to a defined approval matrix based on value thresholds.",
            category=ControlCategory.TRANSACTION_APPROVAL,
            coso_component=COSOComponent.CONTROL_ACTIVITIES,
            control_type="Preventive",
            frequency="Continuous",
            owner="Operations Manager",
            test_procedures=[
                "Review approval matrix documentation",
                "Test matrix enforcement in systems",
                "Sample test transactions at various thresholds",
                "Verify approver authorization levels"
            ],
            evidence_required=[
                "Approval matrix policy",
                "System configuration evidence",
                "Sample transaction approvals",
                "Approver authorization records"
            ],
            risk_addressed=[
                "Unauthorized large transactions",
                "Approval bypass",
                "Insufficient oversight"
            ]
        ),
        Control(
            control_id="TA-002",
            name="Dual Control for Large Transactions",
            description="Transactions exceeding defined thresholds require dual control with two independent approvers.",
            category=ControlCategory.TRANSACTION_APPROVAL,
            coso_component=COSOComponent.CONTROL_ACTIVITIES,
            control_type="Preventive",
            frequency="Continuous",
            owner="Operations Manager",
            test_procedures=[
                "Review dual control policy",
                "Test dual control enforcement",
                "Verify approver independence",
                "Review threshold appropriateness"
            ],
            evidence_required=[
                "Dual control policy",
                "Transaction approval logs",
                "Approver org chart",
                "System configuration"
            ],
            risk_addressed=[
                "Single approver fraud",
                "Collusion risk reduction",
                "Error prevention"
            ]
        ),
        Control(
            control_id="TA-003",
            name="Transaction Velocity Limits",
            description="Implement transaction velocity limits to prevent rapid withdrawal of funds.",
            category=ControlCategory.TRANSACTION_APPROVAL,
            coso_component=COSOComponent.CONTROL_ACTIVITIES,
            control_type="Preventive",
            frequency="Continuous",
            owner="Risk Management",
            test_procedures=[
                "Review velocity limit configuration",
                "Test limit enforcement",
                "Review limit breach alerts",
                "Verify exception handling process"
            ],
            evidence_required=[
                "Velocity limit policy",
                "System configuration",
                "Alert logs",
                "Exception approvals"
            ],
            risk_addressed=[
                "Rapid fund extraction",
                "Account takeover attacks",
                "Unauthorized bulk transfers"
            ]
        ),
        Control(
            control_id="TA-004",
            name="Pre-Transaction Address Verification",
            description="All outbound transactions must include real-time address verification and risk scoring.",
            category=ControlCategory.TRANSACTION_APPROVAL,
            coso_component=COSOComponent.CONTROL_ACTIVITIES,
            control_type="Preventive",
            frequency="Continuous",
            owner="Compliance",
            test_procedures=[
                "Review address verification procedures",
                "Test address screening integration",
                "Verify high-risk address blocking",
                "Review screening vendor due diligence"
            ],
            evidence_required=[
                "Address verification policy",
                "Screening system configuration",
                "Blocked transaction logs",
                "Vendor agreements"
            ],
            risk_addressed=[
                "Sanctioned address transfers",
                "Fraud address transfers",
                "Regulatory violations"
            ]
        )
    ],
    ControlCategory.SEGREGATION_OF_DUTIES: [
        Control(
            control_id="SD-001",
            name="Trading and Custody Separation",
            description="Personnel involved in trading operations must be segregated from those with custody/key access.",
            category=ControlCategory.SEGREGATION_OF_DUTIES,
            coso_component=COSOComponent.CONTROL_ENVIRONMENT,
            control_type="Preventive",
            frequency="Continuous",
            owner="Chief Operating Officer",
            test_procedures=[
                "Review organizational structure",
                "Verify access control segregation",
                "Test for conflicting access rights",
                "Review role definitions"
            ],
            evidence_required=[
                "Organizational charts",
                "Access control matrices",
                "Role definitions",
                "Access review reports"
            ],
            risk_addressed=[
                "Front-running",
                "Unauthorized trading",
                "Conflict of interest"
            ]
        ),
        Control(
            control_id="SD-002",
            name="Developer and Production Access Separation",
            description="Developers must not have direct access to production wallet systems or private keys.",
            category=ControlCategory.SEGREGATION_OF_DUTIES,
            coso_component=COSOComponent.CONTROL_ACTIVITIES,
            control_type="Preventive",
            frequency="Continuous",
            owner="IT Security Manager",
            test_procedures=[
                "Review access control policies",
                "Test production access restrictions",
                "Verify deployment procedures",
                "Review privileged access logs"
            ],
            evidence_required=[
                "Access control policy",
                "Production access lists",
                "Deployment procedures",
                "Access logs"
            ],
            risk_addressed=[
                "Malicious code injection",
                "Unauthorized production changes",
                "Key extraction"
            ]
        ),
        Control(
            control_id="SD-003",
            name="Maker-Checker Controls",
            description="All configuration changes require a maker-checker workflow with independent review.",
            category=ControlCategory.SEGREGATION_OF_DUTIES,
            coso_component=COSOComponent.CONTROL_ACTIVITIES,
            control_type="Preventive",
            frequency="Continuous",
            owner="Operations Manager",
            test_procedures=[
                "Review maker-checker procedures",
                "Test workflow enforcement",
                "Verify reviewer independence",
                "Sample test configuration changes"
            ],
            evidence_required=[
                "Maker-checker policy",
                "Workflow configuration",
                "Change approval logs",
                "Org chart"
            ],
            risk_addressed=[
                "Unauthorized configuration changes",
                "Error introduction",
                "Malicious changes"
            ]
        )
    ],
    ControlCategory.ACCESS_MANAGEMENT: [
        Control(
            control_id="AM-001",
            name="Privileged Access Management",
            description="Privileged access to crypto systems must be managed through a PAM solution with session recording.",
            category=ControlCategory.ACCESS_MANAGEMENT,
            coso_component=COSOComponent.CONTROL_ACTIVITIES,
            control_type="Preventive",
            frequency="Continuous",
            owner="IT Security Manager",
            test_procedures=[
                "Review PAM configuration",
                "Test session recording functionality",
                "Verify access request workflow",
                "Review session logs"
            ],
            evidence_required=[
                "PAM policy",
                "System configuration",
                "Session recordings",
                "Access request logs"
            ],
            risk_addressed=[
                "Privileged access abuse",
                "Unmonitored administrative actions",
                "Audit trail gaps"
            ]
        ),
        Control(
            control_id="AM-002",
            name="Multi-Factor Authentication",
            description="All access to crypto systems must require MFA using hardware tokens or authenticator apps.",
            category=ControlCategory.ACCESS_MANAGEMENT,
            coso_component=COSOComponent.CONTROL_ACTIVITIES,
            control_type="Preventive",
            frequency="Continuous",
            owner="IT Security",
            test_procedures=[
                "Review MFA policy",
                "Test MFA enforcement",
                "Verify MFA coverage",
                "Test MFA bypass controls"
            ],
            evidence_required=[
                "MFA policy",
                "System configuration",
                "MFA enrollment records",
                "Exception logs"
            ],
            risk_addressed=[
                "Credential theft",
                "Phishing attacks",
                "Account takeover"
            ]
        ),
        Control(
            control_id="AM-003",
            name="Quarterly Access Reviews",
            description="Comprehensive access reviews must be performed quarterly with appropriate attestation.",
            category=ControlCategory.ACCESS_MANAGEMENT,
            coso_component=COSOComponent.MONITORING_ACTIVITIES,
            control_type="Detective",
            frequency="Quarterly",
            owner="IT Security Manager",
            test_procedures=[
                "Review access review procedures",
                "Verify review completion",
                "Test attestation process",
                "Review access modifications"
            ],
            evidence_required=[
                "Access review policy",
                "Review completion records",
                "Attestation documentation",
                "Access modification logs"
            ],
            risk_addressed=[
                "Excessive access accumulation",
                "Stale accounts",
                "Inappropriate access"
            ]
        ),
        Control(
            control_id="AM-004",
            name="Immediate Access Revocation",
            description="Access must be revoked within 4 hours of employee termination or role change.",
            category=ControlCategory.ACCESS_MANAGEMENT,
            coso_component=COSOComponent.CONTROL_ACTIVITIES,
            control_type="Preventive",
            frequency="As-needed",
            owner="HR / IT Security",
            test_procedures=[
                "Review termination procedures",
                "Test access revocation timing",
                "Verify HR-IT integration",
                "Sample test recent terminations"
            ],
            evidence_required=[
                "Termination procedures",
                "Access revocation logs",
                "HR notification records",
                "Timing documentation"
            ],
            risk_addressed=[
                "Former employee access",
                "Disgruntled employee risk",
                "Data exfiltration"
            ]
        )
    ],
    ControlCategory.CHANGE_MANAGEMENT: [
        Control(
            control_id="CM-001",
            name="Smart Contract Audit Requirements",
            description="All smart contracts must undergo independent security audit before deployment.",
            category=ControlCategory.CHANGE_MANAGEMENT,
            coso_component=COSOComponent.CONTROL_ACTIVITIES,
            control_type="Preventive",
            frequency="As-needed",
            owner="Security Operations",
            test_procedures=[
                "Review audit requirements policy",
                "Verify audit completion for deployed contracts",
                "Review audit findings and remediation",
                "Verify auditor independence"
            ],
            evidence_required=[
                "Smart contract audit policy",
                "Audit reports",
                "Remediation documentation",
                "Auditor credentials"
            ],
            risk_addressed=[
                "Smart contract vulnerabilities",
                "Exploitation risk",
                "Fund loss"
            ]
        ),
        Control(
            control_id="CM-002",
            name="Change Advisory Board",
            description="All changes to crypto infrastructure must be reviewed and approved by a Change Advisory Board.",
            category=ControlCategory.CHANGE_MANAGEMENT,
            coso_component=COSOComponent.CONTROL_ACTIVITIES,
            control_type="Preventive",
            frequency="Weekly",
            owner="IT Change Manager",
            test_procedures=[
                "Review CAB procedures",
                "Verify CAB approval for changes",
                "Review CAB meeting minutes",
                "Test emergency change procedures"
            ],
            evidence_required=[
                "CAB charter",
                "Meeting minutes",
                "Change approval records",
                "Emergency change logs"
            ],
            risk_addressed=[
                "Unauthorized changes",
                "Poorly planned changes",
                "Service disruption"
            ]
        ),
        Control(
            control_id="CM-003",
            name="Production Deployment Controls",
            description="Production deployments must follow documented procedures with rollback capabilities.",
            category=ControlCategory.CHANGE_MANAGEMENT,
            coso_component=COSOComponent.CONTROL_ACTIVITIES,
            control_type="Preventive",
            frequency="As-needed",
            owner="DevOps Manager",
            test_procedures=[
                "Review deployment procedures",
                "Test rollback capabilities",
                "Verify deployment approvals",
                "Review deployment logs"
            ],
            evidence_required=[
                "Deployment procedures",
                "Rollback documentation",
                "Deployment approval records",
                "Deployment logs"
            ],
            risk_addressed=[
                "Failed deployments",
                "Service outages",
                "Data corruption"
            ]
        )
    ]
}


# =============================================================================
# RISK RATING MATRICES AND SCORING CRITERIA
# =============================================================================

class LikelihoodRating(Enum):
    """Likelihood rating scale (1-5)"""
    RARE = 1
    UNLIKELY = 2
    POSSIBLE = 3
    LIKELY = 4
    ALMOST_CERTAIN = 5


class ImpactRating(Enum):
    """Impact rating scale (1-5)"""
    INSIGNIFICANT = 1
    MINOR = 2
    MODERATE = 3
    MAJOR = 4
    CATASTROPHIC = 5


LIKELIHOOD_DEFINITIONS = {
    LikelihoodRating.RARE: {
        "rating": 1,
        "label": "Rare",
        "description": "Event may occur only in exceptional circumstances",
        "probability": "< 5% chance of occurrence",
        "frequency": "Less than once every 5 years"
    },
    LikelihoodRating.UNLIKELY: {
        "rating": 2,
        "label": "Unlikely",
        "description": "Event could occur at some time but not expected",
        "probability": "5-20% chance of occurrence",
        "frequency": "Once every 2-5 years"
    },
    LikelihoodRating.POSSIBLE: {
        "rating": 3,
        "label": "Possible",
        "description": "Event might occur at some time",
        "probability": "20-50% chance of occurrence",
        "frequency": "Once every 1-2 years"
    },
    LikelihoodRating.LIKELY: {
        "rating": 4,
        "label": "Likely",
        "description": "Event will probably occur in most circumstances",
        "probability": "50-80% chance of occurrence",
        "frequency": "Once or more per year"
    },
    LikelihoodRating.ALMOST_CERTAIN: {
        "rating": 5,
        "label": "Almost Certain",
        "description": "Event is expected to occur in most circumstances",
        "probability": "> 80% chance of occurrence",
        "frequency": "Multiple times per year"
    }
}

IMPACT_DEFINITIONS = {
    ImpactRating.INSIGNIFICANT: {
        "rating": 1,
        "label": "Insignificant",
        "description": "Minimal impact on operations or financials",
        "financial_impact": "< $10,000",
        "operational_impact": "No disruption to services",
        "reputational_impact": "No media coverage",
        "regulatory_impact": "No regulatory concern"
    },
    ImpactRating.MINOR: {
        "rating": 2,
        "label": "Minor",
        "description": "Minor impact requiring some management effort",
        "financial_impact": "$10,000 - $100,000",
        "operational_impact": "Minor service disruption (< 4 hours)",
        "reputational_impact": "Limited negative feedback",
        "regulatory_impact": "Minor regulatory inquiry"
    },
    ImpactRating.MODERATE: {
        "rating": 3,
        "label": "Moderate",
        "description": "Moderate impact requiring significant management",
        "financial_impact": "$100,000 - $1,000,000",
        "operational_impact": "Service disruption (4-24 hours)",
        "reputational_impact": "Negative industry coverage",
        "regulatory_impact": "Formal regulatory review"
    },
    ImpactRating.MAJOR: {
        "rating": 4,
        "label": "Major",
        "description": "Major impact on operations, requires executive attention",
        "financial_impact": "$1,000,000 - $10,000,000",
        "operational_impact": "Extended service disruption (1-7 days)",
        "reputational_impact": "Significant negative media coverage",
        "regulatory_impact": "Regulatory enforcement action"
    },
    ImpactRating.CATASTROPHIC: {
        "rating": 5,
        "label": "Catastrophic",
        "description": "Catastrophic impact threatening business viability",
        "financial_impact": "> $10,000,000",
        "operational_impact": "Prolonged service outage (> 7 days)",
        "reputational_impact": "National/international negative coverage",
        "regulatory_impact": "License revocation or major sanctions"
    }
}

# Risk Scoring Matrix (Likelihood x Impact)
RISK_SCORING_MATRIX = {
    # (Likelihood, Impact): Risk Score
    (1, 1): 1, (1, 2): 2, (1, 3): 3, (1, 4): 4, (1, 5): 5,
    (2, 1): 2, (2, 2): 4, (2, 3): 6, (2, 4): 8, (2, 5): 10,
    (3, 1): 3, (3, 2): 6, (3, 3): 9, (3, 4): 12, (3, 5): 15,
    (4, 1): 4, (4, 2): 8, (4, 3): 12, (4, 4): 16, (4, 5): 20,
    (5, 1): 5, (5, 2): 10, (5, 3): 15, (5, 4): 20, (5, 5): 25
}

class RiskLevel(Enum):
    """Risk level classification based on risk score"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


RISK_LEVEL_THRESHOLDS = {
    RiskLevel.LOW: {"min_score": 1, "max_score": 4, "color": "green"},
    RiskLevel.MEDIUM: {"min_score": 5, "max_score": 9, "color": "yellow"},
    RiskLevel.HIGH: {"min_score": 10, "max_score": 16, "color": "orange"},
    RiskLevel.CRITICAL: {"min_score": 17, "max_score": 25, "color": "red"}
}

RISK_APPETITE_THRESHOLDS = {
    "crypto_custody": {
        "description": "Tolerance for risks related to custody of customer crypto assets",
        "appetite_level": RiskLevel.LOW,
        "max_acceptable_score": 4,
        "rationale": "Customer assets must be protected with highest priority"
    },
    "transaction_processing": {
        "description": "Tolerance for risks in transaction processing operations",
        "appetite_level": RiskLevel.MEDIUM,
        "max_acceptable_score": 9,
        "rationale": "Operational efficiency balanced with security requirements"
    },
    "regulatory_compliance": {
        "description": "Tolerance for regulatory compliance risks",
        "appetite_level": RiskLevel.LOW,
        "max_acceptable_score": 4,
        "rationale": "Regulatory compliance is non-negotiable"
    },
    "technology_infrastructure": {
        "description": "Tolerance for technology and infrastructure risks",
        "appetite_level": RiskLevel.MEDIUM,
        "max_acceptable_score": 9,
        "rationale": "Technology risks managed through redundancy and controls"
    },
    "third_party": {
        "description": "Tolerance for third-party and vendor risks",
        "appetite_level": RiskLevel.MEDIUM,
        "max_acceptable_score": 9,
        "rationale": "Vendor relationships require ongoing monitoring"
    }
}


def calculate_risk_score(likelihood: int, impact: int) -> int:
    """Calculate risk score from likelihood and impact ratings"""
    return RISK_SCORING_MATRIX.get((likelihood, impact), 0)


def get_risk_level(risk_score: int) -> RiskLevel:
    """Determine risk level based on risk score"""
    for level, thresholds in RISK_LEVEL_THRESHOLDS.items():
        if thresholds["min_score"] <= risk_score <= thresholds["max_score"]:
            return level
    return RiskLevel.CRITICAL


# =============================================================================
# CRYPTO RISK CATEGORIES AND SAMPLE RISKS
# =============================================================================

RISK_CATEGORIES = {
    "custody": {
        "name": "Custody Risk",
        "description": "Risks related to the safekeeping and custody of crypto assets",
        "icon": "shield",
        "color": "#1E3A5F",
        "sub_categories": [
            "Private key compromise",
            "Cold storage breach",
            "Hot wallet exposure",
            "Custodian failure",
            "Asset misappropriation"
        ]
    },
    "trading": {
        "name": "Trading Risk",
        "description": "Risks associated with crypto trading operations and market activities",
        "icon": "trending-up",
        "color": "#2E7D32",
        "sub_categories": [
            "Market manipulation",
            "Front-running",
            "Price slippage",
            "Liquidity risk",
            "Counterparty default"
        ]
    },
    "transfers": {
        "name": "Transfer Risk",
        "description": "Risks in crypto asset transfer and settlement processes",
        "icon": "send",
        "color": "#F57C00",
        "sub_categories": [
            "Address substitution",
            "Transaction delay",
            "Network congestion",
            "Failed transactions",
            "Duplicate transfers"
        ]
    },
    "compliance": {
        "name": "Compliance Risk",
        "description": "Risks related to regulatory and compliance requirements",
        "icon": "clipboard-check",
        "color": "#7B1FA2",
        "sub_categories": [
            "AML/KYC violations",
            "Sanctions screening failure",
            "Regulatory reporting gaps",
            "License non-compliance",
            "Travel rule violations"
        ]
    },
    "smart_contracts": {
        "name": "Smart Contract Risk",
        "description": "Risks associated with smart contract vulnerabilities and DeFi protocols",
        "icon": "code",
        "color": "#D32F2F",
        "sub_categories": [
            "Code vulnerabilities",
            "Reentrancy attacks",
            "Oracle manipulation",
            "Flash loan attacks",
            "Upgrade risks"
        ]
    },
    "regulatory": {
        "name": "Regulatory Risk",
        "description": "Risks from evolving regulatory landscape and enforcement actions",
        "icon": "scale",
        "color": "#0288D1",
        "sub_categories": [
            "Regulatory change",
            "Enforcement actions",
            "Cross-border compliance",
            "Tax reporting",
            "Securities classification"
        ]
    }
}

SAMPLE_CRYPTO_RISKS = [
    {
        "id": "RISK-001",
        "name": "Private Key Compromise",
        "description": "Unauthorized access to private keys could result in complete loss of custodied assets. This includes theft through hacking, insider threats, or social engineering attacks targeting key holders.",
        "category": "custody",
        "coso_component": COSOComponent.CONTROL_ACTIVITIES,
        "likelihood": 3,
        "impact": 5,
        "inherent_factors": {"complexity": 4, "volume": 3, "regulatory": 5, "technology": 4},
        "control_effectiveness": {"multi_sig": 0.85, "hsm_storage": 0.90, "access_controls": 0.75},
        "owner": "Chief Security Officer",
        "status": "Open"
    },
    {
        "id": "RISK-002",
        "name": "Hot Wallet Breach",
        "description": "Cyber attack targeting hot wallet infrastructure leading to unauthorized fund transfers. Hot wallets are more vulnerable due to their internet connectivity.",
        "category": "custody",
        "coso_component": COSOComponent.CONTROL_ACTIVITIES,
        "likelihood": 4,
        "impact": 4,
        "inherent_factors": {"complexity": 3, "volume": 4, "regulatory": 3, "technology": 5},
        "control_effectiveness": {"rate_limiting": 0.70, "monitoring": 0.80, "segregation": 0.85},
        "owner": "Security Operations Manager",
        "status": "Open"
    },
    {
        "id": "RISK-003",
        "name": "Market Manipulation Detection Failure",
        "description": "Inability to detect or prevent market manipulation activities such as wash trading, spoofing, or pump-and-dump schemes on trading platforms.",
        "category": "trading",
        "coso_component": COSOComponent.MONITORING_ACTIVITIES,
        "likelihood": 3,
        "impact": 4,
        "inherent_factors": {"complexity": 4, "volume": 5, "regulatory": 4, "technology": 3},
        "control_effectiveness": {"surveillance": 0.75, "alerts": 0.70, "investigation": 0.65},
        "owner": "Compliance Manager",
        "status": "Open"
    },
    {
        "id": "RISK-004",
        "name": "Transaction Address Substitution",
        "description": "Malicious substitution of destination wallet addresses during transaction processing, redirecting funds to attacker-controlled wallets.",
        "category": "transfers",
        "coso_component": COSOComponent.CONTROL_ACTIVITIES,
        "likelihood": 2,
        "impact": 5,
        "inherent_factors": {"complexity": 3, "volume": 4, "regulatory": 3, "technology": 4},
        "control_effectiveness": {"whitelist": 0.90, "verification": 0.85, "dual_control": 0.80},
        "owner": "Operations Manager",
        "status": "Mitigated"
    },
    {
        "id": "RISK-005",
        "name": "AML/KYC Program Deficiency",
        "description": "Inadequate anti-money laundering and know-your-customer processes leading to regulatory violations and potential enforcement actions.",
        "category": "compliance",
        "coso_component": COSOComponent.CONTROL_ENVIRONMENT,
        "likelihood": 3,
        "impact": 5,
        "inherent_factors": {"complexity": 4, "volume": 4, "regulatory": 5, "technology": 3},
        "control_effectiveness": {"screening": 0.80, "monitoring": 0.75, "reporting": 0.85},
        "owner": "Chief Compliance Officer",
        "status": "Open"
    },
    {
        "id": "RISK-006",
        "name": "Smart Contract Vulnerability Exploitation",
        "description": "Exploitation of vulnerabilities in smart contracts used for DeFi operations, staking, or token management leading to fund loss.",
        "category": "smart_contracts",
        "coso_component": COSOComponent.CONTROL_ACTIVITIES,
        "likelihood": 3,
        "impact": 5,
        "inherent_factors": {"complexity": 5, "volume": 3, "regulatory": 2, "technology": 5},
        "control_effectiveness": {"audit": 0.80, "testing": 0.75, "monitoring": 0.70},
        "owner": "Engineering Lead",
        "status": "Open"
    },
    {
        "id": "RISK-007",
        "name": "Regulatory Classification Change",
        "description": "Risk that crypto assets may be reclassified as securities or face new regulatory requirements, impacting business operations.",
        "category": "regulatory",
        "coso_component": COSOComponent.RISK_ASSESSMENT,
        "likelihood": 4,
        "impact": 4,
        "inherent_factors": {"complexity": 3, "volume": 2, "regulatory": 5, "technology": 2},
        "control_effectiveness": {"monitoring": 0.60, "legal_review": 0.70, "contingency": 0.55},
        "owner": "General Counsel",
        "status": "Open"
    },
    {
        "id": "RISK-008",
        "name": "Sanctions Screening Failure",
        "description": "Failure to properly screen transactions and counterparties against OFAC and other sanctions lists, resulting in prohibited transactions.",
        "category": "compliance",
        "coso_component": COSOComponent.CONTROL_ACTIVITIES,
        "likelihood": 2,
        "impact": 5,
        "inherent_factors": {"complexity": 3, "volume": 5, "regulatory": 5, "technology": 4},
        "control_effectiveness": {"real_time_screening": 0.90, "list_updates": 0.85, "manual_review": 0.80},
        "owner": "BSA Officer",
        "status": "Mitigated"
    },
    {
        "id": "RISK-009",
        "name": "Oracle Manipulation Attack",
        "description": "Manipulation of price oracle data used by smart contracts, leading to incorrect valuations or unauthorized transactions.",
        "category": "smart_contracts",
        "coso_component": COSOComponent.MONITORING_ACTIVITIES,
        "likelihood": 3,
        "impact": 4,
        "inherent_factors": {"complexity": 5, "volume": 3, "regulatory": 2, "technology": 5},
        "control_effectiveness": {"multiple_oracles": 0.75, "deviation_checks": 0.70, "circuit_breakers": 0.80},
        "owner": "DeFi Operations Lead",
        "status": "Open"
    },
    {
        "id": "RISK-010",
        "name": "Custodian Counterparty Default",
        "description": "Third-party custodian becomes insolvent or unable to return assets, resulting in potential loss of customer funds.",
        "category": "custody",
        "coso_component": COSOComponent.RISK_ASSESSMENT,
        "likelihood": 2,
        "impact": 5,
        "inherent_factors": {"complexity": 3, "volume": 4, "regulatory": 4, "technology": 2},
        "control_effectiveness": {"due_diligence": 0.80, "diversification": 0.75, "insurance": 0.70},
        "owner": "Treasury Manager",
        "status": "Open"
    }
]


# =============================================================================
# REGULATORY COMPLIANCE CHECKLISTS
# =============================================================================

@dataclass
class ComplianceRequirement:
    """Data class for compliance requirements"""
    requirement_id: str
    regulation: str
    requirement: str
    description: str
    testing_procedures: List[str]
    evidence_required: List[str]
    frequency: str
    applicability: str


REGULATORY_COMPLIANCE_CHECKLISTS = {
    "AML_BSA": {
        "regulation_name": "Anti-Money Laundering / Bank Secrecy Act",
        "authority": "FinCEN",
        "requirements": [
            ComplianceRequirement(
                requirement_id="AML-001",
                regulation="BSA/AML",
                requirement="Customer Identification Program (CIP)",
                description="Implement CIP procedures to verify customer identity before establishing accounts.",
                testing_procedures=[
                    "Review CIP policy and procedures",
                    "Test identity verification controls",
                    "Sample test customer onboarding files",
                    "Verify documentary and non-documentary verification"
                ],
                evidence_required=[
                    "CIP policy",
                    "Identity verification records",
                    "Customer files with ID documentation",
                    "Verification system configuration"
                ],
                frequency="Ongoing with annual review",
                applicability="All Money Services Businesses (MSBs)"
            ),
            ComplianceRequirement(
                requirement_id="AML-002",
                regulation="BSA/AML",
                requirement="Suspicious Activity Reporting (SAR)",
                description="File SARs for transactions or patterns of transactions that appear suspicious.",
                testing_procedures=[
                    "Review SAR filing procedures",
                    "Test suspicious activity detection systems",
                    "Review SAR filing timeliness",
                    "Verify SAR quality and completeness"
                ],
                evidence_required=[
                    "SAR policy and procedures",
                    "SAR filing logs",
                    "Transaction monitoring system records",
                    "SAR quality review documentation"
                ],
                frequency="Ongoing with annual review",
                applicability="All MSBs and financial institutions"
            ),
            ComplianceRequirement(
                requirement_id="AML-003",
                regulation="BSA/AML",
                requirement="Currency Transaction Reporting (CTR)",
                description="File CTRs for cash transactions exceeding $10,000.",
                testing_procedures=[
                    "Review CTR filing procedures",
                    "Test CTR threshold monitoring",
                    "Sample test CTR filings for accuracy",
                    "Verify structuring detection controls"
                ],
                evidence_required=[
                    "CTR policy",
                    "CTR filing records",
                    "Cash transaction logs",
                    "Structuring alert documentation"
                ],
                frequency="Ongoing",
                applicability="Entities handling cash transactions"
            ),
            ComplianceRequirement(
                requirement_id="AML-004",
                regulation="BSA/AML",
                requirement="Transaction Monitoring Program",
                description="Implement automated transaction monitoring for suspicious activity detection.",
                testing_procedures=[
                    "Review monitoring program documentation",
                    "Test alert generation and investigation workflow",
                    "Verify rule tuning and effectiveness",
                    "Review model validation documentation"
                ],
                evidence_required=[
                    "Transaction monitoring procedures",
                    "Alert disposition records",
                    "Rule configuration documentation",
                    "Model validation reports"
                ],
                frequency="Continuous with periodic review",
                applicability="All crypto exchanges and custodians"
            ),
            ComplianceRequirement(
                requirement_id="AML-005",
                regulation="BSA/AML",
                requirement="AML Program Requirements",
                description="Maintain a written AML compliance program with designated compliance officer.",
                testing_procedures=[
                    "Review AML program documentation",
                    "Verify compliance officer designation",
                    "Review training program effectiveness",
                    "Test independent testing procedures"
                ],
                evidence_required=[
                    "AML compliance program",
                    "Board approval documentation",
                    "Training records",
                    "Independent audit reports"
                ],
                frequency="Annual review",
                applicability="All MSBs and financial institutions"
            ),
            ComplianceRequirement(
                requirement_id="AML-006",
                regulation="BSA/AML",
                requirement="Travel Rule Compliance",
                description="Transmit required information with fund transfers exceeding $3,000.",
                testing_procedures=[
                    "Review Travel Rule procedures",
                    "Test information transmission systems",
                    "Verify data completeness",
                    "Review counterparty verification"
                ],
                evidence_required=[
                    "Travel Rule policy",
                    "Transaction records with required data",
                    "Counterparty verification logs",
                    "System configuration documentation"
                ],
                frequency="Ongoing",
                applicability="Crypto exchanges and payment processors"
            )
        ]
    },
    "KYC": {
        "regulation_name": "Know Your Customer",
        "authority": "Multiple regulatory bodies",
        "requirements": [
            ComplianceRequirement(
                requirement_id="KYC-001",
                regulation="KYC",
                requirement="Customer Due Diligence (CDD)",
                description="Perform risk-based due diligence on all customers.",
                testing_procedures=[
                    "Review CDD procedures",
                    "Test risk rating methodology",
                    "Sample test customer risk assessments",
                    "Verify ongoing monitoring"
                ],
                evidence_required=[
                    "CDD policy",
                    "Risk rating criteria",
                    "Customer risk assessments",
                    "Ongoing monitoring records"
                ],
                frequency="At onboarding and ongoing",
                applicability="All regulated entities"
            ),
            ComplianceRequirement(
                requirement_id="KYC-002",
                regulation="KYC",
                requirement="Enhanced Due Diligence (EDD)",
                description="Perform enhanced due diligence for high-risk customers.",
                testing_procedures=[
                    "Review EDD triggers and procedures",
                    "Test high-risk customer identification",
                    "Sample test EDD files",
                    "Verify senior management approval"
                ],
                evidence_required=[
                    "EDD policy",
                    "High-risk customer list",
                    "EDD documentation",
                    "Approval records"
                ],
                frequency="At onboarding and ongoing",
                applicability="High-risk customers"
            ),
            ComplianceRequirement(
                requirement_id="KYC-003",
                regulation="KYC",
                requirement="Beneficial Ownership Identification",
                description="Identify and verify beneficial owners of legal entity customers.",
                testing_procedures=[
                    "Review beneficial ownership procedures",
                    "Test ownership verification process",
                    "Sample test entity customer files",
                    "Verify 25% threshold application"
                ],
                evidence_required=[
                    "Beneficial ownership policy",
                    "Ownership verification records",
                    "Entity customer files",
                    "Organizational charts"
                ],
                frequency="At onboarding with periodic refresh",
                applicability="Legal entity customers"
            ),
            ComplianceRequirement(
                requirement_id="KYC-004",
                regulation="KYC",
                requirement="PEP and Sanctions Screening",
                description="Screen customers against PEP lists and sanctions databases.",
                testing_procedures=[
                    "Review screening procedures",
                    "Test screening system effectiveness",
                    "Verify screening frequency",
                    "Review match resolution process"
                ],
                evidence_required=[
                    "Screening policy",
                    "Screening system configuration",
                    "Match resolution records",
                    "Vendor due diligence"
                ],
                frequency="At onboarding and ongoing",
                applicability="All customers"
            ),
            ComplianceRequirement(
                requirement_id="KYC-005",
                regulation="KYC",
                requirement="Customer Information Refresh",
                description="Periodically refresh customer information based on risk rating.",
                testing_procedures=[
                    "Review refresh policy",
                    "Test refresh triggers and frequency",
                    "Sample test refresh completion",
                    "Verify risk-based approach"
                ],
                evidence_required=[
                    "Refresh policy",
                    "Refresh schedule",
                    "Updated customer records",
                    "Refresh completion logs"
                ],
                frequency="Risk-based (1-3 years)",
                applicability="All existing customers"
            )
        ]
    },
    "SOX": {
        "regulation_name": "Sarbanes-Oxley Act",
        "authority": "SEC / PCAOB",
        "requirements": [
            ComplianceRequirement(
                requirement_id="SOX-001",
                regulation="SOX Section 302",
                requirement="CEO/CFO Certification",
                description="CEO and CFO must certify financial statements and internal controls.",
                testing_procedures=[
                    "Review certification procedures",
                    "Verify sub-certification process",
                    "Test disclosure controls",
                    "Review representation letters"
                ],
                evidence_required=[
                    "Certification policy",
                    "Sub-certification records",
                    "Disclosure committee minutes",
                    "Representation letters"
                ],
                frequency="Quarterly",
                applicability="Public companies"
            ),
            ComplianceRequirement(
                requirement_id="SOX-002",
                regulation="SOX Section 404",
                requirement="Internal Control Assessment",
                description="Assess and report on effectiveness of internal controls over financial reporting.",
                testing_procedures=[
                    "Review control documentation",
                    "Test key controls",
                    "Evaluate control deficiencies",
                    "Review management assessment"
                ],
                evidence_required=[
                    "Control documentation (RCMs)",
                    "Testing workpapers",
                    "Deficiency evaluations",
                    "Management assessment report"
                ],
                frequency="Annual with quarterly monitoring",
                applicability="Public companies"
            ),
            ComplianceRequirement(
                requirement_id="SOX-003",
                regulation="SOX",
                requirement="Crypto Asset Valuation Controls",
                description="Controls over fair value measurement of crypto assets.",
                testing_procedures=[
                    "Review valuation methodology",
                    "Test pricing source controls",
                    "Verify mark-to-market procedures",
                    "Review impairment testing"
                ],
                evidence_required=[
                    "Valuation policy",
                    "Pricing source documentation",
                    "Valuation workpapers",
                    "Management review evidence"
                ],
                frequency="Continuous with period-end review",
                applicability="Entities holding crypto assets"
            ),
            ComplianceRequirement(
                requirement_id="SOX-404",
                regulation="SOX",
                requirement="Crypto Custody Reconciliation Controls",
                description="Controls ensuring accurate recording and reconciliation of crypto holdings.",
                testing_procedures=[
                    "Review reconciliation procedures",
                    "Test reconciliation accuracy",
                    "Verify blockchain balance verification",
                    "Review exception resolution"
                ],
                evidence_required=[
                    "Reconciliation procedures",
                    "Reconciliation workpapers",
                    "Blockchain verification evidence",
                    "Exception resolution documentation"
                ],
                frequency="Daily",
                applicability="Crypto custodians"
            )
        ]
    },
    "STATE_MTL": {
        "regulation_name": "State Money Transmission Licensing",
        "authority": "State Regulators / NMLS",
        "requirements": [
            ComplianceRequirement(
                requirement_id="MTL-001",
                regulation="State MTL",
                requirement="License Maintenance",
                description="Maintain money transmitter licenses in all required jurisdictions.",
                testing_procedures=[
                    "Review license inventory",
                    "Verify license renewals",
                    "Test license condition compliance",
                    "Review expansion procedures"
                ],
                evidence_required=[
                    "License inventory",
                    "License copies",
                    "Renewal documentation",
                    "State examination reports"
                ],
                frequency="Ongoing with annual renewals",
                applicability="Money transmitters"
            ),
            ComplianceRequirement(
                requirement_id="MTL-002",
                regulation="State MTL",
                requirement="Net Worth Requirements",
                description="Maintain minimum net worth as required by state regulators.",
                testing_procedures=[
                    "Review net worth calculations",
                    "Verify compliance with state requirements",
                    "Test calculation methodology",
                    "Review financial reporting"
                ],
                evidence_required=[
                    "Net worth calculations",
                    "Financial statements",
                    "State requirement documentation",
                    "Auditor confirmation"
                ],
                frequency="Quarterly monitoring",
                applicability="Licensed money transmitters"
            ),
            ComplianceRequirement(
                requirement_id="MTL-003",
                regulation="State MTL",
                requirement="Surety Bond Requirements",
                description="Maintain surety bonds as required by state regulators.",
                testing_procedures=[
                    "Review bond inventory",
                    "Verify bond amounts meet requirements",
                    "Test bond renewal process",
                    "Review bond rider updates"
                ],
                evidence_required=[
                    "Bond certificates",
                    "State requirement matrix",
                    "Renewal documentation",
                    "Bond rider documentation"
                ],
                frequency="Annual renewal",
                applicability="Licensed money transmitters"
            ),
            ComplianceRequirement(
                requirement_id="MTL-004",
                regulation="State MTL",
                requirement="Permissible Investment Requirements",
                description="Maintain permissible investments to cover outstanding transmission liability.",
                testing_procedures=[
                    "Review investment policy",
                    "Test investment classification",
                    "Verify coverage calculations",
                    "Review investment reporting"
                ],
                evidence_required=[
                    "Investment policy",
                    "Investment reports",
                    "Coverage calculations",
                    "State filing documentation"
                ],
                frequency="Daily monitoring, quarterly reporting",
                applicability="Licensed money transmitters"
            )
        ]
    },
    "CUSTODY": {
        "regulation_name": "Crypto Custody Requirements",
        "authority": "Multiple (OCC, State Regulators, SEC)",
        "requirements": [
            ComplianceRequirement(
                requirement_id="CUS-001",
                regulation="Custody",
                requirement="Segregation of Customer Assets",
                description="Customer crypto assets must be segregated from company assets.",
                testing_procedures=[
                    "Review segregation procedures",
                    "Verify wallet structure",
                    "Test asset tracing capabilities",
                    "Review accounting treatment"
                ],
                evidence_required=[
                    "Segregation policy",
                    "Wallet architecture documentation",
                    "Account statements",
                    "Reconciliation reports"
                ],
                frequency="Continuous",
                applicability="All crypto custodians"
            ),
            ComplianceRequirement(
                requirement_id="CUS-002",
                regulation="Custody",
                requirement="Proof of Reserves",
                description="Demonstrate sufficient crypto assets to cover customer liabilities.",
                testing_procedures=[
                    "Review proof of reserves methodology",
                    "Verify cryptographic attestation",
                    "Test liability calculation",
                    "Review third-party audit"
                ],
                evidence_required=[
                    "Proof of reserves report",
                    "Cryptographic attestation",
                    "Liability reports",
                    "Third-party audit report"
                ],
                frequency="Monthly or as required",
                applicability="Crypto exchanges and custodians"
            ),
            ComplianceRequirement(
                requirement_id="CUS-003",
                regulation="Custody",
                requirement="Insurance Coverage",
                description="Maintain appropriate insurance coverage for custodied assets.",
                testing_procedures=[
                    "Review insurance policies",
                    "Verify coverage adequacy",
                    "Test claims procedures",
                    "Review policy exclusions"
                ],
                evidence_required=[
                    "Insurance policies",
                    "Coverage analysis",
                    "Broker confirmation",
                    "Claims history"
                ],
                frequency="Annual renewal with ongoing monitoring",
                applicability="Crypto custodians"
            ),
            ComplianceRequirement(
                requirement_id="CUS-004",
                regulation="Custody",
                requirement="Disaster Recovery for Custody Operations",
                description="Maintain DR/BC plans specific to crypto custody operations.",
                testing_procedures=[
                    "Review DR/BC plans",
                    "Verify key recovery procedures",
                    "Test failover capabilities",
                    "Review test results"
                ],
                evidence_required=[
                    "DR/BC plans",
                    "Key recovery procedures",
                    "Test documentation",
                    "Recovery time metrics"
                ],
                frequency="Annual testing",
                applicability="Crypto custodians"
            )
        ]
    }
}


# =============================================================================
# AUDIT FINDINGS TEMPLATES
# =============================================================================

class FindingSeverity(Enum):
    """Severity classification for audit findings"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class RemediationStatus(Enum):
    """Remediation status options"""
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    PENDING_VALIDATION = "pending_validation"
    CLOSED = "closed"
    RISK_ACCEPTED = "risk_accepted"
    OVERDUE = "overdue"


SEVERITY_DEFINITIONS = {
    FindingSeverity.CRITICAL: {
        "level": "Critical",
        "description": "Immediate action required. Significant control weakness that could result in material financial loss, major regulatory action, or severe reputational damage.",
        "response_time": "Immediate (within 24 hours)",
        "escalation": "Board of Directors and Executive Management",
        "examples": [
            "Private keys stored in plaintext",
            "No multi-signature controls on hot wallets",
            "Complete absence of transaction monitoring",
            "Unpatched critical vulnerabilities in custody systems"
        ]
    },
    FindingSeverity.HIGH: {
        "level": "High",
        "description": "Urgent action required. Significant control weakness that could result in financial loss, regulatory scrutiny, or reputational impact.",
        "response_time": "Within 30 days",
        "escalation": "Executive Management and Audit Committee",
        "examples": [
            "Inadequate segregation of duties",
            "Missing access reviews for privileged accounts",
            "Incomplete transaction monitoring rules",
            "Insufficient disaster recovery testing"
        ]
    },
    FindingSeverity.MEDIUM: {
        "level": "Medium",
        "description": "Timely action required. Moderate control weakness that could result in operational inefficiency or compliance gaps.",
        "response_time": "Within 90 days",
        "escalation": "Senior Management",
        "examples": [
            "Incomplete documentation of procedures",
            "Gaps in training records",
            "Minor policy violations",
            "Delayed access removal"
        ]
    },
    FindingSeverity.LOW: {
        "level": "Low",
        "description": "Action recommended. Minor control weakness or opportunity for improvement.",
        "response_time": "Within 180 days",
        "escalation": "Department Management",
        "examples": [
            "Documentation formatting inconsistencies",
            "Minor process efficiency opportunities",
            "Best practice recommendations",
            "Enhancement suggestions"
        ]
    }
}


@dataclass
class AuditFinding:
    """Data class representing an audit finding"""
    finding_id: str
    title: str
    severity: FindingSeverity
    status: RemediationStatus
    identified_date: date
    target_remediation_date: date
    actual_remediation_date: Optional[date]

    # Finding details
    condition: str  # What was found
    criteria: str  # What should be
    cause: str  # Why it occurred
    effect: str  # What is the risk/impact
    recommendation: str  # What to do

    # Classification
    coso_component: COSOComponent
    control_category: ControlCategory
    regulatory_reference: Optional[str]

    # Ownership
    process_owner: str
    audit_owner: str

    # Management response
    management_response: Optional[str] = None
    management_action_plan: Optional[str] = None

    # Validation
    validation_evidence: Optional[str] = None
    validation_date: Optional[date] = None
    validator: Optional[str] = None


FINDING_TEMPLATE = {
    "finding_id": "FINDING-YYYY-NNN",
    "title": "Brief descriptive title of the finding",
    "severity": "Critical / High / Medium / Low",
    "status": "Open / In Progress / Pending Validation / Closed / Risk Accepted",
    "identified_date": "YYYY-MM-DD",
    "target_remediation_date": "YYYY-MM-DD",
    "condition": "Describe what was found during the audit (the current state)",
    "criteria": "Describe what the expected state should be (policy, regulation, best practice)",
    "cause": "Describe why the condition exists (root cause analysis)",
    "effect": "Describe the risk or impact of the finding",
    "recommendation": "Describe the recommended corrective action",
    "coso_component": "Applicable COSO component",
    "control_category": "Applicable control category",
    "regulatory_reference": "Applicable regulation or standard reference",
    "process_owner": "Name and title of the responsible process owner",
    "audit_owner": "Name of the auditor who identified the finding",
    "management_response": "Management's response to the finding",
    "management_action_plan": "Specific actions management will take to remediate"
}


# Sample findings for demonstration
SAMPLE_AUDIT_FINDINGS = [
    AuditFinding(
        finding_id="FINDING-2024-001",
        title="Inadequate Multi-Signature Configuration on Hot Wallet",
        severity=FindingSeverity.CRITICAL,
        status=RemediationStatus.IN_PROGRESS,
        identified_date=date(2024, 1, 15),
        target_remediation_date=date(2024, 1, 22),
        actual_remediation_date=None,
        condition="The primary hot wallet holding approximately $5M in customer BTC is configured with a 1-of-3 multi-signature scheme, allowing any single authorized signer to initiate and complete transactions without additional approval.",
        criteria="Per the Crypto Asset Custody Policy (Section 4.2), all hot wallets must be configured with a minimum 2-of-3 multi-signature requirement. Industry best practice and SOC 2 Trust Services Criteria (CC6.1) require adequate authorization controls for high-value transactions.",
        cause="The wallet was initially configured during a rapid deployment phase in Q2 2023. The configuration was not updated when the policy was revised in Q4 2023 to require 2-of-3 signatures. No periodic review process exists to verify wallet configurations against policy requirements.",
        effect="A single compromised or malicious signer could transfer all funds from the hot wallet without detection or prevention. This represents a significant financial risk and potential regulatory violation.",
        recommendation="1. Immediately reconfigure the hot wallet to require 2-of-3 signatures. 2. Implement a quarterly wallet configuration review process. 3. Update deployment procedures to include configuration verification checklist.",
        coso_component=COSOComponent.CONTROL_ACTIVITIES,
        control_category=ControlCategory.WALLET_MANAGEMENT,
        regulatory_reference="SOC 2 CC6.1, State MTL Custody Requirements",
        process_owner="John Smith, Crypto Operations Manager",
        audit_owner="Jane Doe, Internal Auditor",
        management_response="Management agrees with the finding. The hot wallet configuration will be updated immediately.",
        management_action_plan="1. Emergency change request submitted for wallet reconfiguration (Target: Jan 17). 2. Quarterly configuration review process to be documented and implemented (Target: Feb 15). 3. Deployment checklist to be updated (Target: Feb 28)."
    ),
    AuditFinding(
        finding_id="FINDING-2024-002",
        title="Incomplete Transaction Monitoring Rule Coverage",
        severity=FindingSeverity.HIGH,
        status=RemediationStatus.OPEN,
        identified_date=date(2024, 1, 20),
        target_remediation_date=date(2024, 3, 20),
        actual_remediation_date=None,
        condition="Review of transaction monitoring rules identified that only 60% of required scenarios from the BSA/AML risk assessment are covered by active monitoring rules. Specifically, rules for detecting structuring patterns, rapid movement of funds, and high-risk jurisdiction activity are either missing or inactive.",
        criteria="FinCEN BSA/AML requirements and the company's AML Program require transaction monitoring to detect and report suspicious activity. The risk assessment identified 25 key scenarios requiring monitoring; only 15 have active rules.",
        cause="The transaction monitoring system was implemented in phases, with Phase 2 rules (covering the missing scenarios) delayed due to technology constraints. No tracking mechanism exists to ensure all required rules are implemented.",
        effect="Suspicious activity may go undetected, resulting in potential regulatory violations, SAR filing failures, and increased money laundering risk exposure.",
        recommendation="1. Develop and implement the missing 10 monitoring rules within 60 days. 2. Implement a rule coverage tracking matrix. 3. Conduct quarterly gap assessments between risk assessment and monitoring coverage.",
        coso_component=COSOComponent.MONITORING_ACTIVITIES,
        control_category=ControlCategory.TRANSACTION_APPROVAL,
        regulatory_reference="BSA/AML, FinCEN SAR Requirements",
        process_owner="Sarah Johnson, BSA Officer",
        audit_owner="Jane Doe, Internal Auditor",
        management_response=None,
        management_action_plan=None
    ),
    AuditFinding(
        finding_id="FINDING-2024-003",
        title="Access Review Not Completed Timely for Privileged Accounts",
        severity=FindingSeverity.MEDIUM,
        status=RemediationStatus.PENDING_VALIDATION,
        identified_date=date(2024, 1, 10),
        target_remediation_date=date(2024, 2, 28),
        actual_remediation_date=date(2024, 2, 25),
        condition="The Q4 2023 quarterly access review for privileged accounts was completed 45 days after the required deadline. 3 of 50 privileged accounts (6%) were identified as belonging to terminated employees and had not been disabled.",
        criteria="Access Management Policy requires quarterly access reviews to be completed within 30 days of quarter end. SOX ITGC requirements mandate timely access reviews for privileged accounts.",
        cause="The access review process relies on manual extraction of user lists and manager attestation via email. The process owner was on extended leave, and no backup was assigned.",
        effect="Terminated employees retained privileged access to production systems, creating potential for unauthorized access and data breach.",
        recommendation="1. Disable the 3 identified terminated employee accounts immediately. 2. Implement automated access review workflow with backup assignment. 3. Consider implementing an identity governance solution.",
        coso_component=COSOComponent.MONITORING_ACTIVITIES,
        control_category=ControlCategory.ACCESS_MANAGEMENT,
        regulatory_reference="SOX Section 404, SOC 2 CC6.2",
        process_owner="Mike Williams, IT Security Manager",
        audit_owner="Jane Doe, Internal Auditor",
        management_response="Management agrees with the finding. The terminated employee accounts have been disabled. Process improvements are underway.",
        management_action_plan="1. Accounts disabled on Jan 11. 2. Backup process owner assigned (completed Feb 1). 3. Automated workflow implementation in progress (Target: Q2 2024).",
        validation_evidence="Screenshot of disabled accounts in AD, updated RACI matrix for access review process",
        validation_date=date(2024, 2, 26),
        validator="Jane Doe, Internal Auditor"
    ),
    AuditFinding(
        finding_id="FINDING-2024-004",
        title="Key Ceremony Documentation Incomplete",
        severity=FindingSeverity.MEDIUM,
        status=RemediationStatus.CLOSED,
        identified_date=date(2023, 11, 15),
        target_remediation_date=date(2024, 1, 15),
        actual_remediation_date=date(2024, 1, 10),
        condition="Review of the November 2023 key generation ceremony documentation identified that witness signatures were missing from 2 of 5 required attestation forms, and the video recording was incomplete (missing final 15 minutes).",
        criteria="Key Management Policy requires complete documentation of all key ceremonies including witness signatures on all attestation forms and uninterrupted video recording of the entire ceremony.",
        cause="The ceremony coordinator was not aware of updated documentation requirements implemented in September 2023. No checklist was provided to verify completeness before ceremony conclusion.",
        effect="Incomplete documentation could result in questions about the integrity of generated keys and non-compliance with custody requirements.",
        recommendation="1. Obtain missing witness signatures through supplemental attestation. 2. Develop and implement a key ceremony checklist. 3. Conduct training on updated requirements for all potential ceremony participants.",
        coso_component=COSOComponent.CONTROL_ACTIVITIES,
        control_category=ControlCategory.KEY_CUSTODY,
        regulatory_reference="SOC 2 CC6.7, Custody Best Practices",
        process_owner="David Chen, Security Operations Manager",
        audit_owner="Jane Doe, Internal Auditor",
        management_response="Management agrees with the finding and has implemented corrective actions.",
        management_action_plan="1. Supplemental attestations obtained (completed Nov 20). 2. Key ceremony checklist developed and approved (completed Dec 15). 3. Training completed for all authorized ceremony participants (completed Jan 5).",
        validation_evidence="Signed supplemental attestations, approved checklist document, training completion records",
        validation_date=date(2024, 1, 12),
        validator="Jane Doe, Internal Auditor"
    ),
    AuditFinding(
        finding_id="FINDING-2024-005",
        title="Opportunity to Enhance Wallet Address Verification Process",
        severity=FindingSeverity.LOW,
        status=RemediationStatus.RISK_ACCEPTED,
        identified_date=date(2024, 1, 25),
        target_remediation_date=date(2024, 7, 25),
        actual_remediation_date=None,
        condition="The current wallet address verification process requires manual comparison of addresses during the whitelist approval process. No automated checksum validation or address format verification is performed.",
        criteria="Industry best practices recommend automated address validation to prevent typographical errors and ensure address format correctness before whitelisting.",
        cause="The current whitelist management system was developed in-house and does not include automated validation features. This was identified as a Phase 2 enhancement but has not been prioritized.",
        effect="Potential for human error during address verification, which could result in funds being sent to incorrect addresses. Current compensating control of dual verification mitigates immediate risk.",
        recommendation="Implement automated address checksum validation and format verification in the whitelist management system.",
        coso_component=COSOComponent.CONTROL_ACTIVITIES,
        control_category=ControlCategory.WALLET_MANAGEMENT,
        regulatory_reference=None,
        process_owner="John Smith, Crypto Operations Manager",
        audit_owner="Jane Doe, Internal Auditor",
        management_response="Management acknowledges the recommendation. Given the compensating control of dual verification and current technology roadmap priorities, management accepts the current risk level.",
        management_action_plan="Risk acceptance documented. Enhancement added to technology roadmap for consideration in Q4 2024 planning cycle."
    )
]


# =============================================================================
# SAMPLE TRANSACTION DATA FOR DEMONSTRATION
# =============================================================================

@dataclass
class CryptoTransaction:
    """Data class representing a cryptocurrency transaction"""
    transaction_id: str
    transaction_hash: str
    blockchain: str
    transaction_type: str  # deposit, withdrawal, transfer, trade
    timestamp: datetime

    # Asset details
    asset_symbol: str
    asset_name: str
    amount: float
    amount_usd: float

    # Addresses
    from_address: str
    to_address: str
    from_address_label: Optional[str]
    to_address_label: Optional[str]

    # Transaction details
    fee: float
    fee_usd: float
    confirmations: int
    block_number: int

    # Risk indicators
    risk_score: int  # 0-100
    risk_flags: List[str]
    sanctions_check: str  # clear, hit, pending

    # Internal tracking
    customer_id: Optional[str]
    account_id: Optional[str]
    internal_reference: Optional[str]
    notes: Optional[str]


SAMPLE_TRANSACTIONS = [
    CryptoTransaction(
        transaction_id="TXN-2024-00001",
        transaction_hash="0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        blockchain="Ethereum",
        transaction_type="deposit",
        timestamp=datetime(2024, 1, 15, 10, 30, 0),
        asset_symbol="ETH",
        asset_name="Ethereum",
        amount=10.5,
        amount_usd=25200.00,
        from_address="0xExternalAddress1234567890abcdef12345678",
        to_address="0xCompanyHotWallet1234567890abcdef12345",
        from_address_label="Customer Deposit",
        to_address_label="Hot Wallet 1",
        fee=0.002,
        fee_usd=4.80,
        confirmations=50,
        block_number=19000001,
        risk_score=15,
        risk_flags=[],
        sanctions_check="clear",
        customer_id="CUST-10001",
        account_id="ACC-20001",
        internal_reference="DEP-2024-0001",
        notes="Regular customer deposit"
    ),
    CryptoTransaction(
        transaction_id="TXN-2024-00002",
        transaction_hash="abc123def456789012345678901234567890123456789012345678901234abcd",
        blockchain="Bitcoin",
        transaction_type="withdrawal",
        timestamp=datetime(2024, 1, 15, 14, 45, 0),
        asset_symbol="BTC",
        asset_name="Bitcoin",
        amount=2.5,
        amount_usd=107500.00,
        from_address="bc1qCompanyHotWallet123456789012345678901234",
        to_address="bc1qCustomerWithdrawal12345678901234567890",
        from_address_label="Hot Wallet 2",
        to_address_label="Customer Withdrawal",
        fee=0.0001,
        fee_usd=4.30,
        confirmations=6,
        block_number=825001,
        risk_score=25,
        risk_flags=["Large withdrawal", "First-time destination"],
        sanctions_check="clear",
        customer_id="CUST-10002",
        account_id="ACC-20002",
        internal_reference="WD-2024-0001",
        notes="Customer withdrawal - verified via 2FA"
    ),
    CryptoTransaction(
        transaction_id="TXN-2024-00003",
        transaction_hash="0xfedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321",
        blockchain="Ethereum",
        transaction_type="transfer",
        timestamp=datetime(2024, 1, 15, 16, 0, 0),
        asset_symbol="USDC",
        asset_name="USD Coin",
        amount=500000.00,
        amount_usd=500000.00,
        from_address="0xCompanyHotWallet1234567890abcdef12345",
        to_address="0xCompanyColdStorage1234567890abcdef123",
        from_address_label="Hot Wallet 1",
        to_address_label="Cold Storage 1",
        fee=15.00,
        fee_usd=15.00,
        confirmations=100,
        block_number=19000500,
        risk_score=5,
        risk_flags=[],
        sanctions_check="clear",
        customer_id=None,
        account_id=None,
        internal_reference="INT-2024-0001",
        notes="Scheduled hot-to-cold rebalancing"
    ),
    CryptoTransaction(
        transaction_id="TXN-2024-00004",
        transaction_hash="def789abc012345678901234567890123456789012345678901234567890defg",
        blockchain="Bitcoin",
        transaction_type="deposit",
        timestamp=datetime(2024, 1, 16, 9, 15, 0),
        asset_symbol="BTC",
        asset_name="Bitcoin",
        amount=0.5,
        amount_usd=21500.00,
        from_address="bc1qSuspiciousAddress12345678901234567890123",
        to_address="bc1qCompanyHotWallet123456789012345678901234",
        from_address_label="Unknown",
        to_address_label="Hot Wallet 2",
        fee=0.00005,
        fee_usd=2.15,
        confirmations=3,
        block_number=825100,
        risk_score=75,
        risk_flags=["High-risk jurisdiction", "Mixing service detected", "Rapid movement"],
        sanctions_check="pending",
        customer_id="CUST-10003",
        account_id="ACC-20003",
        internal_reference="DEP-2024-0002",
        notes="ALERT: Flagged for enhanced review - potential mixing service"
    ),
    CryptoTransaction(
        transaction_id="TXN-2024-00005",
        transaction_hash="0x9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba",
        blockchain="Ethereum",
        transaction_type="trade",
        timestamp=datetime(2024, 1, 16, 11, 30, 0),
        asset_symbol="ETH",
        asset_name="Ethereum",
        amount=50.0,
        amount_usd=120000.00,
        from_address="0xCompanyTradingWallet123456789012345678",
        to_address="0xExchangeHotWallet1234567890123456789012",
        from_address_label="Trading Wallet",
        to_address_label="Exchange A",
        fee=0.01,
        fee_usd=24.00,
        confirmations=25,
        block_number=19001000,
        risk_score=20,
        risk_flags=["Large trade"],
        sanctions_check="clear",
        customer_id=None,
        account_id=None,
        internal_reference="TRD-2024-0001",
        notes="OTC trade execution - approved by trading desk"
    ),
    CryptoTransaction(
        transaction_id="TXN-2024-00006",
        transaction_hash="ghi456jkl789012345678901234567890123456789012345678901234567hijkl",
        blockchain="Bitcoin",
        transaction_type="withdrawal",
        timestamp=datetime(2024, 1, 16, 15, 0, 0),
        asset_symbol="BTC",
        asset_name="Bitcoin",
        amount=0.1,
        amount_usd=4300.00,
        from_address="bc1qCompanyHotWallet123456789012345678901234",
        to_address="bc1qSanctionedAddress123456789012345678901",
        from_address_label="Hot Wallet 2",
        to_address_label="BLOCKED - Sanctioned",
        fee=0.0,
        fee_usd=0.0,
        confirmations=0,
        block_number=0,
        risk_score=100,
        risk_flags=["Sanctioned address", "OFAC hit"],
        sanctions_check="hit",
        customer_id="CUST-10004",
        account_id="ACC-20004",
        internal_reference="WD-2024-0002",
        notes="BLOCKED: Withdrawal attempt to sanctioned address - reported to compliance"
    ),
    CryptoTransaction(
        transaction_id="TXN-2024-00007",
        transaction_hash="0xabcdef123456789012345678901234567890123456789012345678901234abcd",
        blockchain="Ethereum",
        transaction_type="deposit",
        timestamp=datetime(2024, 1, 17, 8, 0, 0),
        asset_symbol="USDT",
        asset_name="Tether USD",
        amount=1000000.00,
        amount_usd=1000000.00,
        from_address="0xInstitutionalClient1234567890123456789",
        to_address="0xCompanyHotWallet1234567890abcdef12345",
        from_address_label="Institutional Client A",
        to_address_label="Hot Wallet 1",
        fee=50.00,
        fee_usd=50.00,
        confirmations=200,
        block_number=19002000,
        risk_score=10,
        risk_flags=[],
        sanctions_check="clear",
        customer_id="CUST-10005",
        account_id="ACC-20005",
        internal_reference="DEP-2024-0003",
        notes="Institutional deposit - KYC complete"
    ),
    CryptoTransaction(
        transaction_id="TXN-2024-00008",
        transaction_hash="mno789pqr012345678901234567890123456789012345678901234567890mnop",
        blockchain="Bitcoin",
        transaction_type="deposit",
        timestamp=datetime(2024, 1, 17, 10, 30, 0),
        asset_symbol="BTC",
        asset_name="Bitcoin",
        amount=0.009,
        amount_usd=387.00,
        from_address="bc1qUnknownSource123456789012345678901234567",
        to_address="bc1qCompanyHotWallet123456789012345678901234",
        from_address_label="Unknown",
        to_address_label="Hot Wallet 2",
        fee=0.00001,
        fee_usd=0.43,
        confirmations=1,
        block_number=825500,
        risk_score=45,
        risk_flags=["Structuring pattern detected", "Multiple small deposits"],
        sanctions_check="clear",
        customer_id="CUST-10006",
        account_id="ACC-20006",
        internal_reference="DEP-2024-0004",
        notes="Part of potential structuring pattern - under review"
    ),
    CryptoTransaction(
        transaction_id="TXN-2024-00009",
        transaction_hash="0x1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff",
        blockchain="Ethereum",
        transaction_type="withdrawal",
        timestamp=datetime(2024, 1, 17, 14, 15, 0),
        asset_symbol="ETH",
        asset_name="Ethereum",
        amount=5.0,
        amount_usd=12000.00,
        from_address="0xCompanyHotWallet1234567890abcdef12345",
        to_address="0xVerifiedCustomerAddress12345678901234567",
        from_address_label="Hot Wallet 1",
        to_address_label="Customer - Whitelisted",
        fee=0.003,
        fee_usd=7.20,
        confirmations=30,
        block_number=19002500,
        risk_score=10,
        risk_flags=[],
        sanctions_check="clear",
        customer_id="CUST-10007",
        account_id="ACC-20007",
        internal_reference="WD-2024-0003",
        notes="Standard withdrawal to whitelisted address"
    ),
    CryptoTransaction(
        transaction_id="TXN-2024-00010",
        transaction_hash="qrs456tuv789012345678901234567890123456789012345678901234567qrstu",
        blockchain="Bitcoin",
        transaction_type="transfer",
        timestamp=datetime(2024, 1, 17, 18, 0, 0),
        asset_symbol="BTC",
        asset_name="Bitcoin",
        amount=100.0,
        amount_usd=4300000.00,
        from_address="bc1qCompanyColdStorage12345678901234567890",
        to_address="bc1qCompanyHotWallet123456789012345678901234",
        from_address_label="Cold Storage 1",
        to_address_label="Hot Wallet 2",
        fee=0.0002,
        fee_usd=8.60,
        confirmations=10,
        block_number=825750,
        risk_score=5,
        risk_flags=[],
        sanctions_check="clear",
        customer_id=None,
        account_id=None,
        internal_reference="INT-2024-0002",
        notes="Cold-to-hot rebalancing - approved by treasury (3-of-5 multisig)"
    )
]


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def get_controls_by_category(category: ControlCategory) -> List[Control]:
    """Get all controls for a specific category"""
    return CRYPTO_CONTROLS_LIBRARY.get(category, [])


def get_controls_by_coso_component(component: COSOComponent) -> List[Control]:
    """Get all controls mapped to a specific COSO component"""
    controls = []
    for category_controls in CRYPTO_CONTROLS_LIBRARY.values():
        for control in category_controls:
            if control.coso_component == component:
                controls.append(control)
    return controls


def get_compliance_requirements(regulation_key: str) -> List[ComplianceRequirement]:
    """Get all requirements for a specific regulation"""
    regulation_data = REGULATORY_COMPLIANCE_CHECKLISTS.get(regulation_key, {})
    return regulation_data.get("requirements", [])


def get_findings_by_severity(severity: FindingSeverity) -> List[AuditFinding]:
    """Get all sample findings of a specific severity"""
    return [f for f in SAMPLE_AUDIT_FINDINGS if f.severity == severity]


def get_findings_by_status(status: RemediationStatus) -> List[AuditFinding]:
    """Get all sample findings with a specific status"""
    return [f for f in SAMPLE_AUDIT_FINDINGS if f.status == status]


def get_open_findings() -> List[AuditFinding]:
    """Get all open findings (not closed or risk accepted)"""
    closed_statuses = [RemediationStatus.CLOSED, RemediationStatus.RISK_ACCEPTED]
    return [f for f in SAMPLE_AUDIT_FINDINGS if f.status not in closed_statuses]


def get_high_risk_transactions(threshold: int = 50) -> List[CryptoTransaction]:
    """Get transactions with risk score above threshold"""
    return [t for t in SAMPLE_TRANSACTIONS if t.risk_score >= threshold]


def get_transactions_by_type(transaction_type: str) -> List[CryptoTransaction]:
    """Get transactions of a specific type"""
    return [t for t in SAMPLE_TRANSACTIONS if t.transaction_type == transaction_type]


def generate_finding_id() -> str:
    """Generate a new finding ID"""
    year = datetime.now().year
    # In a real application, this would query the database for the next sequence number
    sequence = str(uuid.uuid4().int)[:5]
    return f"FINDING-{year}-{sequence}"


def generate_transaction_id() -> str:
    """Generate a new transaction ID"""
    year = datetime.now().year
    sequence = str(uuid.uuid4().int)[:5]
    return f"TXN-{year}-{sequence}"


# =============================================================================
# SUMMARY STATISTICS (for dashboard display)
# =============================================================================

def get_control_summary() -> Dict[str, Any]:
    """Get summary statistics for controls library"""
    total_controls = sum(len(controls) for controls in CRYPTO_CONTROLS_LIBRARY.values())

    by_category = {
        category.value: len(controls)
        for category, controls in CRYPTO_CONTROLS_LIBRARY.items()
    }

    by_type = {"Preventive": 0, "Detective": 0, "Corrective": 0}
    for controls in CRYPTO_CONTROLS_LIBRARY.values():
        for control in controls:
            if control.control_type in by_type:
                by_type[control.control_type] += 1

    return {
        "total_controls": total_controls,
        "by_category": by_category,
        "by_type": by_type
    }


def get_compliance_summary() -> Dict[str, Any]:
    """Get summary statistics for compliance requirements"""
    total_requirements = 0
    by_regulation = {}

    for reg_key, reg_data in REGULATORY_COMPLIANCE_CHECKLISTS.items():
        req_count = len(reg_data.get("requirements", []))
        by_regulation[reg_data.get("regulation_name", reg_key)] = req_count
        total_requirements += req_count

    return {
        "total_requirements": total_requirements,
        "by_regulation": by_regulation
    }


def get_findings_summary() -> Dict[str, Any]:
    """Get summary statistics for audit findings"""
    by_severity = {
        severity.value: len(get_findings_by_severity(severity))
        for severity in FindingSeverity
    }

    by_status = {
        status.value: len(get_findings_by_status(status))
        for status in RemediationStatus
    }

    open_findings = len(get_open_findings())

    return {
        "total_findings": len(SAMPLE_AUDIT_FINDINGS),
        "open_findings": open_findings,
        "by_severity": by_severity,
        "by_status": by_status
    }


def get_transaction_summary() -> Dict[str, Any]:
    """Get summary statistics for sample transactions"""
    total_volume_usd = sum(t.amount_usd for t in SAMPLE_TRANSACTIONS)

    by_type = {}
    for t in SAMPLE_TRANSACTIONS:
        by_type[t.transaction_type] = by_type.get(t.transaction_type, 0) + 1

    high_risk_count = len(get_high_risk_transactions())
    sanctions_hits = len([t for t in SAMPLE_TRANSACTIONS if t.sanctions_check == "hit"])

    return {
        "total_transactions": len(SAMPLE_TRANSACTIONS),
        "total_volume_usd": total_volume_usd,
        "by_type": by_type,
        "high_risk_count": high_risk_count,
        "sanctions_hits": sanctions_hits
    }


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__ = [
    # Enums
    "COSOComponent",
    "ControlCategory",
    "LikelihoodRating",
    "ImpactRating",
    "RiskLevel",
    "FindingSeverity",
    "RemediationStatus",

    # Data structures
    "COSO_FRAMEWORK",
    "CRYPTO_CONTROLS_LIBRARY",
    "LIKELIHOOD_DEFINITIONS",
    "IMPACT_DEFINITIONS",
    "RISK_SCORING_MATRIX",
    "RISK_LEVEL_THRESHOLDS",
    "RISK_APPETITE_THRESHOLDS",
    "REGULATORY_COMPLIANCE_CHECKLISTS",
    "SEVERITY_DEFINITIONS",
    "FINDING_TEMPLATE",
    "SAMPLE_AUDIT_FINDINGS",
    "SAMPLE_TRANSACTIONS",

    # Data classes
    "Control",
    "ComplianceRequirement",
    "AuditFinding",
    "CryptoTransaction",

    # Utility functions
    "calculate_risk_score",
    "get_risk_level",
    "get_controls_by_category",
    "get_controls_by_coso_component",
    "get_compliance_requirements",
    "get_findings_by_severity",
    "get_findings_by_status",
    "get_open_findings",
    "get_high_risk_transactions",
    "get_transactions_by_type",
    "generate_finding_id",
    "generate_transaction_id",

    # Summary functions
    "get_control_summary",
    "get_compliance_summary",
    "get_findings_summary",
    "get_transaction_summary"
]
