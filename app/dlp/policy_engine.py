"""
app/dlp/policy_engine.py
────────────────────────
Evaluates DLP security policies against detected findings.
Reads policies/default.yaml with safe in-code defaults fallback.

Rules:
- destination == "external":
    Aadhaar / Card / Secrets / JWT / Password => BLOCK
    PAN / Phone / Email / Bank / etc.        => REDACT_AND_FORWARD
    None                                      => ALLOW
- destination == "internal":
    Secrets / Password                        => BLOCK
    Aadhaar / Card                            => REDACT_AND_FORWARD
    None                                      => ALLOW
- Sensitivity classification:
    CONFIDENTIAL if critical entity or risk_score >= 50
    INTERNAL if moderate PII or risk_score >= 20
    PUBLIC otherwise
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import List, Optional, Set
import yaml

from app.dlp.models import DLPAction, DLPDecision, DLPFinding, DLPSensitivity


_DEFAULT_POLICY_PATH = Path("policies/default.yaml")

# Fallback definitions if YAML file is unavailable
_FALLBACK_DESTINATIONS = {
    "external": {
        "block": {"AADHAAR", "CREDIT_CARD", "SECRET_KEY", "JWT_TOKEN", "PASSWORD"},
        "redact": {
            "PAN", "PHONE", "EMAIL", "PASSPORT", "VOTER_ID", "GSTIN",
            "BANK_ACCOUNT", "NAME", "ADDRESS", "FINANCIAL", "DATE_OF_BIRTH"
        },
    },
    "internal": {
        "block": {"SECRET_KEY", "PASSWORD"},
        "redact": {
            "AADHAAR", "CREDIT_CARD", "PAN", "PHONE", "EMAIL", "PASSPORT",
            "VOTER_ID", "GSTIN", "BANK_ACCOUNT", "NAME", "ADDRESS"
        },
    },
}

_ENTITY_RISK_WEIGHTS = {
    "SECRET_KEY": 40.0,
    "PASSWORD": 40.0,
    "JWT_TOKEN": 35.0,
    "AADHAAR": 35.0,
    "CREDIT_CARD": 35.0,
    "PAN": 25.0,
    "PASSPORT": 25.0,
    "BANK_ACCOUNT": 25.0,
    "GSTIN": 20.0,
    "PHONE": 15.0,
    "EMAIL": 15.0,
    "VOTER_ID": 15.0,
    "NAME": 10.0,
    "ADDRESS": 10.0,
    "FINANCIAL": 20.0,
    "DATE_OF_BIRTH": 10.0,
}


class DLPPolicyEngine:
    """Evaluates DLP policies against findings for a given destination and department."""

    def __init__(self, policy_path: Optional[Path | str] = None) -> None:
        path = Path(policy_path) if policy_path else _DEFAULT_POLICY_PATH
        self.destination_rules = dict(_FALLBACK_DESTINATIONS)
        self.confidential_types: Set[str] = {
            "AADHAAR", "CREDIT_CARD", "SECRET_KEY", "JWT_TOKEN", "PASSWORD"
        }
        self.internal_types: Set[str] = {
            "PAN", "PHONE", "EMAIL", "PASSPORT", "VOTER_ID", "GSTIN",
            "BANK_ACCOUNT", "NAME", "ADDRESS", "FINANCIAL", "DATE_OF_BIRTH"
        }
        self.risk_threshold_confidential = 50.0
        self.risk_threshold_internal = 20.0

        if path.is_file():
            try:
                with open(path, "r", encoding="utf-8") as f:
                    cfg = yaml.safe_load(f) or {}

                rules = cfg.get("destination_rules", {})
                for dest, spec in rules.items():
                    self.destination_rules[dest.lower()] = {
                        "block": set(spec.get("block_types", [])),
                        "redact": set(spec.get("redact_types", [])),
                    }

                sens = cfg.get("sensitivity_classification", {})
                if "confidential_types" in sens:
                    self.confidential_types = set(sens["confidential_types"])
                if "internal_types" in sens:
                    self.internal_types = set(sens["internal_types"])
                thresholds = sens.get("risk_thresholds", {})
                self.risk_threshold_confidential = float(thresholds.get("confidential", 50.0))
                self.risk_threshold_internal = float(thresholds.get("internal", 20.0))
            except Exception:
                # Retain safe fallbacks if YAML parsing fails
                pass

    def calculate_risk_score(self, findings: List[DLPFinding]) -> float:
        """Calculate composite risk score (0.0 to 100.0) based on detected findings."""
        if not findings:
            return 0.0

        score = 0.0
        seen_types: Set[str] = set()

        for f in findings:
            w = _ENTITY_RISK_WEIGHTS.get(f.entity_type, 10.0)
            # Repeated entities add diminished marginal weight
            if f.entity_type not in seen_types:
                score += w
                seen_types.add(f.entity_type)
            else:
                score += w * 0.2

        # Linkability factor: combinations of distinct PII types increase overall risk
        if len(seen_types) >= 3:
            score += 15.0
        elif len(seen_types) >= 2:
            score += 8.0

        return min(round(score, 1), 100.0)

    def determine_sensitivity(self, findings: List[DLPFinding], risk_score: float) -> DLPSensitivity:
        """Classify document sensitivity tier."""
        found_types = {f.entity_type for f in findings}
        if any(t in self.confidential_types for t in found_types) or risk_score >= self.risk_threshold_confidential:
            return DLPSensitivity.CONFIDENTIAL
        if any(t in self.internal_types for t in found_types) or risk_score >= self.risk_threshold_internal:
            return DLPSensitivity.INTERNAL
        return DLPSensitivity.PUBLIC

    def evaluate(
        self,
        findings: List[DLPFinding],
        destination: str = "external",
        department: Optional[str] = None,
    ) -> DLPDecision:
        """
        Evaluate DLP policy rules for findings, destination, and department.
        Returns a DLPDecision.
        """
        risk_score = self.calculate_risk_score(findings)
        sensitivity = self.determine_sensitivity(findings, risk_score)

        if not findings:
            return DLPDecision(
                action=DLPAction.ALLOW,
                reasons=["No sensitive PII or credentials detected. Safe to forward."],
                risk_score=risk_score,
                sensitivity=sensitivity,
            )

        norm_dest = (destination or "external").strip().lower()
        rule_set = self.destination_rules.get(norm_dest, self.destination_rules.get("external", {}))
        block_types = rule_set.get("block", set())
        redact_types = rule_set.get("redact", set())

        blocked_found = [f.entity_type for f in findings if f.entity_type in block_types]
        redact_found = [f.entity_type for f in findings if f.entity_type in redact_types]

        reasons: List[str] = []

        if blocked_found:
            unique_blocks = sorted(set(blocked_found))
            reasons.append(
                f"Policy violation: Critical entities [{', '.join(unique_blocks)}] cannot be transmitted to destination '{norm_dest}'."
            )
            return DLPDecision(
                action=DLPAction.BLOCK,
                reasons=reasons,
                risk_score=risk_score,
                sensitivity=sensitivity,
            )

        if redact_found:
            unique_redacts = sorted(set(redact_found))
            reasons.append(
                f"Policy requirement: Entities [{', '.join(unique_redacts)}] must be redacted prior to dispatching to '{norm_dest}'."
            )
            return DLPDecision(
                action=DLPAction.REDACT_AND_FORWARD,
                reasons=reasons,
                risk_score=risk_score,
                sensitivity=sensitivity,
            )

        # Fallback if findings didn't hit explicit block or redact rules
        return DLPDecision(
            action=DLPAction.ALLOW,
            reasons=["All detected entities are permissible for destination under current policy."],
            risk_score=risk_score,
            sensitivity=sensitivity,
        )


_DEFAULT_POLICY_ENGINE = DLPPolicyEngine()


def evaluate_dlp_policy(
    findings: List[DLPFinding],
    destination: str = "external",
    department: Optional[str] = None,
) -> DLPDecision:
    """Evaluate DLP policies using default engine instance."""
    return _DEFAULT_POLICY_ENGINE.evaluate(findings, destination, department)
