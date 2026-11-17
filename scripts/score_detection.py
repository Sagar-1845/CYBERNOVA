#!/usr/bin/env python3
"""
scripts/score_detection.py
──────────────────────────
Benchmark scoring script for ZeroLeak AI detection and masking evaluation.
Evaluates sanitized output and detected entities against ground-truth answer keys.

Outputs detailed Markdown and JSON reports in tests/reports/<run-name>.(md|json).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from typing import Any, Dict, List, Optional, Set, Tuple

# Add repository root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.privacy.detector import detect_pii, DetectedEntity


def mask_text_from_detections(original_text: str, entities: List[DetectedEntity]) -> Tuple[str, Dict[str, str]]:
    """Mask text using placeholders based on detected entities (descending order)."""
    # Sort descending by start to avoid shifting indices
    sorted_entities = sorted(entities, key=lambda e: (e.start, -(e.end - e.start)), reverse=True)
    sanitized = original_text
    vault: Dict[str, str] = {}
    type_counts: Dict[str, int] = {}

    # Deduplicate overlapping spans
    deduped: List[DetectedEntity] = []
    occupied_start = len(original_text) + 1
    for ent in sorted_entities:
        if ent.end <= occupied_start:
            deduped.append(ent)
            occupied_start = ent.start

    for ent in deduped:
        etype = ent.entity_type
        type_counts[etype] = type_counts.get(etype, 0) + 1
        placeholder = f"[{etype}_{type_counts[etype]}]"
        vault[placeholder] = ent.value
        sanitized = sanitized[:ent.start] + placeholder + sanitized[:ent.end][len(sanitized[:ent.end]):] + sanitized[ent.end:]

    return sanitized, vault


def check_partial_leaks(sanitized: str, entities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Check if any >=3-digit fragment of a masked entity was leaked adjacent to placeholders (e.g. [AADHAAR_3] 6467)."""
    partial_leaks = []
    for m in re.finditer(r"(\[[A-Z_]+_\d+\]\s*\d{3,8}|\d{3,8}\s*\[[A-Z_]+_\d+\])", sanitized):
        partial_leaks.append({
            "entity": m.group(0),
            "fragment": m.group(0),
            "type": "ADJACENT_ORPHANED_DIGITS"
        })
    return partial_leaks


def evaluate_document(
    doc_text: str,
    answer_key: Dict[str, Any],
    detected_entities: List[DetectedEntity],
    sanitized_text: str,
) -> Dict[str, Any]:
    """Evaluate detection and masking quality against ground-truth answer key."""
    t1_expected = answer_key.get("tier_1_entities", [])
    t2_expected = answer_key.get("tier_2_entities", [])
    traps = answer_key.get("must_not_flag_traps", [])

    # Map detected spans and types
    detected_spans = {(e.start, e.end): e for e in detected_entities}
    detected_values = {e.value.strip(): e for e in detected_entities}

    def evaluate_tier(expected_list: List[Dict[str, Any]], tier_name: str) -> Dict[str, Any]:
        correct = 0
        type_mismatches = []
        misses = []

        for exp in expected_list:
            exp_val = exp["value"].strip()
            exp_type = exp["type"]
            exp_start = exp.get("start")
            exp_end = exp.get("end")

            # Check if value is still verbatim present in sanitized text
            present_verbatim = exp_val in sanitized_text

            # Match by span or value
            matched_entity: Optional[DetectedEntity] = None
            if exp_start is not None and exp_end is not None and (exp_start, exp_end) in detected_spans:
                matched_entity = detected_spans[(exp_start, exp_end)]
            elif exp_val in detected_values:
                matched_entity = detected_values[exp_val]
            else:
                # Substring check for near match
                for dval, dent in detected_values.items():
                    if exp_val in dval or dval in exp_val:
                        matched_entity = dent
                        break

            if not present_verbatim and matched_entity is not None:
                # Value was masked
                det_type = matched_entity.entity_type
                # Normalize type synonyms
                is_type_match = (
                    det_type == exp_type or
                    (exp_type == "PERSON" and det_type in ("NAME", "PERSON")) or
                    (exp_type == "NAME" and det_type in ("NAME", "PERSON")) or
                    (exp_type.startswith("SECRET") and det_type == "SECRET")
                )
                if is_type_match:
                    correct += 1
                else:
                    type_mismatches.append({
                        "expected_type": exp_type,
                        "detected_type": det_type,
                        "value": exp_val
                    })
            else:
                misses.append({
                    "type": exp_type,
                    "value": exp_val,
                    "reason": "Still verbatim in text" if present_verbatim else "Not detected"
                })

        total = len(expected_list)
        recall = (correct / total) if total > 0 else 1.0
        return {
            "tier": tier_name,
            "total": total,
            "correct": correct,
            "recall": recall,
            "type_mismatches": type_mismatches,
            "misses": misses
        }

    t1_res = evaluate_tier(t1_expected, "T1")
    t2_res = evaluate_tier(t2_expected, "T2")

    # Evaluate Traps (Must Not Flag)
    traps_wrongly_masked = []
    for trap in traps:
        trap_val = trap["value"].strip()
        # Trap is wrongly masked if it's no longer in sanitized text or in detected values
        if trap_val not in sanitized_text or trap_val in detected_values:
            traps_wrongly_masked.append({
                "value": trap_val,
                "reason": trap.get("reason", "Must not flag"),
                "detected_as": detected_values.get(trap_val, DetectedEntity("UNKNOWN", trap_val, 0, 0)).entity_type
            })

    # Evaluate Precision
    # Real entities set
    all_real_values = {e["value"].strip() for e in t1_expected + t2_expected}
    correct_detections = 0
    for det in detected_entities:
        dval = det.value.strip()
        if any(dval in rval or rval in dval for rval in all_real_values):
            correct_detections += 1
    total_detections = len(detected_entities)
    precision = (correct_detections / total_detections) if total_detections > 0 else 1.0

    # Evaluate Partial Leaks
    partial_leaks = check_partial_leaks(sanitized_text, t1_expected + t2_expected)

    return {
        "document": answer_key.get("document", "unknown"),
        "t1": t1_res,
        "t2": t2_res,
        "traps_total": len(traps),
        "traps_wrongly_masked": traps_wrongly_masked,
        "precision": precision,
        "total_detections": total_detections,
        "correct_detections": correct_detections,
        "partial_leaks": partial_leaks
    }


def run_benchmark(run_name: str, fixtures_dir: str = "tests/fixtures", reports_dir: str = "tests/reports") -> Dict[str, Any]:
    os.makedirs(reports_dir, exist_ok=True)

    docs = [
        ("zeroleak_unstructured_test_doc.txt", "zeroleak_unstructured_test_answer_key.json"),
        ("variant_a.txt", "variant_a.json"),
        ("variant_b.txt", "variant_b.json"),
    ]

    all_results = []

    for doc_file, key_file in docs:
        doc_path = os.path.join(fixtures_dir, doc_file)
        key_path = os.path.join(fixtures_dir, key_file)

        if not os.path.exists(doc_path) or not os.path.exists(key_path):
            print(f"Skipping {doc_file}: file or key missing")
            continue

        with open(doc_path, "r", encoding="utf-8") as f:
            doc_text = f.read()
        with open(key_path, "r", encoding="utf-8") as f:
            key_data = json.load(f)

        # Run real detection path
        detected = detect_pii(doc_text)
        sanitized, vault = mask_text_from_detections(doc_text, detected)

        res = evaluate_document(doc_text, key_data, detected, sanitized)
        all_results.append(res)

    summary_data = {
        "run_name": run_name,
        "documents": all_results,
    }

    # Save JSON report
    json_path = os.path.join(reports_dir, f"{run_name}.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(summary_data, f, indent=2, ensure_ascii=False)

    # Generate Markdown Report
    md_path = os.path.join(reports_dir, f"{run_name}.md")
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(f"# Benchmark Detection Evaluation Report: `{run_name}`\n\n")
        f.write("Evaluation against synthetic ground-truth fixtures.\n\n")
        f.write("| Document | T1 Recall | T2 Recall | Traps Preserved | Precision | Partial Leaks | Type Mismatches |\n")
        f.write("|:---|:---:|:---:|:---:|:---:|:---:|:---:|\n")

        for r in all_results:
            t1_score = f"{r['t1']['correct']}/{r['t1']['total']} ({r['t1']['recall']*100:.1f}%)"
            t2_score = f"{r['t2']['correct']}/{r['t2']['total']} ({r['t2']['recall']*100:.1f}%)"
            traps_preserved = f"{r['traps_total'] - len(r['traps_wrongly_masked'])}/{r['traps_total']}"
            prec = f"{r['precision']*100:.1f}%"
            leaks = str(len(r['partial_leaks']))
            mismatches = str(len(r['t1']['type_mismatches']) + len(r['t2']['type_mismatches']))
            f.write(f"| `{r['document']}` | {t1_score} | {t2_score} | {traps_preserved} | {prec} | {leaks} | {mismatches} |\n")

        f.write("\n\n## Per-Document Detail\n\n")
        for r in all_results:
            f.write(f"### Document: `{r['document']}`\n\n")
            f.write(f"- **T1 Misses ({len(r['t1']['misses'])})**:\n")
            for m in r['t1']['misses']:
                f.write(f"  - `{m['type']}`: \"{m['value']}\" ({m['reason']})\n")
            f.write(f"- **T2 Misses ({len(r['t2']['misses'])})**:\n")
            for m in r['t2']['misses']:
                f.write(f"  - `{m['type']}`: \"{m['value']}\" ({m['reason']})\n")
            f.write(f"- **Traps Wrongly Masked ({len(r['traps_wrongly_masked'])})**:\n")
            for t in r['traps_wrongly_masked']:
                f.write(f"  - \"{t['value']}\" -> flagged as `{t['detected_as']}` ({t['reason']})\n")
            f.write(f"- **Type Mismatches ({len(r['t1']['type_mismatches']) + len(r['t2']['type_mismatches'])})**:\n")
            for tm in r['t1']['type_mismatches'] + r['t2']['type_mismatches']:
                f.write(f"  - \"{tm['value']}\": Expected `{tm['expected_type']}`, got `{tm['detected_type']}`\n")
            f.write("\n")

    print(f"Benchmark report generated:\n  - JSON: {json_path}\n  - Markdown: {md_path}")
    return summary_data


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Score ZeroLeak detection on benchmark fixtures.")
    parser.add_argument("--run-name", default="baseline", help="Report identifier name (e.g. baseline, stage_a, stage_b)")
    args = parser.parse_args()
    run_benchmark(args.run_name)
