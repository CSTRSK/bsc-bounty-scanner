#!/usr/bin/env python3
"""
hermes_bsc_skill.py — BSC Audit-/Bug-Bounty-Skill für Hermes Agent

Wrappt bsc_scanner.py in ein Skill-Interface, das Hermes als Tool/Funktion
registrieren kann. Ergänzt gegenüber der manuellen Version:

  1. LLM-Triage über lokales Ollama (Gemma 4) — filtert Rauschen raus,
     bewertet Ausnutzbarkeit, priorisiert nach Impact.
  2. Scope-Check — meldet nur Findings zu Contracts, die aktuell in einem
     aktiven Bounty-Programm gelistet sind (Immunefi/HackerOne-Style).
  3. Rückgabe als sauberes dict/JSON, das Hermes direkt weiterverarbeiten
     (z. B. Telegram-Approval-Flow von BountyWatch) oder in seinen
     Reasoning-Loop einspeisen kann.

Enthält keinerlei Exploit-Code — nur Erkennung, Bewertung, Reporting.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict
from typing import Any

import requests

from bsc_scanner import scan_address, ScanResult, Finding

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434/api/generate")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "gemma3:latest")  # an dein Setup anpassen

TRIAGE_SYSTEM_PROMPT = """Du bist ein erfahrener Smart-Contract-Auditor. \
Du bekommst einen Finding aus einem Slither-Scan eines BSC-Contracts. \
Bewerte NUR anhand der gegebenen Informationen:

1. plausible_exploit: true/false — ist das Finding wahrscheinlich real \
   ausnutzbar oder eher Boilerplate/False-Positive (z. B. Standard-\
   OpenZeppelin-Pattern, bekanntes Non-Issue)?
2. severity_estimate: "critical" | "high" | "medium" | "low" | "noise"
3. reasoning: kurze Begründung (max. 2 Sätze)

Antworte NUR als JSON: {"plausible_exploit": bool, "severity_estimate": str, "reasoning": str}
Du sollst keinen Exploit-Code oder Angriffsschritte liefern — nur bewerten."""


def triage_finding(finding: Finding, contract_name: str) -> dict[str, Any]:
    """Schickt ein einzelnes Finding zur Bewertung an lokales Gemma via Ollama."""
    user_prompt = (
        f"Contract: {contract_name}\n"
        f"Check: {finding.check}\n"
        f"Slither-Impact: {finding.impact}\n"
        f"Slither-Confidence: {finding.confidence}\n"
        f"Beschreibung: {finding.description}\n"
        f"Betroffene Elemente: {', '.join(finding.elements) or 'n/a'}"
    )

    payload = {
        "model": OLLAMA_MODEL,
        "system": TRIAGE_SYSTEM_PROMPT,
        "prompt": user_prompt,
        "stream": False,
        "format": "json",
    }

    try:
        resp = requests.post(OLLAMA_URL, json=payload, timeout=60)
        resp.raise_for_status()
        raw_response = resp.json().get("response", "{}")
        return json.loads(raw_response)
    except Exception as exc:  # noqa: BLE001
        return {
            "plausible_exploit": None,
            "severity_estimate": "unknown",
            "reasoning": f"Triage fehlgeschlagen: {exc}",
        }


def check_active_scope(address: str, active_scope: set[str] | None) -> bool:
    """
    Prüft, ob der Contract in einem aktiven Bounty-Programm gelistet ist.
    active_scope: Set von Contract-Adressen (lowercase), z. B. aus dem
    Scope-Watcher von BountyWatch Stage 1. None = Check übersprungen
    (z. B. für reine Recherche ohne Einreichungs-Absicht).
    """
    if active_scope is None:
        return True
    return address.lower() in active_scope


def run_bsc_bounty_skill(
    address: str,
    api_key: str | None = None,
    active_scope: set[str] | None = None,
    triage_min_severity: str = "medium",
) -> dict[str, Any]:
    """
    Haupteinstiegspunkt für Hermes.

    Rückgabe-Struktur (immer JSON-serialisierbar):
    {
        "address": ...,
        "contract_name": ...,
        "in_scope": bool,
        "recommend_report": bool,      # true nur wenn in_scope + relevante Findings
        "findings": [
            {..slither finding.., "triage": {...}}
        ],
        "error": str | None,
    }
    """
    severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "noise": 0, "unknown": 0}
    min_level = severity_order.get(triage_min_severity, 2)

    api_key = api_key or os.environ.get("BSCSCAN_API_KEY")
    if not api_key:
        return {"error": "Kein BSCSCAN_API_KEY gesetzt", "address": address}

    result: ScanResult = scan_address(address, api_key)

    if result.error:
        return {"address": address, "error": result.error}

    in_scope = check_active_scope(address, active_scope)

    enriched_findings = []
    for finding in result.findings:
        triage = triage_finding(finding, result.contract_name)
        entry = asdict(finding)
        entry["triage"] = triage
        enriched_findings.append(entry)

    # Nur Findings, die die LLM-Triage als plausibel + relevant genug einstuft
    relevant = [
        f for f in enriched_findings
        if f["triage"].get("plausible_exploit")
        and severity_order.get(f["triage"].get("severity_estimate", "unknown"), 0) >= min_level
    ]

    return {
        "address": result.address,
        "contract_name": result.contract_name,
        "compiler_version": result.compiler_version,
        "in_scope": in_scope,
        "recommend_report": in_scope and len(relevant) > 0,
        "findings": enriched_findings,
        "relevant_findings": relevant,
        "error": None,
    }


# --- Beispiel für Hermes-Tool-Registrierung (an dein Agent-Framework anpassen) ---
# Falls Hermes/OpenClaw-Style Tool-Schemas erwartet, z. B.:
#
# TOOL_SCHEMA = {
#     "name": "bsc_bounty_scan",
#     "description": "Scannt einen BSC-Smart-Contract auf Sicherheitslücken "
#                     "für Bug-Bounty-Zwecke (Audit, kein Exploit).",
#     "parameters": {
#         "type": "object",
#         "properties": {
#             "address": {"type": "string", "description": "0x-Contract-Adresse"},
#         },
#         "required": ["address"],
#     },
# }
#
# def hermes_tool_handler(args: dict) -> dict:
#     return run_bsc_bounty_skill(args["address"])


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Nutzung: python3 hermes_bsc_skill.py <contract_address>")
        sys.exit(1)

    out = run_bsc_bounty_skill(sys.argv[1])
    print(json.dumps(out, indent=2, ensure_ascii=False))
