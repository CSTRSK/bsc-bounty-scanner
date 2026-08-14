#!/usr/bin/env python3
"""
bsc_scanner.py — Manueller BSC Audit-/Bug-Bounty-Scanner

Holt verifizierten Source-Code eines BSC-Contracts über die BscScan-API,
lässt Slither (und optional Aderyn) darüber laufen und gibt strukturierte
Findings als JSON zurück.

Nutzung:
    export BSCSCAN_API_KEY="dein_key"
    python3 bsc_scanner.py 0xContractAddress

Voraussetzungen:
    pip install slither-analyzer requests --break-system-packages
    (Aderyn optional: siehe https://github.com/Cyfrin/aderyn)

WICHTIG: Dieses Skript findet und meldet Schwachstellen (Audit-/Bug-Bounty-
Zweck). Es enthält keinen Code, der Schwachstellen aktiv ausnutzt.
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any

import requests

BSCSCAN_API_URL = "https://api.etherscan.io/v2/api"
DEFAULT_CHAIN_ID = "56"  # 56 = BNB Smart Chain, 1 = Ethereum

# Slither-Detektoren, die für Bug-Bounty-Zwecke am relevantesten sind
# (hohe Impact-Kategorien laut OWASP Smart Contract Top 10 2026:
#  Access Control, Business Logic, Reentrancy)
HIGH_VALUE_CHECKS = {
    "reentrancy-eth",
    "reentrancy-no-eth",
    "reentrancy-unlimited-gas",
    "arbitrary-send-eth",
    "arbitrary-send-erc20",
    "controlled-delegatecall",
    "unprotected-upgrade",
    "suicidal",
    "tx-origin",
    "unchecked-transfer",
    "uninitialized-state",
    "uninitialized-storage",
    "access-control",
    "incorrect-equality",
}


@dataclass
class Finding:
    check: str
    impact: str
    confidence: str
    description: str
    elements: list[str] = field(default_factory=list)
    high_value: bool = False


@dataclass
class ScanResult:
    address: str
    contract_name: str
    compiler_version: str
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        return d


def fetch_source(address: str, api_key: str, chain_id: str = DEFAULT_CHAIN_ID) -> dict[str, Any]:
    """Holt verifizierten Source-Code + Metadaten von BscScan (Etherscan V2 API)."""
    params = {
        "chainid": chain_id,
        "module": "contract",
        "action": "getsourcecode",
        "address": address,
        "apikey": api_key,
    }
    resp = requests.get(BSCSCAN_API_URL, params=params, timeout=30)
    resp.raise_for_status()
    data = resp.json()

    if data.get("status") != "1" or not data.get("result"):
        raise RuntimeError(f"BscScan-Fehler: {data.get('message', 'unbekannt')}")

    result = data["result"][0]
    if not result.get("SourceCode"):
        raise RuntimeError(
            "Contract ist nicht verifiziert — kein Source-Code verfügbar. "
            "Ohne verifizierten Source ist keine statische Analyse möglich."
        )
    return result


def write_source_to_disk(source_info: dict[str, Any], workdir: Path) -> Path:
    """
    BscScan liefert entweder einfachen Solidity-Code oder ein
    Multi-File-JSON (Standard-JSON-Input). Beide Fälle abdecken.
    """
    raw = source_info["SourceCode"]
    contract_name = source_info.get("ContractName", "Contract")

    # Multi-File-Format: beginnt oft mit doppelten geschweiften Klammern {{
    stripped = raw.strip()
    if stripped.startswith("{{") and stripped.endswith("}}"):
        stripped = stripped[1:-1]

    try:
        parsed = json.loads(stripped)
        sources = parsed.get("sources", parsed)
        for rel_path, content in sources.items():
            file_path = workdir / rel_path
            file_path.parent.mkdir(parents=True, exist_ok=True)
            code = content["content"] if isinstance(content, dict) else content
            file_path.write_text(code, encoding="utf-8")
        # Slither braucht einen Einstiegspunkt — größte Datei als Haupt-Contract annehmen
        main_file = max(workdir.rglob("*.sol"), key=lambda p: p.stat().st_size)
        return main_file
    except (json.JSONDecodeError, TypeError):
        # Einfacher Fall: reiner Solidity-Code
        file_path = workdir / f"{contract_name}.sol"
        file_path.write_text(raw, encoding="utf-8")
        return file_path


def run_slither(target_file: Path) -> list[Finding]:
    """Führt Slither aus und parst die JSON-Ausgabe in Finding-Objekte."""
    out_json = target_file.parent / "slither_output.json"
    cmd = [
        "slither",
        str(target_file),
        "--json",
        str(out_json),
    ]
    # Slither gibt bei gefundenen Issues einen Exit-Code != 0 zurück — das ist erwartet
    subprocess.run(cmd, capture_output=True, text=True, cwd=target_file.parent)

    if not out_json.exists():
        return []

    with open(out_json, encoding="utf-8") as f:
        raw = json.load(f)

    findings: list[Finding] = []
    for det in raw.get("results", {}).get("detectors", []):
        check = det.get("check", "unknown")
        elements = [
            el.get("name", str(el.get("source_mapping", {})))
            for el in det.get("elements", [])
        ]
        findings.append(
            Finding(
                check=check,
                impact=det.get("impact", "Informational"),
                confidence=det.get("confidence", "Low"),
                description=det.get("description", "").strip(),
                elements=elements,
                high_value=check in HIGH_VALUE_CHECKS,
            )
        )
    return findings


def scan_address(address: str, api_key: str, chain_id: str = DEFAULT_CHAIN_ID) -> ScanResult:
    source_info = fetch_source(address, api_key, chain_id)
    contract_name = source_info.get("ContractName", "Unknown")
    compiler_version = source_info.get("CompilerVersion", "unknown")

    with tempfile.TemporaryDirectory(prefix="bsc_scan_") as tmp:
        workdir = Path(tmp)
        try:
            target_file = write_source_to_disk(source_info, workdir)
            findings = run_slither(target_file)
        except Exception as exc:  # noqa: BLE001 — bewusst breit, für sauberen Report
            return ScanResult(
                address=address,
                contract_name=contract_name,
                compiler_version=compiler_version,
                error=str(exc),
            )

    # High-value Findings zuerst
    findings.sort(key=lambda f: (not f.high_value, f.impact != "High"))

    return ScanResult(
        address=address,
        contract_name=contract_name,
        compiler_version=compiler_version,
        findings=findings,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="BSC Audit-/Bug-Bounty-Scanner")
    parser.add_argument("address", help="BSC-Contract-Adresse (0x...)")
    parser.add_argument(
        "--api-key",
        default=os.environ.get("BSCSCAN_API_KEY"),
        help="BscScan API-Key (oder ENV BSCSCAN_API_KEY setzen)",
    )
    parser.add_argument(
        "--chain",
        default=DEFAULT_CHAIN_ID,
        help="Chain-ID: 56 = BNB Smart Chain (default), 1 = Ethereum, 42161 = Arbitrum",
    )
    parser.add_argument(
        "--out",
        help="Optional: Pfad, um Ergebnis als JSON-Datei zu speichern",
    )
    args = parser.parse_args()

    if not args.api_key:
        print("Fehler: kein BscScan API-Key gesetzt (--api-key oder BSCSCAN_API_KEY)", file=sys.stderr)
        sys.exit(1)

    result = scan_address(args.address, args.api_key, args.chain)
    output = json.dumps(result.to_dict(), indent=2, ensure_ascii=False)

    print(output)
    if args.out:
        Path(args.out).write_text(output, encoding="utf-8")

    if result.error:
        sys.exit(2)


if __name__ == "__main__":
    main()
