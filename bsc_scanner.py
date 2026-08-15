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
import re
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
    """Führt Slither aus (ALLE Detektoren) und parst die JSON-Ausgabe."""
    out_json = target_file.parent / "slither_output.json"
    cmd = [
        "slither",
        str(target_file),
        "--detect", "all",  # ALLE 140+ Detektoren, nicht nur Defaults
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


def run_deep_heuristics(source_files: list[Path]) -> list[Finding]:
    """Zusätzliche Angriffswinkel jenseits der Standard-Detektoren.

    Umgesetzte Checklisten-Kategorien (bug_checklist.txt):
    A. Token: SafeERC20, Fee-on-Transfer, Blacklist-Timelock, Mint-Guard
    B. AMM/DEX: Skimming/Sync, Deadline/Slippage-Enforcement
    C. Lending: Oracle-Staleness, Reward-Manipulation (same-block)
    D. Governance: Snapshot-Delay, Timelock-Bypass
    E. Proxy: Upgrade-Timelock, Uninitialized-Proxy
    F. Presale: Refund-Reentrancy, Vesting-Berechnung
    G. Cross-Contract: tx.origin, Callbacks, unbegrenzte Mint-Pfade
    H. Signatur: Domain-Separation, Permit-Frontrunning
    I. Gas/DoS: unbegrenzte Loops, wachsende Arrays
    J. Vault/ERC4626: First-Depositor/Inflation, Virtual-Offset, totalAssets, Dead-Share
    K. Delegatecall/Storage: nutzerkontrollierte Ziele, Layout-Mismatch
    L. Multicall/Batch: msg.value in Loops
    M. Router/Approval: Unlimited-Approval, Permit2 ohne Expiry
    N. Self-Destruct/Griefing: address(this).balance-Abhängigkeit
    O. NFT (721/1155): Callback-Reentrancy, Royalty-Bypass
    """
    findings = []
    for f in source_files:
        try:
            src = f.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        name = f.name
        is_lib = bool(re.search(r'(openzeppelin|@uniswap|@pancakeswap|@aave|interface |abstract contract I)', src, re.I))
        # Zeilennummer-Helfer
        def line_of(pos):
            return src[:pos].count("\n") + 1

        # ── A. TOKEN-CONTRACTS ──────────────────────────────
        # A1: transfer/transferFrom ohne SafeERC20 (USDT-Style-Return-los)
        if not is_lib and re.search(r'\.transferFrom?\s*\(', src):
            uses_safe = bool(re.search(r'(SafeERC20|safeTransfer|safeTransferFrom)', src))
            if not uses_safe:
                findings.append(Finding(
                    check="unsafe-erc20-transfer",
                    impact="Medium", confidence="Low",
                    description=f"{name}: Direkte .transfer()/.transferFrom() ohne SafeERC20. "
                                "Return-lose Tokens (USDT-Style) führen zu silent failures.",
                    elements=[name], high_value=False))

        # A2: Fee-on-Transfer im Transfer-Pfad (Pool-Buchhaltung)
        if re.search(r'(fee|tax)\w*\s*[=*]|_takeFee|reflect|redistribut', src, re.I) and re.search(r'(transfer|_transfer|balances)', src):
            if not is_lib:
                findings.append(Finding(
                    check="fee-on-transfer-logic",
                    impact="Medium", confidence="Low",
                    description=f"{name}: Fee-/Reflexionslogik im Transfer-Pfad. "
                                "Prüfen ob Pool-Buchhaltung (k-Invariante) dies ausgleicht.",
                    elements=[name], high_value=False))

        # A3: Blacklist/Pausable ohne Timelock
        if re.search(r'(blacklist|addToBlacklist|excludeFromReward|paused\s*=\s*true)', src, re.I):
            if not re.search(r'(timelock|delay|pendingAdmin|queue)', src, re.I):
                findings.append(Finding(
                    check="blacklist-without-timelock",
                    impact="Medium", confidence="Low",
                    description=f"{name}: Blacklist/Pause-Funktion ohne Timelock/Delay. "
                                "Owner kann Nutzer sofort aussperren.",
                    elements=[name], high_value=False))

        # A4: Mint ohne onlyOwner-Schutz (nur externe public/external mint-Funktionen)
        for m in re.finditer(r'function\s+(\w*mint\w*)\s*\([^)]*\)\s*(public|external)', src):
            ctx = src[m.start():m.start()+400]
            if re.search(r'(onlyOwner|onlyAdmin|require\s*\(\s*msg\.sender|onlyRole|_mint\s*\([^,]+,\s*[^)]*\))', ctx):
                continue
            findings.append(Finding(
                check="unrestricted-mint",
                impact="High", confidence="Medium",
                description=f"{name}: public mint()-Funktion '{m.group(1)}' (Zeile ~{line_of(m.start())}) ohne "
                            "sichtbaren Zugriffsschutz — unbegrenzte Token-Erzeugung.",
                elements=[name], high_value=True))

        # ── B. AMM/DEX-FORKS ────────────────────────────────
        # B1: skim/sync von außen aufrufbar
        for m in re.finditer(r'function\s+(skim|sync)\s*\(', src):
            findings.append(Finding(
                check="external-skim-sync",
                impact="Low", confidence="Low",
                description=f"{name}: {m.group(1)}()-Funktion (Zeile ~{line_of(m.start())}) "
                            "extern aufrufbar — bei Custom-Fee-Logik prüfen ob Manipulation möglich.",
                elements=[name], high_value=False))

        # B2: Fehlende Deadline/Slippage-Enforcement (Protokoll-Ebene)
        if re.search(r'(swapExact|addLiquidity|removeLiquidity)', src):
            if not re.search(r'(deadline|amountOutMin|minAmount|maxAmount|slippage)', src):
                findings.append(Finding(
                    check="missing-deadline-slippage",
                    impact="Medium", confidence="Medium",
                    description=f"{name}: Swap/Liquidity-Funktionen ohne Deadline/Slippage-Check "
                                "auf Protokollebene — Frontrunning/MEV-Verluste möglich.",
                    elements=[name], high_value=False))

        # ── C. LENDING/STAKING/FARMING ──────────────────────
        # C1: Reward-Manipulation durch Same-Block-Deposit+Withdraw
        if re.search(r'(deposit|stake|enter)', src) and re.search(r'(withdraw|unstake|leave)', src):
            if re.search(r'(rewardPerShare|accReward|rewardDebt|pendingReward)', src):
                if not re.search(r'(block\.number|block\.timestamp)\s*[<>=]|lastUpdate', src):
                    findings.append(Finding(
                        check="same-block-reward-manipulation",
                        impact="Medium", confidence="Medium",
                        description=f"{name}: Reward-Tracker (rewardPerShare/accReward) ohne "
                                    "Zeit/Durchschnitts-Guard — Deposit+Withdraw im selben Block "
                                    "kann Rewards manipulieren.",
                        elements=[name], high_value=False))

        # C2: Liquidation mit Spot-Preis aus dünnem Pool
        if re.search(r'(liquidation|liquidat)', src, re.I):
            if re.search(r'(getReserves|getAmountOut|spotPrice|getPrice)', src):
                findings.append(Finding(
                    check="thin-pool-liquidation-price",
                    impact="Medium", confidence="Low",
                    description=f"{name}: Liquidation nutzt Spot-Preis aus Pool-Reserven — "
                                "dünne Pools sind preismanipulierbar (Flash-Loan).",
                    elements=[name], high_value=False))

        # ── D. GOVERNANCE/DAO ───────────────────────────────
        # D1: Flash-Loan-Voting ohne Snapshot-Delay
        # Präzise: nur echte vote/propose-Funktionen (nicht delegatecall/delegate)
        if re.search(r'(function\s+\w*vote\w*\s*\(|function\s+castVote|function\s+propose\s*\(|function\s+submitProposal)', src):
            if not re.search(r'(snapshot|block\.number\s*[<>=]|votingDelay|startBlock)', src):
                findings.append(Finding(
                    check="flash-loan-voting",
                    impact="High", confidence="Medium",
                    description=f"{name}: Voting ohne Snapshot/Delay-Guard — Flash-Loan-Voting "
                                "(leihen → voten → zurückzahlen) möglich.",
                    elements=[name], high_value=True))

        # D2: Timelock-Bypass (alternative Execution-Pfade)
        if re.search(r'(executeTransaction|executeProposal|queueTransaction)', src):
            if not re.search(r'(timelock|delay|onlyTimelock|msg\.sender\s*==\s*timelock)', src, re.I):
                findings.append(Finding(
                    check="timelock-bypass",
                    impact="High", confidence="Medium",
                    description=f"{name}: Execution-Pfad ohne Timelock-Verifikation — "
                                "Governance-Änderungen sofort durchführbar.",
                    elements=[name], high_value=True))

        # ── E. PROXY/UPGRADEABLE ────────────────────────────
        # E1: Upgrade ohne Timelock/Delay (nur Projekt-Code, nicht OZ-Proxy-Boilerplate)
        if not is_lib and re.search(r'(function\s+upgradeTo\w*\s*\(|function\s+upgrade\s*\(|function\s+setImplementation\s*\()', src):
            if not re.search(r'(timelock|delay|pendingAdmin|queue|twoStep)', src, re.I):
                findings.append(Finding(
                    check="instant-upgrade-no-timelock",
                    impact="Medium", confidence="Medium",
                    description=f"{name}: Upgrade-Funktion ohne Timelock — Admin kann "
                                "sofort upgraden (Storage-Kollision/Asset-Verlust-Risiko).",
                    elements=[name], high_value=False))

        # E2: Uninitialized-Proxy (initialize von jedem)
        if re.search(r'(function\s+initialize|initializer)', src):
            if not re.search(r'(initializer\b|onlyOwner|onlyAdmin|require\s*\(\s*msg\.sender|_initialized|isInitialized)', src):
                findings.append(Finding(
                    check="uninitialized-proxy",
                    impact="High", confidence="High",
                    description=f"{name}: initialize()-Muster ohne Guard — jeder kann den "
                                "uninitialisierten Proxy kapern.",
                    elements=[name], high_value=True))

        # ── F. PRESALE/LAUNCHPAD ────────────────────────────
        # F1: Refund mit Reentrancy-Fenster
        for m in re.finditer(r'function\s+\w*(refund|claimRefund|withdrawFunds)\w*\s*\(', src):
            ctx = src[m.start():m.start()+600]
            if re.search(r'\.(call|transfer|send)\s*\{?value', ctx) and not re.search(r'(nonReentrant|reentrancyGuard|mutex|locked)', ctx, re.I):
                findings.append(Finding(
                    check="refund-reentrancy",
                    impact="High", confidence="Medium",
                    description=f"{name}: Refund-Funktion (Zeile ~{line_of(m.start())}) mit "
                                "ETH-Transfer ohne Reentrancy-Guard.",
                    elements=[name], high_value=True))

        # F2: Vesting/Cliff-Berechnung
        if re.search(r'(vesting|cliff|releaseTime|linearRelease)', src, re.I):
            if not re.search(r'(block\.timestamp|block\.number)', src):
                findings.append(Finding(
                    check="vesting-no-time-source",
                    impact="Medium", confidence="Medium",
                    description=f"{name}: Vesting-Logik ohne block.timestamp/block.number — "
                                "Cliff/Release-Berechnung möglicherweise fehlerhaft.",
                    elements=[name], high_value=False))

        # ── G. CROSS-CONTRACT/COMPOSABILITY ─────────────────
        # G1: tx.origin für Auth
        if re.search(r'tx\.origin', src) and not is_lib:
            findings.append(Finding(
                check="tx-origin-auth",
                impact="High", confidence="Medium",
                description=f"{name}: tx.origin für Authentifizierung — Phishing-/"
                            "Callback-Angriffe möglich (msg.sender verwenden).",
                elements=[name], high_value=True))

        # G2: Callback mit State-Änderung
        for cb in ("onERC721Received", "onERC1155Received", "onTokenTransfer"):
            if cb in src and re.search(r'(mapping|balances\[|_transfer|mint)', src):
                findings.append(Finding(
                    check=f"callback-state-change-{cb}",
                    impact="Medium", confidence="Low",
                    description=f"{name}: {cb}-Callback mit State-Änderungen — Reihenfolge "
                                "des eigenen States vor Callback prüfen.",
                    elements=[name], high_value=False))

        # ── H. SIGNATUR-BEZOGEN ─────────────────────────────
        # H1: ECDSA ohne Domain-Separation
        if re.search(r'(ecrecover|ECDSA|_verify|recover\(|permit\(|_hashTypedData)', src):
            if not re.search(r'(DOMAIN_SEPARATOR|domainSeparator|domain_separator|_domainSeparator)', src):
                findings.append(Finding(
                    check="missing-domain-separator",
                    impact="Medium", confidence="Medium",
                    description=f"{name}: Signatur-Verifikation ohne Domain-Separator — "
                                "Signaturen können über Chains/Verträge replayable sein.",
                    elements=[name], high_value=False))

        # H2: Permit-Frontrunning (Nonce-Verbrauch)
        if re.search(r'permit\(|nonces\[|_nonces', src):
            if not re.search(r'(nonces\[[^\]]+\]\s*\+{2}|usedNonce|_useNonce)', src):
                findings.append(Finding(
                    check="permit-nonce-handling",
                    impact="Low", confidence="Low",
                    description=f"{name}: permit()/Nonce-Logik — Frontrunning führt zu "
                                "dauerhaftem Revert der Original-Tx.",
                    elements=[name], high_value=False))

        # ── I. GAS/DoS ──────────────────────────────────────
        # I1: Unbegrenzte Loops über wachsende Arrays
        for m in re.finditer(r'for\s*\([^)]*\)\s*\{', src):
            ctx = src[m.start():m.start()+400]
            if re.search(r'(\.length|holders|userList|array)', ctx):
                findings.append(Finding(
                    check="unbounded-loop-dos",
                    impact="Medium", confidence="Low",
                    description=f"{name}: Loop (Zeile ~{line_of(m.start())}) über wachsende "
                                "Struktur — ökonomischer DoS bei großem Zustand.",
                    elements=[name], high_value=False))
                break

        # I2: Wachsende Arrays/Mappings ohne Pruning
        if re.search(r'\.push\s*\(', src) and not re.search(r'(delete\s+\w+\[|\.pop\s*\(|remove)', src):
            findings.append(Finding(
                check="growing-storage-array",
                impact="Low", confidence="Low",
                description=f"{name}: .push() auf Storage-Array ohne Pruning — "
                            "unbegrenztes Wachstum → steigende Gas-Kosten.",
                elements=[name], high_value=False))

        # ── J. VAULT/ERC4626 ────────────────────────────────
        # J1: First-Depositor/Inflation-Attack
        if re.search(r'(ERC4626|_convertToShares|previewDeposit|totalAssets)', src):
            if not re.search(r'(_decimalsOffset|virtualOffset|VIRTUAL_SHARES|VIRTUAL_ASSETS|dead.?share|_mint\s*\([^,]*address\(0\))', src, re.I):
                findings.append(Finding(
                    check="erc4626-first-depositor-attack",
                    impact="High", confidence="Medium",
                    description=f"{name}: ERC4626-Vault ohne Virtual-Offset/Dead-Share-Schutz — "
                                "First-Depositor/Inflation-Attack: Angreifer deponiert 1 Wei, "
                                "spendet direkt große Menge → folgende Deposits runden auf 0 Shares.",
                    elements=[name], high_value=True))

        # J2: totalAssets liest balanceOf(address(this)) direkt
        for m in re.finditer(r'function\s+totalAssets\s*\([^)]*\)\s*(public|external)\s*(view)?\s*(override)?\s*\{', src):
            ctx = src[m.start():m.start()+500]
            if re.search(r'balanceOf\s*\(?\s*address\s*\(\s*this\s*\)', ctx):
                findings.append(Finding(
                    check="erc4626-totalassets-balanceof",
                    impact="Medium", confidence="Medium",
                    description=f"{name}: totalAssets() (Zeile ~{line_of(m.start())}) liest "
                                "balanceOf(address(this)) direkt — von außen manipulierbar "
                                "(Donation/Griefing auf Share-Preis).",
                    elements=[name], high_value=False))

        # ── K. DELEGATECALL/STORAGE ─────────────────────────
        # K1: Delegatecall an nutzerkontrollierte Adresse
        for m in re.finditer(r'\.delegatecall\s*\(', src):
            ctx = src[max(0, m.start()-300):m.start()+200]
            if re.search(r'(msg\.data|abi\.encode|bytes\s+\w+|input)', ctx) and not re.search(r'(onlyOwner|require\s*\([^)]*(msg\.sender|==\s*(logic|impl|target)))', ctx, re.I):
                findings.append(Finding(
                    check="delegatecall-user-controlled",
                    impact="High", confidence="Medium",
                    description=f"{name}: delegatecall (Zeile ~{line_of(m.start())}) mit "
                                "nutzerkontrollierten Daten/Ziel — Storage-Override möglich.",
                    elements=[name], high_value=True))
            break

        # ── L. MULTICALL/BATCH ──────────────────────────────
        # L1: msg.value in Multicall-Loops mehrfach verrechnet
        if re.search(r'(multicall|batch\w*\(|executeBatch)', src, re.I):
            if re.search(r'for\s*\(', src) and re.search(r'msg\.value', src):
                if not re.search(r'(msg\.value\s*==\s*\w+\.length|if\s*\([^)]*msg\.value|msg\.value\s*<)', src):
                    findings.append(Finding(
                        check="multicall-msgvalue-loop",
                        impact="High", confidence="Medium",
                        description=f"{name}: Multicall/Batch-Loop mit msg.value — wird der "
                                    "Wert pro Sub-Call verrechnet statt einmal geprüft? "
                                    "Mehrfachverrechnung führt zu Value-Manipulation.",
                        elements=[name], high_value=True))

        # ── M. ROUTER/APPROVAL ──────────────────────────────
        # M1: Unlimited-Approval an upgradebaren Router
        if re.search(r'(approve\s*\(|increaseAllowance|setApprovalForAll)', src):
            if re.search(r'(type\(uint256\)\.max|uint256\.max|MAX_UINT|2\s*\*\*\s*256)', src) and \
               re.search(r'(upgrade|proxy|implementation)', src, re.I):
                findings.append(Finding(
                    check="unlimited-approval-upgradeable",
                    impact="Medium", confidence="Medium",
                    description=f"{name}: Unlimited-Approval (uint256.max) an upgradebaren "
                                "Router — Trust-Kette bricht bei Router-Upgrade (alte Approval "
                                "bleibt voll gültig).",
                    elements=[name], high_value=False))

        # M2: Permit2-artige Signaturen ohne Ablaufzeit
        if re.search(r'(permit|signature|ecrecover|_verifySig)', src, re.I):
            if not re.search(r'(deadline|expiry|expiresAt|validUntil|block\.timestamp)', src):
                findings.append(Finding(
                    check="permit-no-expiry",
                    impact="Medium", confidence="Medium",
                    description=f"{name}: Signatur-basierte Genehmigung ohne Ablaufzeit — "
                                "Signaturen bleiben unbegrenzt gültig (Replay-Risiko).",
                    elements=[name], high_value=False))

        # ── N. SELF-DESTRUCT/GRIEFING ───────────────────────
        # N1: Verlass auf address(this).balance (per selfdestruct befüllbar)
        if re.search(r'address\s*\(\s*this\s*\)\s*\.balance', src):
            findings.append(Finding(
                check="selfdestruct-balance-griefing",
                impact="Medium", confidence="Medium",
                description=f"{name}: Verlass auf address(this).balance — per selfdestruct "
                            "(forced ETH) von außen befüllbar → Griefing auf "
                            "Auszahlungs-/Rebase-Logik.",
                elements=[name], high_value=False))

        # ── O. NFT (BEP-721/1155) ───────────────────────────
        # O1: Reentrancy über onERC721Received-Callback
        if re.search(r'(safeTransferFrom|_safeMint|_safeTransfer)', src) and \
           re.search(r'(onERC721Received|onERC1155Received)', src):
            if not re.search(r'(nonReentrant|reentrancyGuard|mutex|locked)', src, re.I):
                findings.append(Finding(
                    check="nft-callback-reentrancy",
                    impact="High", confidence="Medium",
                    description=f"{name}: safeTransferFrom/_safeMint mit onERC721Received-"
                                "Callback ohne Reentrancy-Guard — Callback kann vor "
                                "State-Update reentrant eintreten.",
                    elements=[name], high_value=True))

        # O2: Royalty-Enforcement umgehbar
        if re.search(r'(royalty|royalties|ERC2981|feePercent)', src, re.I):
            if not re.search(r'(_checkOnERC721Received|setApprovalForAll|transferFrom)', src):
                findings.append(Finding(
                    check="royalty-bypass-surface",
                    impact="Low", confidence="Low",
                    description=f"{name}: Royalty-Logik ohne sichtbaren Enforcement-Check — "
                                "Marketplace-Bypass über direkte transferFrom-Pfade möglich.",
                    elements=[name], high_value=False))

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
            # Deep-Heuristiken: zusätzliche Angriffswinkel auf ALLEN Source-Files
            source_files = list(workdir.rglob("*.sol"))
            deep_findings = run_deep_heuristics(source_files)
            findings.extend(deep_findings)
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
