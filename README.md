# BSC Smart-Contract Audit-/Bug-Bounty-Scanner

Automatisierte Sicherheitsanalyse für BSC-Smart-Contracts (und andere EVM-Chains).
Holt verifizierten Source-Code über die **Etherscan V2 API**, lässt **Slither**
(102 Detektoren) darüber laufen und liefert strukturierte Findings als JSON.

> ⚠️ **Nur Erkennung, Bewertung, Reporting — kein Exploit-Code.**
> Für Bug-Bounty-Einreichungen IMMER den Scope des Programms prüfen.

## Features

- 🔍 **Source-Code-Fetch** — verifizierte Contracts via Etherscan V2 API
  (Multi-File-JSON + einfacher Solidity-Code werden unterstützt)
- 🛡️ **Slither-Analyse** — 102 Detektoren, strukturiertes JSON-Output
- 🔥 **High-Value-Priorisierung** — reentrancy, arbitrary-send, tx-origin,
  delegatecall, uninitialized-state u.v.m. werden markiert
- 🧠 **LLM-Triage (optional)** — `hermes_bsc_skill.py` filtert False-Positives
  über lokales Ollama (Gemma) und bewertet Ausnutzbarkeit
- 🌐 **Multi-Chain** — BSC (56), Ethereum (1), Arbitrum (42161), Optimism (10)
- 🤖 **Hermes-Integration** — als Python-Funktion importierbar, liefert
  `recommend_report`-Entscheidung

## Quick Start

```bash
pip install slither-analyzer requests --break-system-packages
solc-select install 0.6.12   # oder die Compiler-Version des Contracts

export BSCSCAN_API_KEY="dein_key"   # kostenlos: https://etherscan.io/apis

python3 bsc_scanner.py 0xContractAddress --chain 56
python3 bsc_scanner.py 0xContractAddress --chain 56 --out result.json
```

### Hermes-Skill-Modus

```python
from hermes_bsc_skill import run_bsc_bounty_skill

result = run_bsc_bounty_skill(
    address="0x...",
    active_scope={"0x...", "0x..."},   # Immunefi/Scope-Adressen
    triage_min_severity="high",
)
if result["recommend_report"]:
    # -> Report einreichen
    ...
```

## Beispiel-Audit

Ein vollständiger Beispiel-Audit mit diesem Scanner wurde für
[**Planet9-Coin**](https://github.com/CSTRSK/-PlanetNine/blob/main/AUDIT.md)
erstellt (BSC-SafeMoon-Fork):

- **45 Findings**, davon **1 High** (Reentrancy in `_transfer`, Zeile 1012-1056)
- Komplettes Audit-Dokument mit Methodik, Zeilennummern und Empfehlungen:
  **[AUDIT.md](https://github.com/CSTRSK/-PlanetNine/blob/main/AUDIT.md)**

## Chain-Support (Free-Tier)

| Chain | Chain-ID | Status |
|-------|----------|--------|
| BNB Smart Chain | 56 | ✅ |
| Ethereum | 1 | ✅ |
| Arbitrum | 42161 | ✅ |
| Optimism | 10 | ✅ |

## Struktur

```
bsc_scanner.py       # CLI-Tool: Fetch → Slither → JSON
hermes_bsc_skill.py  # Hermes-Wrapper: LLM-Triage + Scope-Check
README.md            # diese Datei
```

## Lizenz

**GNU AGPL v3.0** — Copyright (C) 2026 CSTRSK (https://cstrsk.de)
Vollständiger Lizenztext in [LICENSE](LICENSE).

Jede Nutzung/Weitergabe/Modifikation muss die AGPL-Bedingungen einhalten
und den Copyright-Hinweis von CSTRSK enthalten.
