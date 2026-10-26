#!/usr/bin/env python3
"""
Read-only safety audit for a Python bot source file.

This script DOES NOT import or execute the bot being audited.
It never calls order-placement, leverage, cancellation, or position-modification
methods. Its optional API smoke test uses read-only endpoints only.

Install dependency for --api-check:
    python -m pip install pybit

Environment variables for --api-check:
    BYBIT_API_KEY       read-only API key
    BYBIT_API_SECRET    matching secret
    BYBIT_TESTNET       defaults to "1" (testnet); set to "0" only if you
                        intentionally want to test a MAINNET read-only key.
"""

from __future__ import annotations

import ast
import os
import sys
from pathlib import Path
from typing import Iterable

# Names commonly associated with account/position/order mutations.
# These are flagged for review; a text match alone does not prove execution.
WRITE_METHODS = {
    "place_order",
    "place_batch_order",
    "amend_order",
    "amend_batch_order",
    "cancel_order",
    "cancel_all_orders",
    "cancel_batch_order",
    "set_leverage",
    "set_trading_stop",
    "switch_position_mode",
    "switch_margin_mode",
    "set_margin_mode",
    "set_risk_limit",
    "add_or_reduce_margin",
    "move_position",
    "close_position",
    "place_conditional_order",
}

# Common spellings of private or wrapper functions that may perform writes.
WRITE_NAME_PARTS = (
    "place_order",
    "set_leverage",
    "set_trading_stop",
    "cancel_order",
    "cancel_all_orders",
    "amend_order",
    "close_position",
    "switch_position_mode",
    "set_margin_mode",
)


def parse_source(path: Path) -> tuple[str, ast.AST]:
    source = path.read_text(encoding="utf-8", errors="replace")
    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError as exc:
        raise RuntimeError(
            f"Could not parse {path}: line {exc.lineno}: {exc.msg}"
        ) from exc
    return source, tree


def static_audit(path: Path) -> int:
    source, tree = parse_source(path)
    findings: list[tuple[int, str, str]] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        func = node.func
        if isinstance(func, ast.Attribute):
            name = func.attr
        elif isinstance(func, ast.Name):
            name = func.id
        else:
            continue

        if name in WRITE_METHODS or any(part in name.lower() for part in WRITE_NAME_PARTS):
            findings.append((getattr(node, "lineno", 0), name, ast.get_source_segment(source, node) or name))

    print(f"Source: {path.resolve()}")
    print("Mode: STATIC ONLY — the source file was not imported or executed.")
    print(f"Python syntax: OK")
    print(f"Potential write-capable call sites found: {len(findings)}")

    for line, name, snippet in sorted(set(findings)):
        compact = " ".join(snippet.split())
        if len(compact) > 180:
            compact = compact[:177] + "..."
        print(f"  line {line}: {name}: {compact}")

    if findings:
        print(
            "\nIMPORTANT: this is a review list, not proof that each call runs. "
            "Do not run the original bot just because this audit completes."
        )
    else:
        print(
            "\nNo matching call names found. This does not prove the program is "
            "read-only; dynamic calls and aliases may evade a text/AST scan."
        )

    print("\nSafety checks:")
    print("  [PASS] This audit script did not execute the audited source.")
    print("  [PASS] This audit script contains no order-write operation.")
    return 0


def _check_response(label: str, response: object) -> bool:
    """Treat missing, malformed, or nonzero-code API responses as failures."""
    if not isinstance(response, dict):
        print(f"[FAIL] {label}: response was {type(response).__name__}, expected dict")
        return False

    code = response.get("retCode")
    if code != 0:
        print(f"[FAIL] {label}: API retCode={code!r}; retMsg={response.get('retMsg', 'n/a')!r}")
        return False

    result = response.get("result")
    if not isinstance(result, dict):
        print(f"[FAIL] {label}: result was {type(result).__name__}, expected dict")
        return False

    print(f"[PASS] {label}: retCode=0 and result is a dict")
    return True


def api_smoke_test() -> int:
    key = os.environ.get("BYBIT_API_KEY", "").strip()
    secret = os.environ.get("BYBIT_API_SECRET", "").strip()
    testnet = os.environ.get("BYBIT_TESTNET", "1").strip().lower() not in {
        "0", "false", "no", "off"
    }

    if not key or not secret:
        print(
            "[STOP] Set BYBIT_API_KEY and BYBIT_API_SECRET in the environment. "
            "Do not paste credentials into this script or chat."
        )
        return 2

    try:
        from pybit.unified_trading import HTTP
    except ImportError:
        print("[STOP] pybit is not installed. Install it with: python -m pip install pybit")
        return 2

    print(f"API smoke test target: {'TESTNET' if testnet else 'MAINNET'}")
    print("Only read-only requests will be attempted. No order/write methods are called.")

    try:
        session = HTTP(
            testnet=testnet,
            api_key=key,
            api_secret=secret,
            recv_window=10000,
        )
    except Exception as exc:
        print(f"[FAIL] Could not initialize API client: {type(exc).__name__}: {exc}")
        return 1

    checks: list[tuple[str, object]] = []
    failures = 0

    # Public market-data checks (no account permissions needed).
    try:
        checks.append(("public tickers", session.get_tickers(category="linear", symbol="BTCUSDT")))
    except Exception as exc:
        print(f"[FAIL] public tickers: {type(exc).__name__}: {exc}")
        failures += 1

    try:
        checks.append((
            "public klines",
            session.get_kline(category="linear", symbol="BTCUSDT", interval="5", limit=2),
        ))
    except Exception as exc:
        print(f"[FAIL] public klines: {type(exc).__name__}: {exc}")
        failures += 1

    # Private read-only checks. These can fail if the key lacks the relevant read permission
    # or the account type differs; failure must not be interpreted as an empty account.
    try:
        checks.append((
            "wallet balance (UNIFIED)",
            session.get_wallet_balance(accountType="UNIFIED"),
        ))
    except Exception as exc:
        print(f"[FAIL] wallet balance: {type(exc).__name__}: {exc}")
        failures += 1

    try:
        checks.append((
            "linear positions",
            session.get_positions(category="linear", settleCoin="USDT"),
        ))
    except Exception as exc:
        print(f"[FAIL] linear positions: {type(exc).__name__}: {exc}")
        failures += 1

    try:
        checks.append((
            "linear open orders",
            session.get_open_orders(category="linear", settleCoin="USDT", limit=10),
        ))
    except Exception as exc:
        print(f"[FAIL] linear open orders: {type(exc).__name__}: {exc}")
        failures += 1

    for label, response in checks:
        if not _check_response(label, response):
            failures += 1

    # Remove credential references from this function's local namespace as a small
    # hygiene measure; this does not guarantee memory erasure in Python.
    key = ""
    secret = ""

    if failures:
        print(f"\nRESULT: FAIL — {failures} check(s) failed or returned invalid responses.")
        print("A failed read request is not proof that the account has no data.")
        return 1

    print("\nRESULT: PASS — all requested read-only endpoints returned valid success envelopes.")
    print("This validates only these reads; it does NOT certify the original bot as safe.")
    return 0


def main(argv: Iterable[str]) -> int:
    args = list(argv)
    if len(args) < 2:
        print(
            "Usage:\n"
            "  python readonly_safety_audit.py /path/to/bot.py\n"
            "  python readonly_safety_audit.py /path/to/bot.py --api-check\n"
        )
        return 2

    source_path = Path(args[1]).expanduser()
    if not source_path.is_file():
        print(f"[STOP] Source file not found: {source_path}")
        return 2

    status = static_audit(source_path)
    if status != 0:
        return status

    if "--api-check" in args[2:]:
        return api_smoke_test()

    print("\nAPI smoke test not run. Add --api-check to test read-only endpoints.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
