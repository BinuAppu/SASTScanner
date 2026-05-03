#!/usr/bin/env python3
"""
sastscan AI Analysis Module
Decrypts AI config, reads scan findings, queries an AI API for enhanced
analysis and suggestions, and writes ai_findings.csv.
"""

import base64
import csv
import json
import os
import sys
import time
import urllib.error
import urllib.request
from collections import defaultdict

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False


# ── Encryption helpers ────────────────────────────────────────────────────────

def _derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


def decrypt_config(config_file: str, enc_key: str) -> dict:
    if not HAS_CRYPTO:
        raise RuntimeError(
            "cryptography package required. Install: pip3 install cryptography"
        )
    with open(config_file) as fh:
        payload = fh.read().strip()
    salt_b64, token = payload.split(":", 1)
    salt = base64.b64decode(salt_b64)
    key = _derive_key(enc_key, salt)
    try:
        data = Fernet(key).decrypt(token.encode())
        return json.loads(data)
    except Exception as exc:
        raise RuntimeError(f"Decryption failed — wrong encKey? ({exc})") from exc


# ── Findings loader ───────────────────────────────────────────────────────────

def load_findings(report_dir: str) -> list:
    findings = []
    for fname in sorted(os.listdir(report_dir)):
        if not fname.endswith(".csv") or fname == "ai_findings.csv":
            continue
        fpath = os.path.join(report_dir, fname)
        try:
            with open(fpath, newline="", encoding="utf-8", errors="replace") as fh:
                for row in csv.DictReader(fh):
                    row = {k.strip(): v.strip() for k, v in row.items() if k}
                    if "Module" in row and "Severity" in row:
                        findings.append(row)
        except Exception as exc:
            print(f"[AI] Warning: cannot read {fpath}: {exc}", file=sys.stderr)
    return findings


SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def prioritize(findings: list, max_count: int = 100) -> list:
    """Return at most max_count findings sorted by severity, skipping INFO."""
    filtered = [
        f for f in findings
        if f.get("Severity", "").upper() not in ("INFO", "")
        and f.get("File", "")
    ]
    filtered.sort(key=lambda f: SEV_RANK.get(f.get("Severity", "INFO").upper(), 99))
    return filtered[:max_count]


# ── AI API caller ─────────────────────────────────────────────────────────────

def call_ai(config: dict, messages: list) -> str:
    url     = config["url"].rstrip("/")
    model   = config["modelName"]
    version = config.get("apiVersion", "")
    key     = config["subscriptionKey"]

    if version:
        # Azure OpenAI
        endpoint = f"{url}/openai/deployments/{model}/chat/completions?api-version={version}"
        headers  = {"Content-Type": "application/json", "api-key": key}
    else:
        # OpenAI-compatible
        endpoint = f"{url}/v1/chat/completions"
        headers  = {"Content-Type": "application/json", "Authorization": f"Bearer {key}"}

    body = json.dumps({
        "model": model,
        "messages": messages,
        "max_tokens": 2000,
        "temperature": 0.1,
    }).encode()

    req = urllib.request.Request(endpoint, data=body, headers=headers)
    with urllib.request.urlopen(req, timeout=60) as resp:
        result = json.loads(resp.read())
    return result["choices"][0]["message"]["content"]


# ── Batch analysis ────────────────────────────────────────────────────────────

BATCH_SIZE = 8

_SYSTEM = "You are a senior application security engineer. Respond only with valid JSON arrays."

def _build_prompt(batch: list) -> str:
    lines = []
    for i, f in enumerate(batch, 1):
        lines.append(
            f"Finding {i}:\n"
            f"  Module     : {f.get('Module','')}\n"
            f"  File       : {f.get('File','')}, Line: {f.get('Line','')}\n"
            f"  Severity   : {f.get('Severity','')}\n"
            f"  Rule       : {f.get('RuleID','')}\n"
            f"  Title      : {f.get('Title','')}\n"
            f"  Description: {f.get('Description','')[:300]}\n"
            f"  CWE        : {f.get('CWE','')}"
        )
    return (
        "Analyse the SAST findings below. Return a JSON array — one object per finding "
        "(in the same order) — each object with exactly these keys:\n"
        '  "analysis"   : 2-3 sentence root-cause and security-impact explanation\n'
        '  "suggestion" : specific code-level fix, include a short example where helpful\n'
        '  "risk_score" : integer 1-10 (10 = most critical)\n\n'
        "No markdown, no extra text — pure JSON array only.\n\n"
        "Findings:\n" + "\n\n".join(lines)
    )


def analyse_batch(config: dict, batch: list) -> list:
    prompt  = _build_prompt(batch)
    messages = [
        {"role": "system", "content": _SYSTEM},
        {"role": "user",   "content": prompt},
    ]
    raw = call_ai(config, messages).strip()

    # Strip optional markdown code fences
    if raw.startswith("```"):
        parts = raw.split("\n")
        raw = "\n".join(parts[1:-1] if parts[-1].strip() == "```" else parts[1:])

    result = json.loads(raw)
    if isinstance(result, dict):
        result = [result]
    return result


# ── CSV output ────────────────────────────────────────────────────────────────

AI_HEADER = [
    "OriginalModule", "File", "Line", "Severity", "RuleID", "Category",
    "Title", "OriginalDescription", "CWE", "OriginalRecommendation",
    "AIAnalysis", "AISuggestion", "AIRiskScore",
]


def run(config: dict, findings: list, out_csv: str) -> None:
    candidates = prioritize(findings)

    with open(out_csv, "w", newline="", encoding="utf-8") as fh:
        wr = csv.writer(fh, quoting=csv.QUOTE_ALL)
        wr.writerow(AI_HEADER)

        if not candidates:
            print("[AI] No qualifying findings for AI analysis.", file=sys.stderr)
            return

        total_batches = (len(candidates) + BATCH_SIZE - 1) // BATCH_SIZE
        print(
            f"[AI] Analysing {len(candidates)} findings in {total_batches} batch(es)…",
            file=sys.stderr,
        )

        written = 0
        for idx in range(0, len(candidates), BATCH_SIZE):
            batch = candidates[idx : idx + BATCH_SIZE]
            batch_no = idx // BATCH_SIZE + 1
            print(f"[AI] Batch {batch_no}/{total_batches}…", file=sys.stderr)

            try:
                ai_items = analyse_batch(config, batch)
            except (urllib.error.URLError, json.JSONDecodeError, KeyError) as exc:
                print(f"[AI] Batch {batch_no} failed: {exc}", file=sys.stderr)
                ai_items = []

            for j, f in enumerate(batch):
                ai = ai_items[j] if j < len(ai_items) else {}
                wr.writerow([
                    f.get("Module", ""),
                    f.get("File", ""),
                    f.get("Line", ""),
                    f.get("Severity", ""),
                    f.get("RuleID", ""),
                    f.get("Category", ""),
                    f.get("Title", ""),
                    f.get("Description", ""),
                    f.get("CWE", ""),
                    f.get("Recommendation", ""),
                    ai.get("analysis", "AI analysis unavailable"),
                    ai.get("suggestion", ""),
                    str(ai.get("risk_score", "")),
                ])
                written += 1

            if idx + BATCH_SIZE < len(candidates):
                time.sleep(0.5)

    print(f"[AI] Written {written} row(s) → {out_csv}", file=sys.stderr)


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    enc_key     = os.environ.get("SAST_ENC_KEY", "")
    config_file = os.environ.get("SAST_AI_CONFIG", "")
    report_dir  = os.environ.get("SAST_REPORT_DIR", "")
    ai_csv      = os.environ.get("SAST_AI_CSV", "")

    if not all([enc_key, config_file, report_dir, ai_csv]):
        print("[AI] Missing required environment variables.", file=sys.stderr)
        sys.exit(1)

    if not os.path.isfile(config_file):
        print(f"[AI] Config file not found: {config_file}", file=sys.stderr)
        sys.exit(1)

    try:
        config = decrypt_config(config_file, enc_key)
    except RuntimeError as exc:
        print(f"[AI] {exc}", file=sys.stderr)
        sys.exit(1)

    findings = load_findings(report_dir)
    print(f"[AI] Loaded {len(findings)} finding(s) from {report_dir}", file=sys.stderr)

    run(config, findings, ai_csv)


if __name__ == "__main__":
    main()
