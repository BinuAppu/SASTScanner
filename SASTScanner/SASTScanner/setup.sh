#!/usr/bin/env bash
# Setup script for SASTScanner — run once on any new machine.
set -e

echo "[1/3] Installing Python dependencies..."
# Try pip first; fall back to --break-system-packages for Debian/Ubuntu system Python
pip install -r requirements.txt 2>/dev/null \
  || pip install --break-system-packages -r requirements.txt 2>/dev/null \
  || pip3 install -r requirements.txt 2>/dev/null \
  || pip3 install --break-system-packages -r requirements.txt

echo ""
echo "[2/3] Verifying SAST engines..."

BANDIT_OK=false
SEMGREP_OK=false

if command -v bandit &>/dev/null || python3 -m bandit --version &>/dev/null 2>&1; then
    echo "  bandit  : OK ($(bandit --version 2>&1 | head -1))"
    BANDIT_OK=true
else
    echo "  bandit  : NOT FOUND — install with: pip install bandit"
fi

if command -v semgrep &>/dev/null; then
    echo "  semgrep : OK ($(semgrep --version))"
    SEMGREP_OK=true
else
    echo "  semgrep : NOT FOUND — install with: pip install semgrep"
fi

echo ""
echo "[3/3] Verifying local rule files..."
RULES_DIR="scanner/rules"
RULE_COUNT=$(find "$RULES_DIR" -name '*.yaml' -o -name '*.yml' 2>/dev/null | wc -l)
if [ "$RULE_COUNT" -gt 0 ]; then
    echo "  Found $RULE_COUNT rule file(s) in $RULES_DIR — OK"
    semgrep --config "$RULES_DIR" --validate 2>&1 | tail -1
else
    echo "  ERROR: No rule files found in $RULES_DIR"
    exit 1
fi

echo ""
echo "Setup complete. Start the app with:"
echo "  python app.py"
