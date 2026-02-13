#!/usr/bin/env bash
# ─────────────────────────────────────────────────
#  Add health-check endpoint to a backend node
#  Run on: test02, test09
# ─────────────────────────────────────────────────
set -euo pipefail

echo "═══════════════════════════════════════════"
echo "  Backend Health Check Setup"
echo "═══════════════════════════════════════════"

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="${PROJECT_DIR}/venv311"

[ -d "${VENV}" ] && source "${VENV}/bin/activate"
pip install psutil 2>/dev/null || true
grep -q '^psutil' requirements.txt 2>/dev/null || echo "psutil>=5.9.0" >> requirements.txt

echo ""
echo "Checklist — make sure you have:"
echo "  ✓  health_check view in apps/dashboard/views.py"
echo "  ✓  path('api/health/', ...) in apps/dashboard/urls.py"
echo ""
echo "Test:"
echo "  curl http://localhost:8000/api/health/"
echo ""

# Restart dashboard if running
for svc in proxy-dashboard proxy-monitor daphne gunicorn; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        sudo systemctl restart "$svc"
        echo "Restarted $svc"
    fi
done
