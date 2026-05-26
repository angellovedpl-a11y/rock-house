#!/bin/bash
# Rock House — Dependency Auditor
# Runs npm audit or pip audit based on detected project type
# Usage: bash audit-deps.sh [directory]

DIR="${1:-.}"

echo "🏠 Rock House — Auditing dependencies in $DIR"
echo "================================================"

if [ -f "$DIR/package.json" ]; then
  echo "Node.js project detected. Running npm audit..."
  cd "$DIR" && npm audit 2>&1
  echo ""
  echo "Checking for lockfile..."
  if [ ! -f "package-lock.json" ] && [ ! -f "yarn.lock" ] && [ ! -f "pnpm-lock.yaml" ]; then
    echo "⚠️  No lockfile found! Builds are non-reproducible."
  else
    echo "✅ Lockfile found."
  fi
fi

if [ -f "$DIR/requirements.txt" ] || [ -f "$DIR/pyproject.toml" ]; then
  echo "Python project detected."
  if command -v pip-audit &>/dev/null; then
    echo "Running pip-audit..."
    pip-audit -r "$DIR/requirements.txt" 2>&1
  else
    echo "pip-audit not installed. Run: pip install pip-audit"
  fi
fi

echo "================================================"
echo "Done."
