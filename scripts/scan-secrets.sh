#!/bin/bash
# Rock House — Secret Scanner
# Scans project files for hardcoded secrets using regex patterns
# Usage: bash scan-secrets.sh [directory]

DIR="${1:-.}"

echo "🏠 Rock House — Scanning for secrets in $DIR"
echo "================================================"

FOUND=0

# AWS Access Key
grep -rn "AKIA[0-9A-Z]\{16\}" "$DIR" --include="*.js" --include="*.ts" --include="*.py" --include="*.jsx" --include="*.tsx" --include="*.json" --include="*.env*" --exclude-dir=node_modules --exclude-dir=.git --exclude-dir=dist --exclude-dir=build 2>/dev/null && FOUND=$((FOUND+1))

# OpenAI Key
grep -rn "sk-[a-zA-Z0-9]\{48\}" "$DIR" --include="*.js" --include="*.ts" --include="*.py" --include="*.jsx" --include="*.tsx" --exclude-dir=node_modules --exclude-dir=.git 2>/dev/null && FOUND=$((FOUND+1))

# Stripe Live Key
grep -rn "sk_live_[a-zA-Z0-9]\{24\}" "$DIR" --include="*.js" --include="*.ts" --include="*.py" --exclude-dir=node_modules --exclude-dir=.git 2>/dev/null && FOUND=$((FOUND+1))

# Generic password/secret patterns
grep -rn "password\s*[:=]\s*[\"'][^\"']\{4,\}" "$DIR" --include="*.js" --include="*.ts" --include="*.py" --include="*.jsx" --include="*.tsx" --exclude-dir=node_modules --exclude-dir=.git -i 2>/dev/null && FOUND=$((FOUND+1))

# NEXT_PUBLIC_ with sensitive names
grep -rn "NEXT_PUBLIC_.*\(SERVICE\|SECRET\|PRIVATE\|ADMIN\|PASSWORD\)" "$DIR" --include="*.env*" --include="*.ts" --include="*.js" 2>/dev/null && FOUND=$((FOUND+1))

# .env tracked by git
if [ -d "$DIR/.git" ]; then
  git -C "$DIR" ls-files | grep -i '\.env' 2>/dev/null && FOUND=$((FOUND+1))
fi

echo "================================================"
if [ $FOUND -gt 0 ]; then
  echo "⚠️  Encontrados $FOUND padrões suspeitos. Revise acima."
else
  echo "✅ Nenhum secret encontrado nos padrões verificados."
fi
