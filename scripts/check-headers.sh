#!/bin/bash
# Rock House — Security Headers Checker
# Tests security headers on a live URL
# Usage: bash check-headers.sh https://your-site.com

URL="$1"

if [ -z "$URL" ]; then
  echo "Usage: bash check-headers.sh https://your-site.com"
  exit 1
fi

echo "🏠 Rock House — Checking security headers for $URL"
echo "================================================"

HEADERS=$(curl -sI "$URL" 2>/dev/null)

check_header() {
  local name="$1"
  local display="$2"
  if echo "$HEADERS" | grep -qi "$name"; then
    echo "✅ $display: $(echo "$HEADERS" | grep -i "$name" | head -1 | tr -d '\r')"
  else
    echo "❌ $display: MISSING"
  fi
}

check_header "strict-transport-security" "HSTS"
check_header "x-frame-options" "X-Frame-Options"
check_header "x-content-type-options" "X-Content-Type-Options"
check_header "referrer-policy" "Referrer-Policy"
check_header "content-security-policy" "CSP"
check_header "permissions-policy" "Permissions-Policy"

echo "================================================"
