#!/bin/bash
# Rock House — Security Headers Checker
# Tests security headers on a live URL
# Usage: bash check-headers.sh <url>

URL="$1"

if [ -z "$URL" ]; then
  echo "Usage: bash check-headers.sh https://your-site.com"
  exit 1
fi

echo "Rock House — Checking security headers for $URL"
echo "================================================"

HEADERS=$(curl -sI --max-time 10 "$URL" 2>/dev/null)
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ] || [ -z "$HEADERS" ]; then
  echo "ERROR: Could not reach $URL (timeout or connection failed)"
  exit 1
fi

STATUS=$(echo "$HEADERS" | head -1 | tr -d '\r')
echo "Status: $STATUS"
echo ""

PASS=0
FAIL=0

check_header() {
  local name="$1"
  local display="$2"
  local value
  value=$(echo "$HEADERS" | grep -i "^$name:" | head -1 | sed "s/^[^:]*: //" | tr -d '\r')
  if [ -n "$value" ]; then
    echo "PASS $display: $value"
    PASS=$((PASS+1))
  else
    echo "FAIL $display: MISSING"
    FAIL=$((FAIL+1))
  fi
}

check_header "strict-transport-security" "HSTS"
check_header "x-frame-options" "X-Frame-Options"
check_header "x-content-type-options" "X-Content-Type-Options"
check_header "content-security-policy" "CSP"
check_header "referrer-policy" "Referrer-Policy"
check_header "permissions-policy" "Permissions-Policy"

echo ""
echo "================================================"
echo "Results: $PASS passed, $FAIL missing"
