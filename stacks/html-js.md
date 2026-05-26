# Stack Rules: HTML/CSS/JS (Static)

Stack-specific detection patterns for static web projects without backend frameworks.

## Elevated Risks

These are MORE dangerous in static sites because there's no server-side layer:

- XSS via innerHTML/document.write — no server sanitization possible
- localStorage storing sensitive data — accessible by any JS on the page
- Inline event handlers (onclick="") — CSP bypass risk
- External scripts without SRI — supply chain risk

## Detection Patterns

### localStorage with sensitive data
```javascript
localStorage.setItem('token',
localStorage.setItem('password',
localStorage.setItem('user',
sessionStorage.setItem('auth',
```
Severity: 🟠 Alto — any XSS attack can steal these values.

### Inline scripts and event handlers
```html
<script>...</script>  <!-- inline, not from file -->
onclick="
onload="
onerror="
javascript:
```
Severity: 🟡 Médio — makes CSP harder to enforce.

### External scripts without SRI
```html
<script src="https://cdn.example.com/lib.js">
<!-- Missing: integrity="sha384-..." crossorigin="anonymous" -->
```
Severity: 🟡 Médio — CDN compromise = your site compromised.

### Forms posting to HTTP (not HTTPS)
```html
<form action="http://
```
Severity: 🟠 Alto — credentials sent in cleartext.

## Fix Patterns

```html
<!-- ✅ External script with SRI -->
<script src="https://cdn.example.com/lib.js"
  integrity="sha384-abc123..."
  crossorigin="anonymous"></script>

<!-- ✅ CSP meta tag -->
<meta http-equiv="Content-Security-Policy"
  content="default-src 'self'; script-src 'self' https://cdn.example.com">
```
