# Stack Rules: Next.js / React

Stack-specific detection patterns for Next.js and React projects.

## Elevated Risks

- `NEXT_PUBLIC_` exposing server secrets in client bundle
- Server Actions without auth checks
- API routes without middleware protection
- dangerouslySetInnerHTML misuse

## Detection Patterns

### NEXT_PUBLIC_ exposure (upgrade to Crítico)
```
NEXT_PUBLIC_.*SERVICE
NEXT_PUBLIC_.*SECRET
NEXT_PUBLIC_.*PRIVATE
NEXT_PUBLIC_.*ADMIN
```
If found, upgrade to 🔴 Crítico — these values are in the JavaScript bundle sent to every visitor.

### Server Actions without authentication
```typescript
// 'use server' functions accessible without auth check
'use server'
// Look for: no auth.getSession() or getServerSession() call before database operations
```
Severity: 🟠 Alto — anyone can call exposed server actions.

### API routes without middleware
```typescript
// app/api/*/route.ts without auth check
export async function POST(req) {
  // No getServerSession() or auth check at the top
  const data = await req.json();
  // Direct database operation
}
```
Severity: 🟠 Alto — unprotected endpoints.

### Client-side auth checks only
```typescript
// Using useSession() to HIDE ui but not protecting the API
// If the API route doesn't also check auth, the protection is client-only (bypassable)
```
Severity: 🟠 Alto — client-side auth is UI sugar, not real protection.

### Middleware.ts coverage
Check if `middleware.ts` exists and what paths it protects:
```typescript
export const config = { matcher: ['/dashboard/:path*'] }
```
If auth-protected pages aren't in the matcher, flag it.

## Safe Patterns (NOT findings)

```typescript
// Server-side auth check — safe
import { getServerSession } from 'next-auth';
export async function GET() {
  const session = await getServerSession();
  if (!session) return new Response('Unauthorized', { status: 401 });
}
```
