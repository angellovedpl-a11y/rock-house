# Stack Rules: Supabase / PostgreSQL

Stack-specific detection patterns for projects using Supabase.

## Elevated Risks

- Service role key in client code = total RLS bypass
- Tables without RLS = open to anyone with the anon key
- Incomplete policies = partial protection that feels safe but isn't
- SECURITY DEFINER functions callable from client

## Detection Patterns

### Service key location (upgrade to Crítico)
Search ALL files for service_role patterns. If found in:
- `src/`, `app/`, `components/`, `pages/`, `hooks/` → 🔴 Crítico (client code)
- `api/`, `server/`, `lib/server` → ✅ Safe (server-only)

### createClient with wrong key
```typescript
// Check what key is passed to createClient
createClient(url, process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY)
// NEXT_PUBLIC_ + service_role = 🔴 Crítico
```

### RLS status check
Look in migration files (`supabase/migrations/`) for:
```sql
-- Tables that SHOULD have RLS
CREATE TABLE
-- Then check if followed by:
ALTER TABLE [name] ENABLE ROW LEVEL SECURITY;
-- If not → 🔴 Crítico
```

### Policy completeness
For each table with RLS enabled, check policies exist for ALL operations:
- `FOR SELECT` ✓
- `FOR INSERT` ✓
- `FOR UPDATE` ✓
- `FOR DELETE` ✓

Missing operation policy → 🟠 Alto

### Supabase client-side queries on sensitive tables
```typescript
// Check if these tables are queried from client WITHOUT server intermediary
supabase.from('users').select()
supabase.from('payments').select()
supabase.from('admin_').select()
```
If queried from client, ensure RLS policies are tight.

## Fix Patterns

```typescript
// ✅ Server-only Supabase client
// lib/supabase-server.ts (NOT imported in client components)
import { createClient } from '@supabase/supabase-js';
export const supabaseAdmin = createClient(
  process.env.SUPABASE_URL!,
  process.env.SUPABASE_SERVICE_ROLE_KEY! // NOT NEXT_PUBLIC_
);

// ✅ Client Supabase with anon key only
import { createBrowserClient } from '@supabase/ssr';
export const supabase = createBrowserClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY! // anon only
);
```
