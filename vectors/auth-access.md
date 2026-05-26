# Vector Module: Auth & Access

Detects RLS bypass, IDOR, JWT/session issues, and mass assignment vulnerabilities.

## VEC-AUTH-01: RLS Bypass (Supabase / PostgreSQL)

### What to Look For

#### Service Key in Client Code

Search for Supabase service role key used in client-side code:

```
# Direct service key usage
createClient.*service_role
SUPABASE_SERVICE_ROLE
supabaseAdmin
createServiceRoleClient

# In files that run on the client (NOT in API routes or server files)
# Client files: components/, pages/ (without 'use server'), app/**/page.tsx, hooks/
```

The `service_role` key bypasses ALL RLS policies. It must NEVER appear in client-side code.

#### Incomplete RLS Policies

If Supabase is detected, check for:
- Tables without RLS enabled (check migration files or Supabase config)
- Policies that only cover SELECT but miss INSERT, UPDATE, DELETE
- Policies using `SECURITY DEFINER` functions callable from client

Search for patterns:
```
ALTER TABLE .* ENABLE ROW LEVEL SECURITY
CREATE POLICY .* FOR SELECT
CREATE POLICY .* FOR INSERT
CREATE POLICY .* FOR UPDATE
CREATE POLICY .* FOR DELETE
SECURITY DEFINER
```

If a table has SELECT policy but no UPDATE/DELETE policies, flag it.

#### Anon Key Misuse

Check if the `anon` key is used with operations that should require auth:
```
supabase.from('sensitive_table').delete()
supabase.from('users').update()
# Without prior supabase.auth.getUser() check
```

### Severity Assignment

| Finding | Severity |
|---------|----------|
| Service role key in client-side code | 🔴 Crítico |
| Table with RLS disabled | 🔴 Crítico |
| SELECT policy exists but no UPDATE/DELETE policies | 🟠 Alto |
| SECURITY DEFINER function callable from client | 🟠 Alto |
| Anon key used for privileged operations | 🟠 Alto |

### Fix Suggestions

```typescript
// ❌ Errado — service key no client
import { createClient } from '@supabase/supabase-js';
const supabase = createClient(url, process.env.NEXT_PUBLIC_SERVICE_ROLE_KEY);

// ✅ Correto — service key só no server (API route)
// app/api/admin/route.ts
import { createClient } from '@supabase/supabase-js';
const supabaseAdmin = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY);
```

```sql
-- ✅ RLS completo — policy pra cada operação
ALTER TABLE posts ENABLE ROW LEVEL SECURITY;
CREATE POLICY "users read own posts" ON posts FOR SELECT USING (auth.uid() = user_id);
CREATE POLICY "users insert own posts" ON posts FOR INSERT WITH CHECK (auth.uid() = user_id);
CREATE POLICY "users update own posts" ON posts FOR UPDATE USING (auth.uid() = user_id);
CREATE POLICY "users delete own posts" ON posts FOR DELETE USING (auth.uid() = user_id);
```

---

## VEC-AUTH-02: IDOR (Insecure Direct Object Reference)

### What to Look For

Search for API endpoints that use IDs from URL parameters without verifying ownership:

```
# Express / Next.js API routes
req.params.id
req.query.id
params.id
searchParams.get('id')

# Flask
request.args.get('id')
<int:id>
<user_id>

# Combined with database queries WITHOUT ownership check
.findById(
.findOne({ _id:
.from('table').select().eq('id',
WHERE id =
```

The pattern to detect: endpoint receives an ID → queries database with that ID → returns data WITHOUT checking if the authenticated user owns that resource.

#### Safe Pattern (NOT a finding)

```javascript
// This is safe — checks ownership
const post = await db.posts.findOne({ id: req.params.id, userId: req.user.id });
```

#### Unsafe Pattern (IS a finding)

```javascript
// This is IDOR — no ownership check
const post = await db.posts.findOne({ id: req.params.id });
```

### Severity Assignment

| Finding | Severity |
|---------|----------|
| IDOR on user profile/personal data endpoint | 🔴 Crítico |
| IDOR on financial/payment data | 🔴 Crítico |
| IDOR on content/posts (read) | 🟠 Alto |
| IDOR on content/posts (update/delete) | 🔴 Crítico |
| IDOR on public data (non-sensitive) | 🟡 Médio |

### Fix Suggestions

```javascript
// ❌ Errado — qualquer usuário acessa qualquer recurso
app.get('/api/invoices/:id', async (req, res) => {
  const invoice = await Invoice.findById(req.params.id);
  res.json(invoice);
});

// ✅ Correto — verifica ownership
app.get('/api/invoices/:id', async (req, res) => {
  const invoice = await Invoice.findOne({
    _id: req.params.id,
    userId: req.user.id  // ownership check
  });
  if (!invoice) return res.status(404).json({ error: 'Not found' });
  res.json(invoice);
});
```

---

## VEC-AUTH-03: JWT / Session Issues

### What to Look For

#### Algorithm "none"

Search for JWT configuration that allows or doesn't restrict algorithms:
```
algorithms: ['none']
algorithm: 'none'
verify: false
jwt.decode(  # decode without verify
jsonwebtoken.decode(  # same
```

#### Weak Secret

Search for JWT secrets that are short or common:
```
jwt.sign(.*, ['"](?:secret|password|123|test|key|jwt)['"]) 
JWT_SECRET=(?:secret|password|test|key|123)
process.env.JWT_SECRET  # check if the env var is actually set
```

#### No Expiration

Search for JWT creation without expiration:
```
jwt.sign\(.*\)  # without expiresIn
# Check if the sign call includes expiresIn or exp claim
```

#### Cookie Flags Missing

Search for session/cookie configuration:
```
cookie\s*:\s*{  # then check for httpOnly, secure, sameSite
Set-Cookie:  # check for HttpOnly; Secure; SameSite=
session.*cookie  # framework session config
```

Cookies must have: `HttpOnly` (JS can't read), `Secure` (HTTPS only), `SameSite=Strict` or `Lax` (anti-CSRF).

### Severity Assignment

| Finding | Severity |
|---------|----------|
| Algorithm "none" allowed | 🔴 Crítico |
| JWT decoded without verification | 🔴 Crítico |
| JWT secret is common/weak string | 🔴 Crítico |
| JWT without expiration | 🟠 Alto |
| Cookies without HttpOnly | 🟠 Alto |
| Cookies without Secure flag | 🟠 Alto |
| Cookies without SameSite | 🟡 Médio |

### Fix Suggestions

```javascript
// ❌ Errado — sem expiração, secret fraco
const token = jwt.sign({ userId: user.id }, 'secret');

// ✅ Correto — RS256, expiração curta, secret forte
const token = jwt.sign(
  { userId: user.id },
  process.env.JWT_SECRET, // secret forte (≥256 bits)
  { algorithm: 'HS256', expiresIn: '15m' }
);

// ✅ Cookies seguros
res.cookie('session', token, {
  httpOnly: true,
  secure: true,
  sameSite: 'strict',
  maxAge: 15 * 60 * 1000, // 15 min
});
```

---

## VEC-AUTH-04: Mass Assignment

### What to Look For

Search for patterns where request body is passed directly to database operations:

```javascript
// Dangerous patterns
Object.assign(user, req.body)
{ ...req.body }
Model.create(req.body)
db.insert(req.body)
.update(req.body)
prisma.user.create({ data: req.body })
supabase.from('users').insert(req.body)
```

```python
# Flask dangerous patterns
**request.json
**request.form
Model(**data)  # where data comes from request
db.session.add(Model(**request.json))
```

The danger: if the database has fields like `role`, `is_admin`, `is_verified`, an attacker can send `{ "name": "Hacker", "role": "admin" }` and become admin.

### Severity Assignment

| Finding | Severity |
|---------|----------|
| req.body passed to user/auth table operations | 🔴 Crítico |
| req.body passed to any table with role/permission fields | 🔴 Crítico |
| req.body passed to content tables | 🟠 Alto |
| Spread operator on request data without whitelist | 🟠 Alto |

### Fix Suggestions

```javascript
// ❌ Errado — aceita qualquer campo
app.post('/api/register', async (req, res) => {
  const user = await User.create(req.body);
});

// ✅ Correto — whitelist explícita de campos
app.post('/api/register', async (req, res) => {
  const { name, email, password } = req.body;
  const user = await User.create({ name, email, password });
  // role, is_admin, is_verified NUNCA vêm do request
});
```

```python
# ❌ Errado
user = User(**request.json)

# ✅ Correto — schema validation com campos permitidos
from pydantic import BaseModel
class RegisterSchema(BaseModel):
    name: str
    email: str
    password: str
# role, is_admin não estão no schema = ignorados
```
