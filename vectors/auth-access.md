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

---

## VEC-AUTH-05: Insecure Password Storage

### What to Look For

Passwords stored with weak or no hashing are trivially cracked via rainbow tables
or brute force. A senior attacker with a database dump cracks MD5/SHA in seconds.

#### Dangerous patterns

```javascript
// Plaintext storage
db.insert({ password: req.body.password })
user.password = password

// Weak hashing — crackable in seconds
crypto.createHash('md5').update(password)
crypto.createHash('sha1').update(password)
crypto.createHash('sha256').update(password)  // fast hash = wrong for passwords
hashlib.md5(password.encode())
hashlib.sha1(password.encode())
hashlib.sha256(password.encode())
```

#### What to search for (Grep patterns)

```
createHash.*md5
createHash.*sha1
createHash.*sha256
hashlib.md5
hashlib.sha1
hashlib.sha256
# Then check if context is password/credential storage
```

Also search for password fields stored without ANY hashing:

```
password: req.body.password
password: password
password = request.form
# Direct assignment to database without hash call nearby
```

#### Safe patterns (NOT findings)

```javascript
// bcrypt — adaptive, slow by design
const bcrypt = require('bcrypt');
const hash = await bcrypt.hash(password, 12);

// argon2 — winner of Password Hashing Competition
const argon2 = require('argon2');
const hash = await argon2.hash(password);

// scrypt — built into Node crypto
const { scrypt } = require('crypto');
```

```python
# passlib with bcrypt/argon2
from passlib.hash import bcrypt
hash = bcrypt.hash(password)

# werkzeug (Flask)
from werkzeug.security import generate_password_hash
hash = generate_password_hash(password, method='pbkdf2:sha256')
```

### Severity Assignment

| Finding | Severity |
|---------|----------|
| Plaintext password stored in database | Critico |
| MD5 hash on passwords | Critico |
| SHA1 hash on passwords | Critico |
| SHA256 without salt on passwords | Alto |
| bcrypt with cost < 10 | Medio |
| No password hashing library detected in auth flow | Alto |

### Fix Suggestions

```javascript
// ❌ Errado — hash rapido = inseguro para passwords
const hash = crypto.createHash('sha256').update(password).digest('hex');

// ✅ Correto — bcrypt com cost 12
const bcrypt = require('bcrypt');
const SALT_ROUNDS = 12;
const hash = await bcrypt.hash(password, SALT_ROUNDS);
const isValid = await bcrypt.compare(inputPassword, storedHash);

// ✅ Ainda melhor — argon2id (estado da arte)
const argon2 = require('argon2');
const hash = await argon2.hash(password, { type: argon2.argon2id });
const isValid = await argon2.verify(storedHash, inputPassword);
```

---

## VEC-AUTH-06: Insecure Randomness

### What to Look For

`Math.random()` is NOT cryptographically secure. Using it for tokens, IDs, or
anything security-sensitive allows attackers to predict values.

#### Dangerous patterns

```javascript
// Math.random for security-sensitive values
const token = Math.random().toString(36)
const resetCode = Math.floor(Math.random() * 999999)
const sessionId = 'sess_' + Math.random()
const apiKey = [...Array(32)].map(() => Math.random().toString(36)[2]).join('')
const otp = String(Math.random()).slice(2, 8)
```

```python
# random module (NOT secure)
import random
token = random.randint(100000, 999999)
code = ''.join(random.choices(string.ascii_letters, k=32))
```

#### What to search for (Grep patterns)

```
Math.random
# Then check if result is used for: token, session, key, code, otp, reset, verify, id, nonce, salt
random.randint
random.choice
random.random
# Same — check if security context
```

#### Safe patterns (NOT findings)

```javascript
// crypto.randomUUID — Node 19+
const id = crypto.randomUUID();

// crypto.randomBytes — all Node versions
const token = crypto.randomBytes(32).toString('hex');

// crypto.getRandomValues — browser + Node
const array = new Uint8Array(32);
crypto.getRandomValues(array);
```

```python
# secrets module (Python 3.6+)
import secrets
token = secrets.token_hex(32)
otp = secrets.randbelow(1000000)
```

### Severity Assignment

| Finding | Severity |
|---------|----------|
| Math.random for auth tokens / session IDs | Critico |
| Math.random for password reset codes | Critico |
| Math.random for API keys or OTPs | Alto |
| Math.random for non-security IDs (display only) | Baixo |
| random module (Python) for tokens | Alto |

### Fix Suggestions

```javascript
// ❌ Errado — previsivel
const resetToken = Math.random().toString(36).slice(2);

// ✅ Correto — criptograficamente seguro
const crypto = require('crypto');
const resetToken = crypto.randomBytes(32).toString('hex');
// Ou: crypto.randomUUID() para IDs
```

---

## VEC-AUTH-07: Missing Input Validation (Schema)

### What to Look For

API endpoints that accept user input without schema validation (Zod, Joi, yup,
Pydantic) allow unexpected data types, extra fields, and malformed payloads.
This is the root cause of many other vulnerabilities (mass assignment, injection, prototype pollution).

#### Dangerous patterns

```javascript
// Direct use of req.body without validation
app.post('/api/users', async (req, res) => {
  const user = await db.users.create(req.body);
});

// Destructuring without type/shape validation
const { email, password } = req.body;
// email could be an object, array, number — not validated

// Next.js API route without validation
export async function POST(req: NextRequest) {
  const data = await req.json();
  await db.insert(data);
}
```

```python
# Flask without schema validation
@app.route('/api/users', methods=['POST'])
def create_user():
    data = request.json
    db.execute("INSERT INTO users ...", data)
```

#### What to search for (Grep patterns)

First, check if a validation library is installed:

```
# package.json — look for ANY of these
"zod"
"joi"
"yup"
"ajv"
"class-validator"
"superstruct"

# requirements.txt / pyproject.toml
pydantic
marshmallow
cerberus
```

If NONE found: flag as Alto — "Nenhuma biblioteca de validacao de input detectada."

Then check each API route handler for validation before database/business logic:

```
// Search for route handlers
app.post(
app.put(
app.patch(
app.delete(
export async function POST
export async function PUT
export async function PATCH
export async function DELETE

// In each, check if req.body / req.json() goes through schema validation
// before being used in db operations
```

#### Safe patterns (NOT findings)

```javascript
// Zod validation at the boundary
const CreateUserSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
});
const validated = CreateUserSchema.parse(req.body);

// Joi
const schema = Joi.object({ email: Joi.string().email().required() });
const { value, error } = schema.validate(req.body);
```

### Severity Assignment

| Finding | Severity |
|---------|----------|
| No validation library in project dependencies | Alto |
| API endpoint with req.body passed directly to DB | Alto |
| Destructured req.body used without type validation | Medio |
| Validation exists but only on some endpoints | Medio |

### Fix Suggestions

```javascript
// ❌ Errado — input direto sem validacao
export async function POST(req: NextRequest) {
  const data = await req.json();
  await supabase.from('users').insert(data);
}

// ✅ Correto — Zod no boundary
import { z } from 'zod';
const CreateUserSchema = z.object({
  name: z.string().min(1).max(100),
  email: z.string().email(),
  password: z.string().min(8).max(128),
});

export async function POST(req: NextRequest) {
  const raw = await req.json();
  const data = CreateUserSchema.parse(raw);
  await supabase.from('users').insert(data);
}
```
