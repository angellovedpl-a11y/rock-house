# Vector Module: Upload & Network

Detects SSRF, file upload attacks, and open redirect vulnerabilities.

## VEC-NET-01: SSRF (Server-Side Request Forgery)

### What to Look For

Search for places where the server fetches a URL provided by the user:

```javascript
// Node.js — fetching user-provided URLs
fetch(req.body.url)
axios.get(req.body.url)
http.get(userUrl)
got(req.query.imageUrl)
request(userProvidedUrl)

// Image/file download from URL
downloadImage(req.body.imageUrl)
```

```python
# Python
requests.get(user_url)
urllib.request.urlopen(user_url)
httpx.get(request.json['url'])
```

#### Internal network access

Check if the URL is validated against internal networks:
```
127.0.0.1
localhost
0.0.0.0
10.0.0.0/8
172.16.0.0/12
192.168.0.0/16
169.254.169.254  # AWS metadata endpoint — critical
[::1]  # IPv6 localhost
```

#### Image URL in uploads

Search for upload features that accept URLs instead of files:
```
imageUrl
image_url
avatarUrl
profilePicUrl
thumbnailUrl
```

### Severity Assignment

| Finding | Severity |
|---------|----------|
| Server fetches user URL without validation | 🔴 Crítico |
| No blocklist for internal IPs (127.0.0.1, 10.x, etc.) | 🔴 Crítico |
| Image upload accepts external URLs | 🟠 Alto |
| URL fetch with some validation but no IP blocklist | 🟠 Alto |

### Fix Suggestions

```javascript
// ❌ Errado — aceita qualquer URL
app.post('/api/fetch-image', async (req, res) => {
  const image = await fetch(req.body.url);
});

// ✅ Correto — whitelist + blocklist
const { URL } = require('url');

function isUrlSafe(urlString) {
  const url = new URL(urlString);
  const blocked = ['127.0.0.1', 'localhost', '0.0.0.0', '[::1]'];
  if (blocked.includes(url.hostname)) return false;
  // Block private ranges
  const ip = url.hostname;
  if (ip.startsWith('10.') || ip.startsWith('192.168.') || ip.startsWith('172.')) return false;
  if (ip === '169.254.169.254') return false; // AWS metadata
  // Whitelist allowed domains
  const allowed = ['cdn.meusite.com', 'images.meusite.com'];
  return allowed.includes(url.hostname);
}
```

---

## VEC-NET-02: File Upload Attacks

### What to Look For

#### No file type validation

```javascript
// Accepting any file without checking type
multer({ dest: 'uploads/' })  // no fileFilter
formidable()  // no type check
req.files  // used directly without validation

// Only checking extension (easily spoofed)
if (file.name.endsWith('.jpg'))  // WRONG — check magic bytes
path.extname(file.originalname)  // extension only — insufficient
```

```python
# Flask — no validation
file = request.files['upload']
file.save(os.path.join('uploads', file.filename))  # path traversal + no type check
```

#### Path traversal in filename

```javascript
// Using user filename directly
fs.writeFile(`uploads/${req.file.originalname}`, data)
// Attacker sends filename: "../../../etc/passwd" or "../../app.js"
```

```python
file.save(os.path.join('uploads', file.filename))
# filename could be "../../../etc/passwd"
```

#### Files stored in webroot

Check if uploaded files are stored where they can be directly accessed:
```
uploads/  # inside public/ or static/ directory
public/uploads/
static/uploads/
```

If uploads are in the webroot, a .php or .py file upload becomes a webshell.

### Severity Assignment

| Finding | Severity |
|---------|----------|
| No file type validation at all | 🟠 Alto |
| Extension-only validation (no magic bytes) | 🟠 Alto |
| User filename used directly (path traversal) | 🔴 Crítico |
| Uploads stored in webroot/public directory | 🟠 Alto |
| No file size limit | 🟡 Médio |

### Fix Suggestions

```javascript
// ✅ Correto — validação completa
const multer = require('multer');
const { fileTypeFromBuffer } = require('file-type');

const upload = multer({
  storage: multer.memoryStorage(), // don't write to disk yet
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB max
  fileFilter: (req, file, cb) => {
    const allowed = ['image/jpeg', 'image/png', 'image/webp'];
    cb(null, allowed.includes(file.mimetype));
  },
});

// After upload, verify magic bytes
const type = await fileTypeFromBuffer(req.file.buffer);
if (!type || !['image/jpeg', 'image/png'].includes(type.mime)) {
  return res.status(400).json({ error: 'Tipo de arquivo inválido' });
}

// Use UUID filename, store OUTSIDE webroot
const filename = `${crypto.randomUUID()}.${type.ext}`;
await uploadToS3(filename, req.file.buffer); // external storage
```

---

## VEC-NET-03: Open Redirect

### What to Look For

Search for redirects that use URL parameters:

```javascript
// Express
res.redirect(req.query.redirect)
res.redirect(req.query.next)
res.redirect(req.query.returnTo)
res.redirect(req.body.callbackUrl)

// Next.js
redirect(searchParams.get('redirect'))
router.push(searchParams.get('next'))
window.location = params.get('url')
window.location.href = returnUrl
```

```python
# Flask
redirect(request.args.get('next'))
redirect(request.args.get('redirect'))
return redirect(url)
```

```html
<!-- Meta refresh redirect -->
<meta http-equiv="refresh" content="0;url=${userInput}">
```

### Severity Assignment

| Finding | Severity |
|---------|----------|
| Server redirect using full URL from parameter | 🟠 Alto |
| Client-side redirect (window.location) from URL param | 🟠 Alto |
| Redirect with some validation but bypassable | 🟡 Médio |
| Meta refresh with user input | 🟡 Médio |

### Fix Suggestions

```javascript
// ❌ Errado — aceita qualquer URL
app.get('/login', (req, res) => {
  // After login...
  res.redirect(req.query.next); // attacker: ?next=https://evil.com
});

// ✅ Correto — só aceita paths relativos
function safeRedirect(url) {
  if (!url || !url.startsWith('/') || url.startsWith('//')) {
    return '/dashboard'; // fallback seguro
  }
  return url;
}
res.redirect(safeRedirect(req.query.next));
```
