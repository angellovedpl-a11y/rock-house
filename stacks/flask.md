# Stack Rules: Flask / Python

Stack-specific detection patterns for Flask and Python web projects.

## Elevated Risks

- Flask debug mode in production
- Secret key hardcoded or weak
- No CSRF protection (Flask doesn't include it by default)
- SQL string formatting (Python f-strings in queries)
- Pickle deserialization of user input

## Detection Patterns

### Debug mode enabled
```python
app.run(debug=True)
DEBUG = True
FLASK_DEBUG=1
```
Severity: 🔴 Crítico in production — exposes interactive debugger (code execution).

### Weak/hardcoded secret key
```python
app.secret_key = 'secret'
app.secret_key = 'development'
SECRET_KEY = 'changeme'
app.config['SECRET_KEY'] = 'any-short-string'
```
Severity: 🔴 Crítico — allows session forgery.

### SQL via f-string or format
```python
f"SELECT * FROM users WHERE id = {user_id}"
"SELECT * FROM users WHERE name = '%s'" % name
"SELECT * FROM users WHERE id = " + str(id)
cursor.execute(f"DELETE FROM {table}")
```
Severity: 🔴 Crítico — SQL injection.

### Missing CSRF protection
Check if Flask-WTF or similar is used:
```python
# Should have:
from flask_wtf.csrf import CSRFProtect
csrf = CSRFProtect(app)
# Or in templates:
{{ form.csrf_token }}
```
If no CSRF library is imported, flag state-changing routes.

### Pickle with user input
```python
pickle.loads(user_data)
pickle.load(request.files['data'])
```
Severity: 🔴 Crítico — arbitrary code execution.

### CORS misconfiguration
```python
CORS(app)  # allows all origins by default
CORS(app, resources={r"/*": {"origins": "*"}})
```

## Safe Patterns

```python
# ✅ Parameterized query
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))

# ✅ ORM usage (SQLAlchemy)
user = User.query.filter_by(id=user_id).first()

# ✅ Strong secret from environment
app.secret_key = os.environ.get('SECRET_KEY')
```
