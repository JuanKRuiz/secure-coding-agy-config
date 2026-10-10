---
name: secure-coding
description: >-
  Applies mandatory secure coding rules for Python apps and ADK agents: input
  validation, safe deserialization, XSS output encoding, authentication and
  sessions, access control, password hashing, encryption, secure randomness,
  dependency scanning, OWASP LLM prompt injection and excessive agency
  defenses, human-in-the-loop approval, audit logging, and secrets storage.
  Use when writing or reviewing a Python function or diff that handles
  untrusted input, builds SQL, file paths, or shell commands, renders user
  content in templates, implements login, sessions, password reset, or JWT
  validation, adds role or ownership checks, deserializes, hashes, or encrypts
  data, generates tokens, or stores API keys; when designing an agent's tools,
  permissions, or guardrails; or during the GREEN step of a security fix.
  Don't use as the entry point for fixing a vulnerability or adding
  authentication or authorization logic (use test-driven-development), for
  starting a security review (use threat-modeling), or for non-Python code.
---

# Secure Coding Guidelines

This document outlines the mandatory secure coding practices for Python applications and AI agents built using an Agent Development Kit (ADK). These guidelines are designed to comply with typical corporate and cloud governance concerns, preventing common vulnerabilities (such as OWASP Top 10, OWASP Top 10 for LLM Applications 2025) and ensuring system integrity.

---

## Part 1: Python Application Security (AppSec)

### 1. Input Validation and Sanitization
- **Strict Allow-lists**: Validate all inputs (API requests, file uploads, CLI arguments, environment variables, environment configs) against strict allow-lists of expected formats, sizes, and character sets.
- **Type Checking**: Enforce type constraints using Python type hinting and runtime validation libraries (e.g., `pydantic` or `marshmallow`).
- **Parsing instead of Regex**: Prefer robust parsing libraries (e.g., `urllib.parse` for URLs, `email.utils` for emails) over complex custom regular expressions which are prone to ReDoS (Regular Expression Denial of Service).

### 2. Preventing Injection Vulnerabilities
- **SQL Injection**:
  - **Never** construct SQL queries using string concatenation, formatting (f-strings), or interpolation.
  - **Always** use parameterized queries / prepared statements (e.g., `cursor.execute("SELECT * FROM users WHERE username = %s", (username,))`) or a secure ORM (e.g., SQLAlchemy, Django ORM).
- **Command Injection**:
  - Avoid invoking shell commands via `os.system`, `subprocess.Popen(..., shell=True)`, or `eval`/`exec`.
  - If execution is unavoidable, pass arguments as a list to `subprocess.run(..., shell=False)` and validate both the executable path and arguments against a strict, hardcoded allow-list.
- **Path Traversal / Arbitrary File Access**:
  - Never trust user-provided paths or filenames directly.
  - Canonicalize before checking: join the user value to the sandbox and resolve it to its absolute, symlink-free form with `pathlib.Path.resolve()` (or `os.path.realpath()`), so `..` segments and symlinks are collapsed first (an absolute user path replaces the sandbox in the join, and the boundary check below then rejects it).
  - **Strict Boundary Check (primary)**: On Python 3.9+, verify containment with `Path(target).resolve().is_relative_to(Path(sandbox).resolve())`, where `target` is `Path(sandbox) / user_path`, and reject the request when it returns `False`. It also accepts the sandbox root itself, so also require `target.is_file()` (or `target.resolve() != Path(sandbox).resolve()`) when a file is expected.
  - **Fallback (Python < 3.9 only)**: `os.path.realpath(target).startswith(os.path.realpath(sandbox) + os.sep)`. The trailing `os.sep` prevents partial-prefix bypasses (e.g., `/sandbox-malicious` matching `/sandbox`); a bare `startswith(sandbox)` is not a boundary check.
  - `os.path.basename()` alone is **not** a boundary check: it strips directory components but neither resolves symlinks nor enforces containment. Use it only as extra filename normalization before the canonical boundary check.

### 3. Safe Serialization and Deserialization
- **Insecure Deserialization**:
  - **Never** use `pickle`, `marshal`, or `shelve` to deserialize untrusted data, as they allow arbitrary code execution.
  - For data serialization, use safe formats such as JSON (`json.loads`) or safe YAML loading (`yaml.safe_load`, **never** `yaml.load`).
  - For XML parsing, use `defusedxml` to prevent XML External Entity (XXE) and XML Entity Expansion attacks.

### 4. Cryptography and Hashing
- **Hashing**:
  - **Never** use insecure hashing algorithms (e.g., MD5, SHA-1) for sensitive data, signatures, or password hashing.
  - Use established, memory-hard hashing functions (e.g., Argon2, bcrypt, or PBKDF2) for passwords and credential storage.
  - Use SHA-256 or SHA-3 for general cryptographic hashes/integrity checks.
- **Encryption**:
  - Use authenticated encryption (e.g., AES-GCM or ChaCha20-Poly1305 via `cryptography.hazmat.primitives.ciphers.aead`).
- **Randomness**:
  - Use `secrets` (cryptographically secure pseudo-random number generator) for tokens, keys, and security-sensitive values.
  - **Never** use the standard `random` module for security-sensitive operations.

### 5. Dependency Management
- **Scan Dependencies**: Run dependency scanning tools (e.g., `pip-audit` or `safety`) to identify known vulnerabilities in third-party libraries.
- **Pin Versions**: Pin exact versions in `requirements.txt` or `pyproject.toml` to prevent supply chain attacks (dependency confusion, malicious updates).
- **Internal Repositories**: Use private artifact registries (e.g., Artifact Registry) for internal dependencies.

### 6. Output Encoding and XSS Prevention
- **Autoescape Always On**:
  - Keep template autoescaping enabled: Jinja2 `Environment(autoescape=select_autoescape(["html", "xml"]))` (Flask enables it for `.html` templates) and Django templates (on by default).
  - **Never** wrap untrusted data in `{% autoescape false %}` (Jinja2) or `{% autoescape off %}` (Django).
- **No Trust Markers on Untrusted Data**:
  - **Never** apply `|safe`, `Markup(...)`, or `mark_safe(...)` to any string that contains user-controlled or API-supplied content.
  - When building HTML in Python, escape each value with `markupsafe.escape()` (or use Django `format_html()` with arguments) instead of string concatenation or f-strings.
- **Context-Aware Encoding**: HTML-body escaping does not protect other contexts; encode for the exact sink:
  - HTML attributes: always quote attribute values and escape them; never place untrusted data in event-handler attributes (`onclick`, `onerror`) or `style`.
  - JavaScript: pass data as JSON with Jinja2 `{{ data|tojson }}` or Django `{{ data|json_script:"data-id" }}`, never by interpolating values into `<script>` blocks.
  - URLs: percent-encode path segments with `urllib.parse.quote(value, safe="")` and query strings with `urllib.parse.urlencode()`, and allow-list schemes (`https`, `mailto`) before rendering into `href`/`src`, which blocks `javascript:` URLs.
- **Rich Text**: When users must submit HTML, sanitize it server-side with a vetted allow-list sanitizer such as `nh3` (or `bleach` in legacy code), restricting tags, attributes, and URL schemes. **Never** write a custom regex-based HTML sanitizer.
- **Content Security Policy**: Send a `Content-Security-Policy` header (e.g., `script-src 'nonce-{nonce}' 'strict-dynamic'; object-src 'none'; base-uri 'none'` with a fresh per-response nonce from `secrets.token_urlsafe(16)`) without `'unsafe-inline'`, plus `X-Content-Type-Options: nosniff`. Serve API responses with `Content-Type: application/json`, never `text/html`.
- **Client-Side Rendering**: Frontends must render API data with `textContent` or framework bindings that escape by default, **never** `innerHTML`, `outerHTML`, `document.write`, `dangerouslySetInnerHTML`, or `v-html`.

### 7. Authentication and Session Management
- **Password Storage**: Hash passwords as defined in section 4 (Cryptography and Hashing) and verify them with the library's verify function (e.g., `argon2.PasswordHasher().verify`, which raises `VerifyMismatchError` on a wrong password instead of returning `False`; call `check_needs_rehash()` after a successful login to upgrade the stored hash). **Never** store, log, or reversibly encrypt plaintext passwords.
- **Constant-Time Comparison**: Compare tokens, API keys, and HMAC signatures as `bytes` with `hmac.compare_digest()` (it raises `TypeError` on non-ASCII `str`), **never** `==`, to prevent timing attacks.
- **Brute-Force Protection**:
  - Rate-limit login, password-reset, and MFA endpoints per account and per client IP (e.g., `Flask-Limiter`, `django-axes`), with progressive delays or temporary account lockout.
  - Return generic errors (e.g., "Invalid username or password") that do not reveal whether an account exists.
- **Multi-Factor Authentication**: Require MFA (e.g., WebAuthn or TOTP via `pyotp`) for administrative and other privileged accounts.
- **Session Lifecycle**:
  - Regenerate the session id on login and on any privilege change to prevent session fixation (Django `login()` calls `cycle_key()`; Flask's default session is a signed client-side cookie that cannot be revoked server-side, so for revocable sessions use a server-side store such as Flask-Session and call `app.session_interface.regenerate(session)` on login; `session.clear()` alone keeps the same session id).
  - Invalidate the session server-side on logout and enforce idle and absolute timeouts.
- **Cookie Flags**: Set session and auth cookies with `Secure`, `HttpOnly`, and `SameSite=Lax` (or `Strict`), e.g., Django `SESSION_COOKIE_SECURE = True`, `SESSION_COOKIE_HTTPONLY = True`, `SESSION_COOKIE_SAMESITE = "Lax"` (Flask uses the same setting names), plus Django `CSRF_COOKIE_SECURE = True`, which defaults to `False`.
- **CSRF Protection**: Protect every cookie-authenticated state-changing request (`POST`, `PUT`, `PATCH`, `DELETE`) with CSRF tokens (Django `CsrfViewMiddleware`, Flask-WTF `CSRFProtect`). **Never** change state on `GET`, and never `@csrf_exempt` a cookie-authenticated view.
- **Password Reset Tokens**: Generate them with `secrets.token_urlsafe(32)`, store only their hash, bind them to one account, make them single-use, expire them quickly (e.g., 15 to 60 minutes), and invalidate existing sessions after a successful reset.
- **JWT Validation**:
  - Always verify the signature and pin an algorithm allow-list, e.g., PyJWT `jwt.decode(token, key, algorithms=["RS256"], audience="my-api", issuer="https://issuer.example", options={"require": ["exp", "aud", "iss"]})`.
  - **Never** accept `alg=none`, disable signature verification (`options={"verify_signature": False}`), or read the allowed algorithm from the token header.

### 8. Authorization and Access Control
- **Deny by Default**: Every route, view, and API endpoint requires authentication and an explicit permission unless it is deliberately marked public; new endpoints start locked.
- **Server-Side Checks on Every Request**: Enforce authorization in the backend on each request. Hiding buttons, menu items, or routes in the UI is not access control.
- **Object-Level Ownership Checks (IDOR)**:
  - Scope every lookup to the caller, e.g., Django `get_object_or_404(Invoice, pk=invoice_id, owner=request.user)` or SQLAlchemy `session.query(Invoice).filter_by(id=invoice_id, owner_id=current_user.id).one_or_none()`, and return 404 when nothing matches.
  - **Never** fetch a record by a client-supplied id alone; apply the same check to reads, updates, deletes, and file downloads.
- **Centralized Role and Permission Checks**: Implement checks once in a decorator, middleware, or dependency (e.g., a custom `@require_role("admin")`, Django `@permission_required`, DRF permission classes, FastAPI `Depends`) instead of ad-hoc `if` statements scattered across handlers.
- **Never Trust Client-Supplied Identity**:
  - Derive the user id, tenant, and role from the authenticated session or verified token, **never** from the request body, query parameters, hidden form fields, or headers such as `X-User-Id` or `X-Role`.
  - Block mass assignment of privileged fields (`is_admin`, `role`, `owner_id`) by binding requests to explicit allow-listed schemas.
- **Least Privilege for Service Accounts**: Give each service, job, and agent its own identity with only the roles it needs (e.g., a dedicated IAM service account with narrowly scoped roles, a read-only database user for read paths), **never** shared admin or owner credentials.

---

## Part 2: Securing AI/LLM Agents in ADK (Agentic Security & Governance)

AI Agents built with an Agent Development Kit (ADK) run autonomously and can perform actions via tools. This requires strict security and governance measures to prevent the risks catalogued in the OWASP Top 10 for LLM Applications 2025, notably **Prompt Injection** (LLM01), **Improper Output Handling** (LLM05), **Excessive Agency** (LLM06), **System Prompt Leakage** (LLM07), and **Unbounded Consumption** (LLM10).

### 1. Principle of Least Privilege & Excessive Agency (LLM06)
- **Granular Tool Access**: Only equip the agent with the minimum set of tools required to perform its specific task. Do not grant a generic agent access to administrative or system tools.
- **Fine-Grained Permissions**: Ensure the credentials or API keys used by the agent's tools have restricted permissions. For example, a database tool should connect with a read-only user if the agent only needs to query data.
- **Sandboxed Execution**: Any code execution tool (e.g., Python interpreter, bash runner) MUST run in an isolated, sandboxed environment (e.g., gVisor, Docker container, microVM) with strict resource limits, network egress filtering, and no access to the host filesystem.
- **Unbounded Consumption (LLM10)**: Cap every agent loop with a maximum number of iterations and tool calls per turn, per-request token limits, per-user rate limits, timeouts, and a spend budget with alerts; fail closed when a limit is hit.

### 2. Tool & Plugin Input Validation and Improper Output Handling (LLM05)
- **Do Not Trust LLM Output**: The arguments generated by the LLM to invoke a tool must be treated as untrusted user input.
- **Validate Arguments**: Validate tool parameters strictly (e.g., check types, enforce schema validation using Pydantic, validate parameter formats, ensure paths are canonical and sandboxed).
- **Sanitize Commands & Queries**: If an agent uses a database tool or a command-line tool, parameterize queries and restrict allowed commands rather than allowing arbitrary execution.
- **Encode Model Output Downstream**: Treat model responses rendered in web UIs, emails, or reports as untrusted and apply Part 1 section 6 (Output Encoding and XSS Prevention) before display.

### 3. Prompt Injection Defense (LLM01)
- **System Instructions Integrity**: Protect the agent's system instructions from being overridden. Use structural delimiters (e.g., `<system_instructions>...</system_instructions>`) to clearly separate system directives from user inputs.
- **Indirect Prompt Injection**: Treat all retrieved documents, emails, search results, web pages, and database records as untrusted sources of instructions. The agent must parse them as data, not as directives.
- **Layered Defenses**: No single control stops prompt injection, and regex or keyword filters alone are insufficient because payloads can be paraphrased, encoded, or translated. Combine:
  - Privilege separation: the agent or sub-agent that reads untrusted content must not hold high-impact tools; only validated, structured data crosses to the privileged agent (dual-LLM pattern).
  - Tool allow-lists: expose only the tools the task needs, with strictly validated arguments (section 2).
  - Human-in-the-loop approval for every state-changing action (section 4).
  - A dedicated prompt injection classifier or guardrail service (e.g., Google Cloud Model Armor) screening user inputs, retrieved content, and model outputs.
- **System Prompt Leakage (LLM07)**: Assume the system prompt will leak. **Never** place secrets, API keys, connection strings, or authorization logic in system instructions; enforce permissions in code and tool credentials instead.

### 4. Human-in-the-Loop (HITL) for Governance
- **State-Changing Actions**: Require explicit human approval (HITL) before executing any high-risk or state-changing action. This includes:
  - Writing or deleting database records.
  - Making financial transactions.
  - Sending external emails or notifications.
  - Deploying code or configuration changes.
  - Executing system commands or scripts.
- **Approval Mechanisms**: Implement interactive approval modals, Slack/email confirmations, or explicit CLI confirmations.

### 5. Audit Logging and Traceability
- **Comprehensive Logging**: Log all aspects of the agent's lifecycle:
  - User prompts and system instructions.
  - LLM raw inputs and outputs.
  - Tool calls, including target tool, arguments, execution status, and raw tool output.
  - Model decisions and reasoning paths.
- **PII and Secret Masking**: Prior to logging or storing traces, mask sensitive data, including PII, credentials, API keys, and session tokens.
- **Immutable Log Storage**: Store audit logs in a centralized, read-only, tamper-evident logging service (e.g., Cloud Logging with restricted IAM access) to ensure audit compliance.

### 6. Secrets and Credential Management
- **No Hardcoding**: Never hardcode API keys (e.g., OpenAI, Gemini, GitHub tokens) or database passwords in agent code, prompts, or configuration files.
- **Environment and KMS**: Load secrets dynamically from environment variables or a Secret Manager (e.g., Google Cloud Secret Manager).
- **Ephemeral Credentials**: Where possible, use short-lived credentials, IAM workload identity federation, or OAuth tokens instead of long-lived keys.
