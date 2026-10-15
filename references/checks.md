# The 15 checks

Index: [1 Uploads](#1-file-upload-validation) · [2 Webhooks](#2-payment-webhook-verification) · [3 XSS](#3-xss-protection) · [4 Secrets](#4-exposed-api-keys-and-secrets) · [5 Authentication](#5-missing-authentication) · [6 Authorization](#6-broken-authorization-idor) · [7 Database rules](#7-open-database-rules) · [8 Injection](#8-sql-nosql-and-command-injection) · [9 Rate limiting](#9-no-rate-limiting) · [10 Dependencies](#10-vulnerable-or-fake-dependencies) · [11 Sessions](#11-weak-sessions-passwords-and-csrf) · [12 CORS and headers](#12-cors-and-security-headers) · [13 Errors and debug](#13-verbose-errors-and-debug-mode) · [14 Privacy](#14-privacy-and-data-exposure) · [15 SSRF](#15-ssrf-and-open-redirects)

Each section has: why it matters, what to look for, and how to fix it. The code snippets are patterns to adapt to the project's stack, not drop-in answers.

---

## 1. File upload validation

**Why it matters.** An upload endpoint that trusts the client lets an attacker send a script, an HTML or SVG file with embedded JavaScript, or a file with a traversal name like `../../app.js`. If the file lands somewhere the server executes or serves from the app's own origin, that's remote code execution or stored XSS. Missing size limits let one request fill the disk or memory.

**Look for**
- Upload handlers: multer, formidable, busboy, `multipart`, FastAPI `UploadFile`, Django `FileField`/`ImageField`, Flask `request.files`, PHP `move_uploaded_file`, direct-to-bucket signed URLs.
- Type decided by the client-supplied `Content-Type` or file extension only.
- No size cap at the parser (not just in the UI).
- The original filename used in the storage path.
- Uploads written under `public/`, `static/`, or the web root, or into a bucket set to public.
- SVG or HTML accepted and served inline.
- Signed upload URLs with no content-type or size conditions.

**Fix**
- Allowlist types, then verify the real type from the file's magic bytes (`file-type` in Node, `python-magic` or opening with Pillow in Python). Never trust the extension or header.
- Cap size and file count in the parser configuration.
- Generate the stored name server-side (UUID plus an extension derived from the detected type). Discard the user's filename or keep it only as database metadata.
- Store outside the web root or in a private bucket. Serve through signed URLs, or with `Content-Disposition: attachment` and `X-Content-Type-Options: nosniff`, ideally from a separate domain.
- Re-encode images (Sharp, Pillow) to strip embedded payloads. Reject SVG unless it is sanitized.
- Require authentication on the endpoint.

```js
// Express + multer: size cap, real type check, random name, no public path
import multer from "multer";
import { fileTypeFromBuffer } from "file-type"; // ESM-only: use dynamic import() in CommonJS
import crypto from "node:crypto";

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 5 * 1024 * 1024, files: 1 } });
const ALLOWED = new Map([["image/png", "png"], ["image/jpeg", "jpg"], ["image/webp", "webp"]]);

app.post("/upload", requireAuth, upload.single("file"), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: "No file" });
  const type = await fileTypeFromBuffer(req.file.buffer);
  if (!type || !ALLOWED.has(type.mime)) return res.status(400).json({ error: "Unsupported file type" });
  const key = `${crypto.randomUUID()}.${ALLOWED.get(type.mime)}`;
  await privateStorage.put(key, req.file.buffer, { contentType: type.mime }); // private bucket, not /public
  res.json({ key });
});
```

---

## 2. Payment webhook verification

**Why it matters.** A webhook is just a public URL. If the handler believes any POST that says `payment_intent.succeeded`, an attacker can send that message themselves and unlock paid features for free. Signature verification is what proves the message came from the payment provider.

**Look for**
- A webhook route that reads `req.body` and acts on `event.type` without verifying `Stripe-Signature` (or the provider's equivalent).
- The signing secret missing, hardcoded, or empty-string-defaulted.
- Verification removed or commented out because "it kept failing". The usual cause is JSON body parsing running before the webhook, which destroys the raw body the signature is computed over.
- Access granted from a client-side redirect to `success_url` instead of from the verified webhook.
- Price, amount, plan, or product ID accepted from the client when creating a checkout.
- User or order ID taken from metadata the client controls.
- No idempotency, so a replayed or duplicated event grants access twice.
- Fulfillment on `checkout.session.completed` without checking `payment_status === "paid"` (delayed payment methods complete the session before the money arrives).

**Fix**
- Verify with the provider's SDK over the raw body, reject with 400 on failure.
- Store processed `event.id`s and ignore repeats.
- Look up prices server-side from your own catalog or provider price IDs; never from the request.
- Create checkout sessions server-side and attach the user ID there.
- Treat the signed webhook (or a server-side retrieve of the session) as the only source of truth for "paid".
- Other providers: LemonSqueezy and Paddle sign with HMAC (compare with a timing-safe function); PayPal has a verify-webhook-signature API; Svix-based services (Clerk and others) ship a verification library.

```js
// Express: raw body for the webhook route ONLY, mounted before express.json()
app.post("/webhooks/stripe", express.raw({ type: "application/json" }), async (req, res) => {
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, req.headers["stripe-signature"], process.env.STRIPE_WEBHOOK_SECRET);
  } catch {
    return res.status(400).send("Invalid signature");
  }
  if (await alreadyProcessed(event.id)) return res.sendStatus(200);
  if (event.type === "checkout.session.completed" && event.data.object.payment_status === "paid") {
    await grantAccess(event.data.object.client_reference_id);
  }
  await markProcessed(event.id);
  res.sendStatus(200);
});
```

```ts
// Next.js App Router
export async function POST(req: Request) {
  const body = await req.text(); // raw text, not req.json()
  const sig = req.headers.get("stripe-signature")!;
  let event;
  try { event = stripe.webhooks.constructEvent(body, sig, process.env.STRIPE_WEBHOOK_SECRET!); }
  catch { return new Response("Invalid signature", { status: 400 }); }
  // ...handle event
  return new Response(null, { status: 200 });
}
```

---

## 3. XSS protection

**Why it matters.** Cross-site scripting lets an attacker's JavaScript run inside another user's session, so it can read what they can read and act as them. It usually enters through content that other users see: comments, usernames, bios, messages, product reviews. Stealing sessions and personal data this way is a data breach with real legal exposure.

**Look for**
- Raw HTML sinks: `dangerouslySetInnerHTML`, `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, Vue `v-html`, Angular `bypassSecurityTrust*`, Jinja `|safe` or `{% autoescape off %}`, EJS `<%- %>`, Handlebars `{{{ }}}`, PHP `echo $_GET[...]`.
- Markdown rendered to HTML with no sanitizer.
- User-controlled `href` or `src` (a `javascript:` URL runs on click).
- User data injected into inline scripts or event handlers, or JSON dumped into a `<script>` tag unescaped.
- `eval` or `new Function` on anything user-influenced.
- `postMessage` listeners that don't check `event.origin`.
- No Content-Security-Policy header. Auth tokens in `localStorage` make any XSS far worse (see check 11).

React, Vue, and Angular escape by default, so most real XSS in modern apps hides behind the escape hatches above. Trace each one back to where its data comes from.

**Fix**
- Delete the raw-HTML sink and render as text. This is the best fix whenever it works.
- When HTML is genuinely needed (rich text, markdown), sanitize with a vetted library using a strict allowlist: DOMPurify on the client, `sanitize-html` on a Node server, `nh3` in Python. Sanitize on the way out as well as on the way in.
- Validate user-supplied URLs to `http:`, `https:`, and `mailto:` only.
- Add a CSP (nonce or hash based, no `unsafe-inline` for scripts) as a second layer. If breaking the site is a risk, start with `Content-Security-Policy-Report-Only`.
- Set session cookies `HttpOnly` so injected script can't read them.

```jsx
// Before: user comment rendered as raw HTML
<div dangerouslySetInnerHTML={{ __html: comment.body }} />

// After (preferred): plain text. React escapes it.
<div>{comment.body}</div>

// After (if formatting is required): sanitized
import DOMPurify from "dompurify";
<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(comment.body) }} />
```

---

## 4. Exposed API keys and secrets

**Why it matters.** Whoever holds a secret key can act as the app: run up the LLM bill, read the database, send email, take payments. "Hiding" a key in a `.env` file does nothing if the variable is exposed to the browser or the file is committed.

**Look for**
- Hardcoded keys in source (`sk-…`, `sk_live_…`, `AKIA…`, `ghp_…`, `whsec_…`, private key blocks, database URLs with passwords).
- Secrets behind public prefixes, which ship to the browser: `NEXT_PUBLIC_*`, `VITE_*`, `REACT_APP_*`, `EXPO_PUBLIC_*`, `NUXT_PUBLIC_*`.
- Secret APIs called directly from frontend code (OpenAI, Anthropic, Stripe secret key, Twilio, SendGrid, Supabase `service_role`).
- `.env` committed to git, or not in `.gitignore`.
- Secrets in git history: check `git log --all --oneline -- '.env*'`, and use gitleaks or trufflehog if they're installed.
- Secrets in `docker-compose.yml`, CI workflow files, `config.json`, notebooks, Postman exports, README examples.

Not leaks, because they're designed to be public: Stripe `pk_` publishable keys, Supabase anon key, Firebase web config, Google Maps keys restricted by referrer. Whether those are *safe* depends on the rules behind them (check 7).

**Fix**
- Move the call to the server (API route, edge function, backend) and have the browser call that instead. Put auth and rate limiting on it (checks 5 and 9), or it's just a free proxy to the paid API.
- Server-only env vars with no public prefix; `.env*` in `.gitignore`; a `.env.example` with placeholder values.
- **Rotate every exposed key** in the provider's dashboard. This is non-negotiable, and it comes before any cleanup.
- Only after rotating, optionally scrub history (`git filter-repo`) and consider a pre-commit scanner such as gitleaks.
- Add provider-side spend limits and key restrictions where available.

---

## 5. Missing authentication

**Why it matters.** Endpoints that never ask "who are you?" are open to the whole internet. AI-generated apps often protect the pages in the UI and forget the API routes behind them.

**Look for**
- API routes, route handlers, server actions, RPC or GraphQL resolvers with no session check.
- Admin routes protected only by a hidden link or a client-side `if (user.isAdmin)`.
- Client-side route guards as the only protection.
- User identity taken from the request body or query (`userId` param) instead of the session.
- Next.js: relying on middleware alone. A 2025 vulnerability (CVE-2025-29927) let a crafted header skip middleware entirely, so check the handler or server action itself too.
- GraphQL introspection or playground open in production; unauthenticated health, debug, or admin endpoints that return data.
- Default or seeded credentials.

**Method.** Build the route inventory: route, method, authenticated yes/no, what it reads or writes. Anything that reads or writes user data without "yes" is a finding. Endpoints that are meant to be public (login, signed webhooks, public pages) should be public on purpose, not by omission.

**Fix**
- Default-deny: one auth middleware, decorator, or wrapper applied to all routes, with an explicit allowlist of public ones.
- Verify the session server-side on every request, in the handler as well as any middleware.
- Derive the user from the session, never from client input.
- Check roles on the server.

---

## 6. Broken authorization (IDOR)

**Why it matters.** Logged in is not the same as allowed. If `/api/invoices/123` returns invoice 123 to anyone with a session, then changing the number reads everyone's invoices. This is one of the most common real-world breaches, and AI-written CRUD code makes it constantly.

**Look for**
- Fetch, update, or delete by an ID from the URL or body with no owner or tenant filter (`findById(req.params.id)`, `WHERE id = $1`).
- Mass assignment: `update(req.body)` or `{...req.body}` letting a user set `role`, `isAdmin`, `credits`, `price`, `userId`, `orgId`.
- Multi-tenant queries missing the org filter.
- Files or exports downloadable by ID or path with no ownership check.
- Responses containing fields the viewer shouldn't see (admin flags, other users' emails).
- Roles or permissions kept client-side or in an unsigned token.
- Supabase or Firebase queries that rely on the frontend to add the `user_id` filter (check 7).

**Fix**
- Scope every query by the authenticated user or tenant: `where: { id, userId: session.user.id }`. Return 404 for things that aren't theirs.
- Accept only an explicit allowlist of fields on writes (zod, pydantic, DTOs). Never spread the request body into a model.
- Centralize permission checks in one policy layer so routes can't forget.
- Unguessable IDs (UUIDs) are defense in depth only, not authorization.

```js
// Before
const doc = await db.document.findUnique({ where: { id: req.params.id } });

// After
const doc = await db.document.findFirst({ where: { id: req.params.id, ownerId: req.user.id } });
if (!doc) return res.sendStatus(404);
```

---

## 7. Open database rules

**Why it matters.** With Supabase and Firebase the browser talks to the database directly, so the only thing between the internet and your data is the rules. No rules, or rules that say "allow all", means anyone with the public key (which is in the page source) can read or rewrite every row.

**Look for**

*Supabase / Postgres*
- Tables in `public` without `ENABLE ROW LEVEL SECURITY`. Check migrations and schema files; count `CREATE TABLE` against `ENABLE ROW LEVEL SECURITY`.
- Policies like `USING (true)` or `WITH CHECK (true)`, or policies granted to `anon` on non-public tables.
- `service_role` key anywhere client-side (it bypasses all rules).
- Policies that trust `user_metadata` (the user can edit it); use `app_metadata` or a server-controlled table.
- Views that bypass RLS (security definer views; use `security_invoker`), `SECURITY DEFINER` functions exposed over RPC, public storage buckets holding private files.

*Firebase*
- `allow read, write: if true`; test-mode rules with a far-future expiry date; rules that don't reference `request.auth.uid`; open Storage rules or Realtime Database `.read`/`.write: true`.

*Other*
- Mongo, Postgres, or Redis reachable from the internet with default or no credentials; S3 buckets set public-read; PocketBase or Appwrite collections with empty rules.

**Fix**
- Enable RLS on every exposed table and write explicit per-operation policies.
- Verify the fix by querying with the anon key while signed out: it should return nothing.
- Firebase: write rules keyed on `request.auth.uid`, and deny by default.
- The rule changes usually live in a migration or the dashboard, so provide the SQL or rules file and list applying it under **Manual steps**.

```sql
alter table public.notes enable row level security;

create policy "owner reads"   on public.notes for select to authenticated using (auth.uid() = user_id);
create policy "owner inserts" on public.notes for insert to authenticated with check (auth.uid() = user_id);
create policy "owner updates" on public.notes for update to authenticated using (auth.uid() = user_id) with check (auth.uid() = user_id);
create policy "owner deletes" on public.notes for delete to authenticated using (auth.uid() = user_id);
```

---

## 8. SQL, NoSQL and command injection

**Why it matters.** When user input is glued into a query or command, the input becomes code. Result: data theft, data deletion, or a shell on the server.

**Look for**
- SQL built with string concatenation or templates: `` `SELECT * FROM users WHERE id = ${id}` ``, `f"... {x}"`, `"..." + x`.
- ORM escape hatches fed user input: `$queryRawUnsafe`, `$executeRawUnsafe`, `sequelize.query` with interpolation, Django `.raw()` or `.extra()`, SQLAlchemy `text(f"...")`.
- NoSQL operator injection: `find({ user: req.body.user })` where the body can contain `{ "$ne": null }`.
- OS commands: `child_process.exec`, `os.system`, `subprocess` with `shell=True`, backticks, built from input.
- `eval`, `new Function`, `vm.runInContext`, template engines rendering user-controlled template strings (`render_template_string`).
- Path traversal: user-controlled file names joined into `fs.readFile`, `sendFile`, `open()`.
- Prototype pollution via deep-merge of user objects.
- Apps with LLM features: model output or user-supplied prompts that flow into tools, shell, SQL, or file access. Treat LLM output as untrusted input.

**Fix**
- Parameterized queries or the ORM's safe API for every query, no exceptions.
- Validate and coerce input with a schema (zod, pydantic) so an object can't arrive where a string is expected.
- `execFile` or `subprocess.run([...], shell=False)` with an argument array, plus an allowlist for anything variable.
- Path traversal: resolve the final path and confirm it stays under the intended base directory.
- Remove `eval`.

```js
// Before
const rows = await db.query(`SELECT * FROM orders WHERE user_id = ${req.query.id}`);
// After
const rows = await db.query("SELECT * FROM orders WHERE user_id = $1", [req.query.id]);
```

---

## 9. No rate limiting

**Why it matters.** Without limits, attackers can guess passwords all day, flood signup and password-reset with junk or email bombs, and call your paid endpoints (LLM, SMS, image generation, email) until the bill is thousands of dollars. This is how "free tier" apps get drained.

**Look for**
- No rate-limit library or gateway rule anywhere in the project.
- Unlimited login, signup, password-reset, OTP, and magic-link endpoints.
- Endpoints that call a paid API with no per-user quota, no input size cap, no `max_tokens`.
- No CAPTCHA or bot check on signup.
- Different error messages for "no such user" vs "wrong password" (user enumeration).
- Unbounded pagination (`?limit=100000`), GraphQL with no depth or batching limits.

**Fix**
- Add rate limiting: `express-rate-limit`, `@upstash/ratelimit` (serverless), `slowapi` or `flask-limiter`, `django-ratelimit`, or edge rules (Cloudflare and similar).
- Tight limits on auth routes (for example 5 attempts per minute per IP and per account), per-user daily quotas on paid endpoints.
- Cap request body size, prompt length, and `max_tokens`; clamp pagination.
- Same generic message for every login failure.
- Turnstile or hCaptcha on signup.
- Set spend caps in the paid provider's dashboard (**Manual step**).

---

## 10. Vulnerable or fake dependencies

**Why it matters.** Most of an app's code is other people's packages. Known-vulnerable versions are exploited automatically at scale. AI tools also sometimes invent package names that don't exist, and attackers register those names with malware ("slopsquatting"), so installing the AI's suggestion can run the attacker's code.

**Look for**
- Known CVEs: `npm audit --omit=dev`, `pip-audit`, `composer audit`, `bundle audit`, `govulncheck`, `cargo audit`. Run whichever applies if available offline or online.
- Every dependency that looks unfamiliar or recently added. Does it exist in the registry, with real history and a sensible download count, and does it match the library the code actually intends? If network access isn't available, list the suspect names for the user to check.
- Typosquat shapes: near-misses of popular names (`reqeusts`, `lodahs`), odd scopes.
- `latest` or `*` version ranges, no lockfile committed, git or URL dependencies, risky install scripts.
- Dockerfiles with `curl | sh`; GitHub Actions pinned to tags instead of commit SHAs.

**Fix**
- Upgrade to patched versions (show the diff; flag major-version bumps that may break things), remove unused packages, commit the lockfile, use `npm ci` in CI.
- Replace or remove anything suspicious, and tell the user to rotate any secrets that were present where a suspicious package was installed.
- Turn on Dependabot or Renovate (**Manual step** if it needs repo settings).

---

## 11. Weak sessions, passwords and CSRF

**Why it matters.** If sessions can be stolen or forged, or passwords are cheap to crack after a leak, attackers walk in as real users.

**Look for**
- Passwords stored plaintext, MD5, SHA-1, or unsalted SHA-256 (should be bcrypt, scrypt, or argon2).
- JWTs: hardcoded or weak secret, `alg: none` accepted, no `exp` or very long lifetime, no way to revoke.
- Session or auth tokens in `localStorage` or `sessionStorage`, where any XSS can steal them.
- Cookies missing `HttpOnly`, `Secure`, or `SameSite`.
- Reset and verification tokens made with `Math.random`, timestamps, or sequential IDs; tokens that never expire, can be reused, or appear in URLs that get logged.
- Cookie-authenticated state-changing routes (POST, PUT, DELETE) with no CSRF defense.
- OAuth flows with no `state` parameter or a loosely validated `redirect_uri`.
- Sessions not invalidated on logout or password change.

**Fix**
- Hash with argon2id or bcrypt. If the app has plaintext or weak hashes in storage, plan a rehash-on-next-login migration and tell the user.
- Use an established auth library or provider (NextAuth/Auth.js, Clerk, Supabase Auth, Django auth) rather than hand-rolled sessions where possible.
- `HttpOnly; Secure; SameSite=Lax` (or Strict) cookies; short-lived access tokens.
- `crypto.randomBytes` or `secrets.token_urlsafe` for tokens, with single use and short expiry.
- CSRF: SameSite cookies plus a CSRF token or Origin/Referer check on state-changing routes.
- Strong signing secret loaded from env.

---

## 12. CORS and security headers

**Why it matters.** Headers tell the browser which protections to enforce. Missing or wrong ones turn small bugs into exploitable ones: a wildcard CORS policy on an authenticated API lets other websites read your users' data from their browsers; no frame protection allows clickjacking.

**Look for**
- `Access-Control-Allow-Origin: *`, especially with credentials; servers that reflect the request's `Origin` back; bare `cors()` on an authenticated API.
- Missing: `Strict-Transport-Security`, `Content-Security-Policy`, `X-Content-Type-Options: nosniff`, `Referrer-Policy`, `frame-ancestors` or `X-Frame-Options`, `Permissions-Policy`.
- `X-Powered-By` exposed; source maps shipped to production.
- Files that shouldn't be public reachable from the web root: `.git/`, `.env`, backups, database dumps; directory listing on.
- HTTP not redirected to HTTPS; mixed content.

**Fix**
- Allowlist exact origins (from env), never `*` with credentials and never reflect arbitrary origins.
- Set the standard headers: `helmet` for Express, `headers()` in `next.config.js`, Django's security settings, Flask-Talisman.
- Roll out CSP in report-only mode first if breakage is a concern.
- Disable production source maps; make sure the static directory contains only intended public files.

---

## 13. Verbose errors and debug mode

**Why it matters.** Stack traces, SQL errors, and debug pages hand attackers a map of your internals, and some debug tools are outright backdoors (Flask's Werkzeug debugger allows code execution).

**Look for**
- `DEBUG = True` (Django), `app.run(debug=True)` (Flask), non-production `NODE_ENV`/`APP_ENV` in deploy config.
- `res.send(err.stack)`, `res.json({ error: err.message })` passing database or library errors to the client.
- GraphQL introspection or playground enabled in production; Swagger/OpenAPI docs exposed publicly.
- Logging passwords, tokens, `Authorization` headers, full request bodies, card or ID numbers, or other personal data (`console.log(req.body)` on a login route).
- Leftover `/debug`, `/test`, `/phpinfo`, `/actuator` endpoints; seeded demo admin accounts.

**Fix**
- Debug flags driven by env and off by default.
- Generic client-facing errors (with a request ID) and detailed errors only in server logs.
- Redact sensitive fields in logs; remove or auth-gate debug routes and docs.

---

## 14. Privacy and data exposure

**Why it matters.** The more personal data an app collects, stores, logs, and returns, the bigger every other bug becomes. A breach of data you didn't need to hold is a legal and reputational problem you chose to take on. Regimes that often apply include GDPR and UK GDPR, CCPA/CPRA, Canada's PIPEDA and Quebec's Law 25, COPPA for children, and HIPAA for health data. This check flags exposure; it isn't legal advice, and the report should say so.

**Look for**
- API responses returning whole user objects (password hashes, emails, phone numbers, internal flags) instead of selected fields.
- Personal data in logs, analytics events, error trackers, URLs, and query strings.
- Highly sensitive fields (government IDs, health, financial) stored unencrypted, or collected with no clear need.
- No way for a user to delete their account or export their data; no retention policy; deleted rows still in backups or logs.
- Third-party trackers or SDKs firing before consent; no cookie banner where one is needed.
- User data sent to LLM or analytics providers without disclosure.
- Public profile or search endpoints exposing more than intended; user-uploaded files publicly readable.
- No privacy policy or terms page.
- Children's data collected without age handling.

**Fix**
- Return explicit field lists (DTOs, `select`), never raw records.
- Collect less. Remove fields the app doesn't use.
- Redact logs; keep personal data out of URLs and analytics.
- Field-level encryption for the most sensitive data.
- Add account deletion and data export endpoints.
- Consent gating for non-essential trackers.
- For policies and legal text, point the user to a lawyer or a reputable template rather than inventing legal language.

---

## 15. SSRF and open redirects

**Why it matters.** If the server fetches a URL the user provides, the attacker can point it at things only the server can reach: cloud metadata endpoints (`169.254.169.254`, which hold credentials), localhost admin panels, internal services. Open redirects let attackers send people to a phishing site from a link that starts on your real domain, and can leak OAuth tokens.

**Look for**
- Server-side fetches of user-supplied URLs: link previews and unfurling, image proxies, "import from URL", webhook testers, PDF or screenshot generators, avatar-by-URL.
- `fetch(req.body.url)`, `requests.get(request.args["url"])`, `axios.get(userUrl)` with no host validation; redirects followed automatically.
- Redirects built from input: `res.redirect(req.query.next)`, `returnTo`, `redirect_uri`, `?url=`.
- Non-HTTP schemes (`file://`, `gopher://`) accepted.

**Fix**
- Allowlist hosts and schemes (https only).
- Resolve DNS and block private, loopback, and link-local ranges, re-checking after every redirect, or disable redirect following.
- Short timeouts and response size caps.
- Cloud: enforce IMDSv2 and least-privilege roles (**Manual step**).
- Redirects: accept only relative paths that start with a single `/` (reject `//` and `/\`) or a fixed allowlist of destinations.

```js
function safeRedirectTarget(next) {
  if (typeof next === "string" && next.startsWith("/") && !next.startsWith("//") && !next.startsWith("/\\")) return next;
  return "/";
}
res.redirect(safeRedirectTarget(req.query.next));
```
