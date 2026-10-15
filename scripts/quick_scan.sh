#!/usr/bin/env bash
# app-lockdown quick scan
#
# A fast grep-based first pass over a project. It produces LEADS for Claude to
# confirm by reading the code; it is not a verdict and it will have false
# positives and misses. Secret matches are printed as file:line only, never the
# matched text, so the output is safe to paste into a report.
#
# Usage: bash quick_scan.sh [project-root]

set -u
ROOT="${1:-.}"
cd "$ROOT" 2>/dev/null || { echo "Cannot open directory: $ROOT" >&2; exit 1; }

Q="[\"']"      # a quote character, single or double
BT='`'         # a backtick

EXCL=(
  --exclude-dir=node_modules --exclude-dir=.git --exclude-dir=dist
  --exclude-dir=build --exclude-dir=.next --exclude-dir=.nuxt
  --exclude-dir=venv --exclude-dir=.venv --exclude-dir=__pycache__
  --exclude-dir=vendor --exclude-dir=coverage --exclude-dir=.turbo
  '--exclude=*.min.js' '--exclude=*.map' '--exclude=*.lock'
  '--exclude=package-lock.json' '--exclude=LOCKDOWN_REPORT.md'
)

SECTIONS=0

# scan <check-id> <title> <mask 0|1> <ERE pattern> [extra grep flags]
scan() {
  local id="$1" title="$2" mask="$3" pattern="$4" flags="${5:-}"
  local out
  # shellcheck disable=SC2086
  out=$(grep -rInE $flags "${EXCL[@]}" -e "$pattern" . 2>/dev/null | sed 's|^\./||' | head -40)
  [ -z "$out" ] && return
  echo "## [$id] $title"
  if [ "$mask" = "1" ]; then
    echo "$out" | cut -d: -f1,2 | sed 's/^/  /'
  else
    echo "$out" | cut -c1-180 | sed 's/^/  /'
  fi
  echo
  SECTIONS=$((SECTIONS + 1))
}

note() { echo "## [$1] $2"; shift 2; for l in "$@"; do echo "  $l"; done; echo; SECTIONS=$((SECTIONS + 1)); }

# Files matching a pattern, ignoring manifests and docs that merely mention a library name
have_files() { grep -rIlE "${EXCL[@]}" -e "$1" . 2>/dev/null | sed 's|^\./||' | grep -vE '(package\.json|composer\.json|requirements\.txt|\.md)$'; }

echo "# app-lockdown quick scan of: $(pwd)"
echo "# Leads only. Confirm each by reading the code."
echo

# ---------- Stack hints ----------
stack=""
[ -f package.json ] && stack="$stack node"
[ -f requirements.txt ] || [ -f pyproject.toml ] && stack="$stack python"
[ -f composer.json ] && stack="$stack php"
[ -f Gemfile ] && stack="$stack ruby"
[ -f go.mod ] && stack="$stack go"
[ -d supabase ] && stack="$stack supabase"
[ -f firebase.json ] || [ -f firestore.rules ] && stack="$stack firebase"
echo "# Stack hints:${stack:- none detected}"
echo

# ---------- 4. Secrets ----------
scan 4 "Possible hardcoded secrets (values hidden; file:line only)" 1 \
  "sk_live_[0-9a-zA-Z]{16,}|sk-[A-Za-z0-9_-]{20,}|sk-ant-[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|xox[baprs]-[A-Za-z0-9-]{10,}|whsec_[A-Za-z0-9]{16,}|-----BEGIN ([A-Z]+ )?PRIVATE KEY-----"

scan 4 "Generic secret-looking assignments (values hidden; file:line only)" 1 \
  "(api[_-]?key|secret|passwd|password|token|private[_-]?key)${Q}?[[:space:]]*[:=][[:space:]]*${Q}[A-Za-z0-9_/+=.-]{12,}${Q}" "-i"

scan 4 "Secret-looking env vars exposed to the browser via a public prefix" 0 \
  "(NEXT_PUBLIC|VITE|REACT_APP|EXPO_PUBLIC|NUXT_PUBLIC|GATSBY)_[A-Z0-9_]*(SECRET|PRIVATE|SERVICE_ROLE|STRIPE_SK|OPENAI|ANTHROPIC|SENDGRID|TWILIO)[A-Z0-9_]*"

scan 4 "Supabase service_role referenced (must never be in client code)" 0 "service_role|SERVICE_ROLE"

scan 4 "LLM / secret-API keys referenced from frontend-looking files (check they are not shipped to the browser)" 0 \
  "(OPENAI_API_KEY|ANTHROPIC_API_KEY|STRIPE_SECRET_KEY)" "--include=*.jsx --include=*.tsx --include=*.vue --include=*.svelte"

if [ -d .git ] && command -v git >/dev/null 2>&1; then
  tracked=$(git ls-files 2>/dev/null | grep -E '(^|/)\.env($|\.)' | grep -vE 'example|sample|template')
  [ -n "$tracked" ] && note 4 ".env files tracked by git (rotate anything inside them)" $tracked
  if ! grep -qE '(^|/)\.env' .gitignore 2>/dev/null && ls .env* >/dev/null 2>&1; then
    note 4 ".env files exist but .gitignore does not ignore them" ".gitignore missing a .env rule"
  fi
  hist=$(git log --all --oneline -- '.env' '.env.local' '.env.production' 2>/dev/null | head -5)
  [ -n "$hist" ] && note 4 ".env files appear in git history (secrets may be recoverable; rotate)" $hist
fi

# ---------- 2. Payment webhooks ----------
wh=$(have_files "checkout\.session\.completed|payment_intent\.succeeded|invoice\.paid|stripe.*webhook|webhooks?/(stripe|paddle|lemon)|LemonSqueezy|X-Signature")
if [ -n "$wh" ]; then
  unsigned=""
  while IFS= read -r f; do
    [ -z "$f" ] && continue
    if ! grep -qE "constructEvent|construct_event|verifyHeader|verify_header|stripe-signature|Stripe-Signature|createHmac|hmac\.new|timingSafeEqual|compare_digest|svix|Webhook\(" "$f" 2>/dev/null; then
      unsigned="$unsigned$f"$'\n'
    fi
  done <<< "$wh"
  [ -n "$unsigned" ] && note 2 "Files handling payment events with NO signature verification found" $unsigned
fi

# ---------- 1. File uploads ----------
up=$(have_files "multer|formidable|busboy|multipart/form-data|UploadFile|request\.files|FileField|ImageField|move_uploaded_file|upload\.(single|array|fields)|createPresignedPost|getSignedUrl")
if [ -n "$up" ]; then
  unchecked=""
  while IFS= read -r f; do
    [ -z "$f" ] && continue
    if ! grep -qE "fileSize|maxFileSize|max_size|MAX_UPLOAD|content_length|limits[[:space:]]*:|fileFilter|mimetype|content_type|allowedTypes|ALLOWED|file-type|magic|ContentLengthRange|content-length-range" "$f" 2>/dev/null; then
      unchecked="$unchecked$f"$'\n'
    fi
  done <<< "$up"
  [ -n "$unchecked" ] && note 1 "Upload handlers with no size/type validation found" $unchecked
fi
scan 1 "Uploads written into a public/web-served path" 0 "(public|static|www|wwwroot)/(uploads?|files|images)"

# ---------- 3. XSS ----------
scan 3 "Raw HTML sinks (trace each back to its data source)" 0 \
  "dangerouslySetInnerHTML|\.innerHTML[[:space:]]*[+]?=|\.outerHTML[[:space:]]*=|insertAdjacentHTML|document\.write\(|v-html|bypassSecurityTrust|\|[[:space:]]*safe[[:space:]]*\}\}|autoescape[[:space:]]+off|\{\{\{|<%-|mark_safe|Markup\(|\| *raw"
scan 3 "eval / Function constructor" 0 "[^a-zA-Z_.]eval\(|new Function\("

# ---------- 5/6. Auth inventory ----------
routes=$(have_files "(app|router|api)\.(get|post|put|patch|delete|all)\(|@(app|router|bp|blueprint)\.(route|get|post|put|patch|delete)|export (async )?function (GET|POST|PUT|PATCH|DELETE)|export const (GET|POST|PUT|PATCH|DELETE)|APIRouter|path\(${Q}|createTRPCRouter|server action|${Q}use server${Q}")
if [ -n "$routes" ]; then
  count=$(echo "$routes" | wc -l | tr -d ' ')
  noauth=""
  while IFS= read -r f; do
    [ -z "$f" ] && continue
    if ! grep -qiE "auth|session|getUser|currentUser|requireUser|login_required|permission|jwt|token|verify|clerk|getServerSession|Depends\(" "$f" 2>/dev/null; then
      noauth="$noauth$f"$'\n'
    fi
  done <<< "$routes"
  note "5/6" "Route inventory: $count files define routes. Review every one for auth AND ownership checks" $(echo "$routes" | head -30)
  [ -n "$noauth" ] && note 5 "Route files with no auth-looking code at all (likely unauthenticated)" $noauth
fi
scan 6 "Mass-assignment patterns (request body passed straight into a write)" 0 \
  "(update|create|insert|set|assign|merge)[A-Za-z]*\((req|request)\.(body|json)[,)]|\.\.\.(req|request)\.body|Object\.assign\([^,]+,[[:space:]]*(req|request)\.body|\*\*request\.(json|data|POST)"

# ---------- 7. Database rules ----------
tables=$(grep -rIhEi "${EXCL[@]}" --include=*.sql -e "create table" . 2>/dev/null | wc -l | tr -d ' ')
rls=$(grep -rIhEi "${EXCL[@]}" --include=*.sql -e "enable row level security" . 2>/dev/null | wc -l | tr -d ' ')
if [ "${tables:-0}" -gt 0 ] && [ "${rls:-0}" -lt "${tables:-0}" ]; then
  note 7 "SQL defines $tables tables but only $rls ENABLE ROW LEVEL SECURITY statements (if this is Supabase/PostgREST, some tables are likely open)" "check supabase/migrations and schema files"
fi
scan 7 "Permissive SQL policies" 0 "(using|with check)[[:space:]]*\([[:space:]]*true[[:space:]]*\)" "-i"
scan 7 "Policies trusting user-editable metadata" 0 "user_metadata|raw_user_meta_data" "-i"
scan 7 "Open Firebase / Firestore rules" 0 "allow[[:space:]]+(read|write|read,[[:space:]]*write)[[:space:]]*:[[:space:]]*if[[:space:]]+true|request\.time[[:space:]]*<[[:space:]]*timestamp\.date|\"\.(read|write)\"[[:space:]]*:[[:space:]]*true" "--include=*.rules --include=*.json"

# ---------- 8. Injection ----------
scan 8 "SQL built from strings / unsafe raw query APIs" 0 \
  "(query|execute|exec|raw|queryRaw|executeRaw)\(.*(${BT}[^${BT}]*\\$\{|[+][[:space:]]*(req|request|params|input|body|id))|queryRawUnsafe|executeRawUnsafe|(execute|text)\(f${Q}|\.raw\(f${Q}|\.extra\(|(SELECT|INSERT|UPDATE|DELETE)[^;]{0,80}(%s|%d)[^;]{0,40}%[[:space:]]*\(?[a-z]" "-i"
scan 8 "Shell / command execution (check for user input)" 0 \
  "child_process|execSync\(|[^a-zA-Z_.]exec\(|os\.system\(|subprocess\.[a-z_]+\(.*shell[[:space:]]*=[[:space:]]*True|Runtime\.getRuntime\(\)\.exec|popen\("
scan 8 "File path built from request input (path traversal)" 0 \
  "(readFile|readFileSync|createReadStream|sendFile|send_file|open)\(.*(req|request)\.(query|params|body|args)"
scan 8 "NoSQL queries built directly from request body" 0 "\.(find|findOne|findOneAndUpdate|updateOne|deleteOne|deleteMany)\((req|request)\.(body|query)|\.(find|findOne)\(\{[^}]*(req|request)\.(body|query)"

# ---------- 9. Rate limiting ----------
authy=$(have_files "(login|signin|signup|register|reset[-_]?password|forgot[-_]?password|otp|magic[-_]?link|chat/completions|messages\.create|openai|anthropic)")
rl=$(have_files "rate-?limit|ratelimit|slowapi|flask_limiter|Limiter\(|throttle|Throttle|django_ratelimit|@upstash/ratelimit|express-slow-down|rack-attack")
if [ -n "$authy" ] && [ -z "$rl" ]; then
  note 9 "Auth or paid-API endpoints found but no rate-limiting library or code anywhere in the project" $(echo "$authy" | head -15)
fi

# ---------- 10. Dependencies ----------
deps=""
[ -f package.json ] && deps="$deps\"npm audit --omit=dev\" (and verify any package you do not recognise exists: npm view <name>)"
[ -f requirements.txt ] || [ -f pyproject.toml ] && deps="$deps  \"pip-audit\""
[ -f composer.json ] && deps="$deps  \"composer audit\""
[ -f Gemfile ] && deps="$deps  \"bundle audit\""
[ -f go.mod ] && deps="$deps  \"govulncheck ./...\""
[ -n "$deps" ] && note 10 "Run dependency audits (needs network) and sanity-check unfamiliar package names" "$deps"
if [ -f package.json ] && ! ls package-lock.json yarn.lock pnpm-lock.yaml bun.lockb bun.lock >/dev/null 2>&1; then
  note 10 "No lockfile found for package.json" "commit a lockfile so installs are reproducible"
fi
scan 10 "Wildcard or 'latest' dependency versions" 0 "${Q}(\*|latest)${Q}[[:space:]]*,?[[:space:]]*$" "--include=package.json"

# ---------- 11. Sessions, passwords, CSRF ----------
scan 11 "Weak password hashing (md5/sha1/sha256 near password handling)" 0 \
  "(md5|sha1|sha256)\(.*(pass|pwd)|createHash\(${Q}(md5|sha1|sha256)${Q}\).*(pass|pwd)|hashlib\.(md5|sha1|sha256)\(.*(pass|pwd)" "-i"
scan 11 "Auth tokens kept in localStorage/sessionStorage (stealable via XSS)" 0 \
  "(localStorage|sessionStorage)\.setItem\(${Q}[^${Q}]*(token|jwt|session|auth)[^${Q}]*${Q}" "-i"
scan 11 "JWT signing / verification sites (check expiry, secret strength, alg)" 0 "jwt\.(sign|verify|decode)\(|jsonwebtoken|PyJWT|jwt\.encode\(|algorithms[[:space:]]*=[[:space:]]*\[?${Q}none${Q}"
scan 11 "Predictable token generation" 0 "Math\.random\(\)|random\.random\(\)|uuid1\(" "--include=*.js --include=*.ts --include=*.jsx --include=*.tsx --include=*.py"
scan 11 "Cookies set with weak flags" 0 "httpOnly[[:space:]]*:[[:space:]]*false|secure[[:space:]]*:[[:space:]]*false|SESSION_COOKIE_SECURE[[:space:]]*=[[:space:]]*False|sameSite[[:space:]]*:[[:space:]]*${Q}none${Q}" "-i"

# ---------- 12. CORS & headers ----------
scan 12 "Wildcard or reflected CORS origin" 0 \
  "origin[[:space:]]*:[[:space:]]*(${Q}\*${Q}|true)|Access-Control-Allow-Origin${Q}?[[:space:]]*[:,=][[:space:]]*${Q}?\*|CORS_ALLOW_ALL_ORIGINS[[:space:]]*=[[:space:]]*True|allow_origins[[:space:]]*=[[:space:]]*\[${Q}\*${Q}\]|[^a-zA-Z_]cors\(\)" "-i"
if have_files "require\(${Q}express${Q}\)|from ${Q}express${Q}|import express" | grep -q . && ! have_files "helmet" | grep -q .; then
  note 12 "Express app found with no helmet (security headers) usage" "consider helmet() plus an explicit CSP"
fi
scan 12 "Source maps enabled for production" 0 "productionBrowserSourceMaps[[:space:]]*:[[:space:]]*true|devtool[[:space:]]*:[[:space:]]*${Q}source-map${Q}|sourcemap[[:space:]]*:[[:space:]]*true"

# ---------- 13. Errors & debug ----------
scan 13 "Debug mode / debugger enabled" 0 "DEBUG[[:space:]]*=[[:space:]]*True|app\.run\(.*debug[[:space:]]*=[[:space:]]*True|debug[[:space:]]*:[[:space:]]*true|APP_DEBUG[[:space:]]*=[[:space:]]*true" "-i"
scan 13 "Stack traces or raw error text sent to clients" 0 "(res|response)\.(send|json|status\([0-9]+\)\.(send|json))\([^)]*(err|error|e)\.(stack|message)|traceback\.format_exc\(\).*(return|jsonify|response)"
scan 13 "Sensitive values logged" 0 "(console\.(log|info|debug)|print|logger\.[a-z]+|logging\.[a-z]+)\(.*(password|passwd|token|secret|authorization|api[_-]?key|req\.body|request\.body)" "-i"
scan 13 "GraphQL introspection/playground or API docs possibly exposed" 0 "introspection[[:space:]]*:[[:space:]]*true|playground[[:space:]]*:[[:space:]]*true|swagger-ui|/api-docs|FastAPI\(\)" "-i"

# ---------- 14. Privacy ----------
scan 14 "Whole user objects returned or logged (check for hashes, emails, internal flags)" 0 \
  "(res|response)\.(json|send)\((user|users|account|profile)\)|return[[:space:]]+(jsonify\()?(user|account)\.(__dict__|to_dict)|SELECT[[:space:]]+\*[[:space:]]+FROM[[:space:]]+users" "-i"
scan 14 "Analytics / tracker SDKs (check consent and what data is sent)" 0 "gtag\(|fbq\(|mixpanel|segment\.(track|identify)|posthog|hotjar|amplitude|clarity\.ms" "-i"
scan 14 "Highly sensitive field names stored or handled (SSN/SIN, ID numbers, health, card)" 0 "(ssn|social_security|sin_number|passport|drivers?_license|date_of_birth|dob|medical|diagnosis|card_number|cvv)" "-i --include=*.sql --include=*.prisma --include=schema.* --include=models.py --include=*.model.*"

# ---------- 15. SSRF & redirects ----------
scan 15 "Server-side fetch of a request-supplied URL" 0 "(fetch|axios\.(get|post)|got|requests\.(get|post)|urlopen|http\.get|HttpClient\.[A-Za-z]+)\(.*(req|request)\.(body|query|params|args|json)"
scan 15 "Redirect target taken from request input" 0 "(redirect|Redirect|sendRedirect)\(.*(req|request)\.(query|body|params|args)|(next|returnTo|return_to|redirect_uri|redirectUrl)[[:space:]]*=[[:space:]]*(req|request)\."

echo "# Done. $SECTIONS section(s) with leads."
echo "# Not covered by grep: broken authorization logic, whether flagged inputs are really user-controlled, CSRF, business-logic flaws. Review those by reading the code."
exit 0
