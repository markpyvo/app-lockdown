---
name: app-lockdown
description: Security audit and auto-fix for web apps, especially AI-generated ("vibe coded") ones. Scans a project for 15 of the most common ways apps get hacked (insecure file uploads, unverified payment webhooks, XSS, leaked API keys, missing auth, broken authorization, open database rules, injection, no rate limiting, vulnerable or fake dependencies, weak sessions and passwords, CORS and security headers, debug and error leaks, privacy exposure, SSRF and open redirects), writes a severity-ranked report with file and line references, then fixes each issue one diff at a time and re-scans to confirm. Use this whenever the user says things like "check my app for security issues", "is my app secure", "audit my code", "lock down my app", "security review", "before I launch or ship this", "did the AI leave holes in this", or asks to harden, pentest, or find vulnerabilities in a codebase, even if they never say "app-lockdown".
---

# App Lockdown

AI coding tools are very good at making an app work and very bad at making it safe. Ask one to "make it secure" and it will usually move an API key into a `.env` file and stop there, while the upload endpoint accepts anything, the payment webhook trusts whoever calls it, and user comments render as raw HTML. This skill exists to close that gap: audit the whole app against the failure modes that actually get apps breached, report them plainly, and fix them with the user's approval.

The user may not be a security person. Explain findings in plain English first ("anyone can fake a payment"), technical detail second.

## Ground rules

These exist because a security tool that is careless is worse than none.

- **Static review of the user's own code only.** Don't send requests to live sites, attempt exploitation, or probe third-party systems. Reading code, config, and schema is the whole job.
- **Never print a full secret.** When you find a key, show the file, the line, and at most the first 4 characters. Reports get shared and pasted into chats; a report that contains the live key becomes the leak.
- **Never change code before showing the diff and getting approval.** Security fixes can break login flows and payments, and the user needs to see what's changing. If the user says "apply the rest", do that, but they have to say it.
- **Smallest idiomatic fix.** Use the framework's own mechanism first (built-in escaping, built-in CSRF, the ORM's parameter binding). Add a library only when the stack has no good native option, and say you're adding it.
- **Removing a leaked secret from code does not un-leak it.** Anyone who could see the repo or the browser bundle may already have it. Always tell the user which keys to rotate and where. You can't rotate them yourself.
- **Never claim the app is "secure".** Say what was checked, what was found, what was fixed, and what wasn't covered. A clean scan means "none of these 15 were found", not "unhackable".
- **Don't commit or push** unless the user asks.
- **Never write real secret values to any file.** New environment variables go in `.env.example` with placeholders.

## Workflow

### 1. Orient

Find the project root (use the path the user gave, otherwise the current directory; if it holds several apps, ask which one). Detect the stack from manifests (`package.json`, `requirements.txt`, `pyproject.toml`, `composer.json`, `Gemfile`, `go.mod`) and note the services in play: Supabase, Firebase, Stripe, Clerk, NextAuth, S3, an LLM provider. One line to the user is enough: "Next.js + Supabase + Stripe, scanning now."

Create a task list covering the steps below so progress is visible.

### 2. Quick scan

Run the bundled first-pass scanner. It is a fast grep sweep that produces leads, not verdicts.

```bash
bash <path-to-this-skill>/scripts/quick_scan.sh <project-root>
```

`<path-to-this-skill>` is the folder containing this SKILL.md. Secret hits come back as `file:line` only, by design.

### 3. Deep review

Read the matching sections of `references/checks.md` for each check (it has an index at the top; load the sections relevant to this stack rather than all fifteen if context is tight). For every check:

1. Open the files the scanner flagged.
2. Open the entry points the scanner can't judge on its own: route handlers, API routes, server actions, middleware, auth config, database schema and policies, upload handlers, webhook handlers, `next.config`/server setup.
3. Confirm or dismiss each lead. Grep finds patterns; only reading the code tells you whether user input actually reaches the dangerous call.
4. Record the result as a finding, "reviewed, no issue", or "not applicable" (for example, no payments in this app). Never skip a check silently, because the user needs to know it was looked at.

For auth and authorization (checks 5 and 6), build a route inventory: every endpoint, its method, whether it requires a session, and what data it reads or writes. Holes show up when you can see all the routes side by side.

Some things look like secrets but are meant to be public: Supabase anon keys, Firebase web config, Stripe publishable keys (`pk_`). Don't flag those as leaks. Do check whether the rules behind them are open (check 7).

### 4. Report

Write `LOCKDOWN_REPORT.md` in the project root using `references/report-template.md`. The report contains a map of the app's weaknesses, so tell the user to keep it out of git and offer to add it to `.gitignore`.

Then summarize in chat: counts by severity, the top three to five findings in plain English, and ask whether to start fixing. Keep the chat summary short; the details live in the report.

### 5. Fix, one diff at a time

Work from Critical down to Low. For each finding:

1. One plain-English line on what's wrong and what an attacker could do.
2. The diff (unified format, only the lines that change).
3. Ask: apply, skip, or change it.
4. On approval, apply it. When it's cheap, run whatever the project already has (typecheck, lint, build, tests) and report failures honestly rather than moving on.

Group tiny mechanical fixes of the same kind (for example, adding the same missing header block) into one diff so the user isn't asked twenty times.

Some fixes can't be done in code. Collect these as **Manual steps** with exact instructions: rotate a leaked key in the provider's dashboard, paste the webhook signing secret into the host's env settings, enable row-level security in the Supabase dashboard, turn on provider spend limits. Don't bury them; for leaked secrets and open databases they are the actual fix.

### 6. Verify

Re-run `quick_scan.sh` and re-read each fixed location. Update `LOCKDOWN_REPORT.md` so every finding is marked Fixed, Skipped, or Needs manual action. Finish with a short summary: before and after counts, the manual steps still open, and what this audit did not cover (anything dynamic, infrastructure, anything outside the repo).

## The 15 checks

Details, detection signals, and fix patterns for each are in `references/checks.md`.

| # | Check | The attack in one line |
|---|-------|------------------------|
| 1 | File upload validation | Upload a script or oversized file that runs on or floods the server |
| 2 | Payment webhook verification | Forge a "payment succeeded" message and get the product free |
| 3 | XSS protection | Plant script in a comment or username that runs in every viewer's browser |
| 4 | Exposed API keys and secrets | Read keys from the browser bundle, repo, or git history |
| 5 | Missing authentication | Call endpoints that never ask who you are |
| 6 | Broken authorization (IDOR) | Change an ID or a field to read or edit someone else's data |
| 7 | Open database rules | Query the database directly because row-level rules are off |
| 8 | SQL, NoSQL and command injection | Turn input into queries or shell commands |
| 9 | No rate limiting | Brute-force logins or run up a bill on paid endpoints |
| 10 | Vulnerable or fake dependencies | Ride a known CVE or a hallucinated, typosquatted package |
| 11 | Weak sessions, passwords and CSRF | Steal or forge sessions, crack weakly hashed passwords |
| 12 | CORS and security headers | Abuse wildcard origins, clickjacking, missing browser protections |
| 13 | Verbose errors and debug mode | Learn internals from stack traces, or use a debug console as a backdoor |
| 14 | Privacy and data exposure | Over-collected or over-returned personal data turns a bug into a breach |
| 15 | SSRF and open redirects | Make the server fetch internal URLs, or bounce users to a phishing page |

## Severity

- **Critical:** an anonymous attacker can exploit it now with major impact. Examples: forgeable payments, upload leading to code execution, live secret keys exposed, database readable without login, auth bypass.
- **High:** exploitable by any signed-up user, or with one small precondition. Examples: IDOR, stored XSS, injection behind login, unlimited calls to a paid AI endpoint.
- **Medium:** weakens defenses or needs unusual conditions. Examples: no CSP, weak session settings, verbose errors, vulnerable dependency with no reachable path.
- **Low:** hygiene and hardening.

When unsure between two levels, choose the higher one and say why. A user can downgrade a finding; they can't act on one you quietly understated.

## Edge cases

- **Unknown stack or language:** the checks are about behavior, not frameworks. Read the code for the same questions and say which parts the scanner couldn't help with.
- **Large repos:** prioritize the entry points (routes, handlers, auth, schema, webhooks, uploads) over exhaustive file-by-file reads, and state the scope in the report.
- **Not a git repo, or no history access:** skip the history check in check 4 and say so.
- **Secret already committed:** the fix is rotate first, then clean the code, and only then optionally scrub history. Never suggest rewriting history before rotation.
- **Findings in generated or vendored code** (build output, `node_modules`): ignore, but report if the *source* that generates it is the problem.
- **User wants only some checks:** run only those, and list the others as "not run".
