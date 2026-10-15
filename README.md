# app-lockdown

**Your AI built the app. This makes sure it can't be hacked in an afternoon.**

![license](https://img.shields.io/badge/license-MIT-green) ![type](https://img.shields.io/badge/Claude-skill-orange) ![checks](https://img.shields.io/badge/checks-15-blue) ![cost](https://img.shields.io/badge/price-free-brightgreen)

A Claude skill that audits your app for the 15 most common ways apps get hacked, hands you a plain-English report, and fixes each issue with a diff you approve.

AI tools are great at building apps and bad at securing them. Tell one to "make it secure" and it usually moves your API key into a `.env` file and calls it done, while the upload endpoint takes any file, the payment webhook trusts anyone, and user comments render as raw HTML. This skill goes after the stuff that actually gets apps breached.

## 60 second start

```bash
git clone https://github.com/markpyvo/app-lockdown ~/.claude/skills/app-lockdown
```

Then open Claude in your project and say:

> Run app-lockdown on this project

That's it. You get a report, then fixes one diff at a time.

Not using Claude Code? See [Install](#install) for the Claude app.

## What it does

1. **Scans** your project: a fast pattern sweep, then Claude reads the code that matters (routes, auth, schema, webhooks, uploads).
2. **Reports** what it found in `LOCKDOWN_REPORT.md`, ranked Critical to Low, with file and line numbers and plain-English explanations.
3. **Fixes** each issue one diff at a time. Nothing changes until you approve it.
4. **Re-scans** to confirm the fixes held, and lists any manual steps (like rotating a key) that code can't do for you.

## What a finding looks like

```
### [LOCK-002] Stripe webhook accepts anyone: Critical
- Check:   2. Payment webhook verification
- Where:   app/api/stripe/webhook/route.ts:14
- What's wrong:  The endpoint marks orders as paid without checking
                 the request really came from Stripe.
- What an attacker can do:  Send a fake "payment succeeded" request
                 and get your product for free.
- Fix:     Verify the Stripe signature before touching the order.
- Status:  Open
```

Plain English first, technical detail second. You don't need to be a security person.

## The 15 checks

| # | Check | The attack |
|---|-------|-----------|
| 1 | **File upload validation** | Upload a script or huge file that runs on, or floods, your server |
| 2 | **Payment webhook verification** | Fake a "payment succeeded" message and get your product free |
| 3 | **XSS protection** | Plant code in a comment or username that runs in every viewer's browser and steals logins |
| 4 | **Exposed API keys and secrets** | Pull keys from the browser bundle, the repo, or git history |
| 5 | **Missing authentication** | Hit endpoints that never ask who you are |
| 6 | **Broken authorization (IDOR)** | Change an ID in the URL to read or edit someone else's data |
| 7 | **Open database rules** | Query Supabase or Firebase directly because row-level rules are off |
| 8 | **SQL, NoSQL and command injection** | Turn user input into queries or shell commands |
| 9 | **No rate limiting** | Brute-force logins or run up your AI bill |
| 10 | **Vulnerable or fake dependencies** | Ride a known CVE, or a package name an AI hallucinated and an attacker registered |
| 11 | **Weak sessions, passwords and CSRF** | Steal or forge sessions, crack badly hashed passwords |
| 12 | **CORS and security headers** | Wildcard origins, clickjacking, missing browser protections |
| 13 | **Verbose errors and debug mode** | Read your internals from stack traces, or use a debug console as a backdoor |
| 14 | **Privacy and data exposure** | Over-collected, over-returned personal data turns a bug into a breach |
| 15 | **SSRF and open redirects** | Make your server fetch internal URLs, or bounce users to a phishing page |

Each check has detection signals and fix patterns in [`references/checks.md`](references/checks.md).

## Install

**Claude Code**

```bash
git clone https://github.com/markpyvo/app-lockdown ~/.claude/skills/app-lockdown
```

**Claude.ai / Claude app**

Download this repo as a ZIP (green **Code** button, then **Download ZIP**), then upload it as a custom skill in Claude's skills settings.

## Use it

Open Claude in your project and say something like:

- "Run app-lockdown on this project"
- "Is my app secure? Check it before I launch."
- "Audit this codebase for security holes and fix them."

It works on any stack. The quick-scan script has the sharpest patterns for JavaScript/TypeScript, Python, and PHP apps, and Supabase/Firebase backends, and Claude reviews the rest by reading the code.

## How fixing works

- You see a diff for every change and choose **apply**, **skip**, or **change it**. If you say "apply the rest", it will.
- Fixes use your framework's built-in tools first and only add a library when there's no good native option.
- Secrets in the report are always redacted (first 4 characters at most), and the skill never writes real secret values anywhere.
- It never commits or pushes for you.

## FAQ

**Does it send my code anywhere?**
No extra services. It runs inside your own Claude session and reads files locally. The quick-scan script is plain `grep`.

**Will it attack my live site?**
No. It only reads your code, config, and schema. It never sends requests to your deployed app or anyone else's.

**Do I need to know security?**
No. Findings are written in plain English with the exact file and line.

**Is it safe to let it edit my code?**
Every change is shown as a diff and waits for your approval. It never commits or pushes.

**Should I commit `LOCKDOWN_REPORT.md`?**
No. It lists your app's weaknesses. Keep it out of git and don't post it publicly.

## What's in the repo

```
app-lockdown/
├── SKILL.md                      # the workflow Claude follows
├── scripts/quick_scan.sh         # fast first-pass scanner (grep based)
└── references/
    ├── checks.md                 # all 15 checks: signals and fixes
    └── report-template.md        # format of LOCKDOWN_REPORT.md
```

You can run the scanner on its own:

```bash
bash scripts/quick_scan.sh /path/to/your/project
```

It prints leads, not verdicts. Secret matches show `file:line` only.

## Limits (read this)

- This is **static code review**, not a penetration test. It reads your code and config; it doesn't attack your running app.
- A clean report means none of these 15 issues were found. It does not mean the app is unhackable.
- It can't see your cloud setup, third-party dashboards, or anything outside the repo.
- If a secret was ever exposed, **rotate it**. Deleting it from code doesn't un-leak it. The skill tells you exactly which ones.
- The privacy check flags exposure; it isn't legal advice.
- If you handle payments at scale, health data, or other regulated data, get a professional security review too.

## Contributing

Found a pattern the scanner misses, or a false positive that wastes your time? Open an issue or a PR. New checks should explain the attack, the signals that reveal it, and a concrete fix.

## License

MIT. See [LICENSE](LICENSE).

Made by Mark ([@markpyvovarov](https://instagram.com/markpyvovarov)).
