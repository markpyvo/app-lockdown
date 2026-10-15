# Report template

Write the report to `LOCKDOWN_REPORT.md` in the project root, using this structure. Keep findings concrete: file, line, what's wrong, what an attacker gets. Use plain English first.

````markdown
# App Lockdown Report

**Project:** <name or path>
**Date:** <YYYY-MM-DD>
**Stack detected:** <e.g. Next.js 14, Supabase, Stripe, OpenAI API>
**Scope:** <what was reviewed; note anything skipped such as large generated folders>

> This file lists weaknesses in the app. Keep it out of git and don't share it publicly. This is a static code review, not a penetration test, and it does not prove the app is secure.

## Summary

| Severity | Found | Fixed | Skipped | Needs manual action |
|----------|-------|-------|---------|---------------------|
| Critical | 0 | 0 | 0 | 0 |
| High     | 0 | 0 | 0 | 0 |
| Medium   | 0 | 0 | 0 | 0 |
| Low      | 0 | 0 | 0 | 0 |

**Checks:** <N> of 15 run. Not run / not applicable: <list, with the reason>

## Findings

### [LOCK-001] <short title>: Critical
- **Check:** <number and name, e.g. 2. Payment webhook verification>
- **Where:** `<path>:<line>` (list each location)
- **What's wrong:** <plain English, one or two sentences>
- **What an attacker can do:** <one sentence, concrete>
- **Fix:** <what the change does, in one or two sentences>
- **Status:** Open | Fixed | Skipped | Needs manual action

(repeat per finding, ordered Critical to Low)

## Manual steps

Things the code change can't do on its own. Numbered, with exact instructions.

1. **Rotate <provider> key** that appeared at `<path>:<line>` (first 4 chars: `sk-a…`). Dashboard: <where>. Then update the value in <where it's set>.
2. ...

## Reviewed, no issue

Checks or areas that were examined and are fine, one line each. This tells the user what was actually looked at.

## Not covered

What this audit can't see: runtime behavior, infrastructure and cloud configuration, third-party service settings, anything outside the repo, social engineering. Suggest a professional penetration test before handling sensitive data at scale.
````

## Notes for filling it in

- Number findings `LOCK-001`, `LOCK-002`, … so the user can refer to them ("skip LOCK-004").
- Partial secrets only: never more than the first 4 characters.
- After fixing, update each Status and the summary table; leave the original description intact so the report still reads as an audit trail.
- If there are no findings for a check, it goes under "Reviewed, no issue", not omitted.
