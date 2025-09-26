# GHSA Roadmap — A Documentary‑Style, End‑to‑End Guide to Contributing to the GitHub Advisory Database (README‑ready)

[![Made for GHSA](https://img.shields.io/badge/GitHub%20Advisory-Contributor-blue)](https://github.com/advisories)
[![OSV.dev](https://img.shields.io/badge/OSV.dev-Reference-informational)](https://osv.dev)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](#21-license--credits)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](#21-license--credits)

> **Language:** English (for PRs and issues). **Goal:** Take you from zero to an accepted PR improving entries in the **GitHub Advisory Database (GHSA)** with defensible CVSS v4.0/v3.1 scores, primary sources, accurate affected ranges, and crisp, technical narratives.

---

## Table of Contents

- [1. Overview](#1-overview)
- [2. Ethics & Scope](#2-ethics--scope)
- [3. The 10‑Step Workflow](#3-the-10step-workflow)
- [4. Repository Setup & Local Notes](#4-repository-setup--local-notes)
- [5. How to Find Good Targets](#5-how-to-find-good-targets)
- [6. Primary Sources: Evidence Hierarchy](#6-primary-sources-evidence-hierarchy)
- [7. Understand the Vulnerability (CWE, Preconditions, Impact)](#7-understand-the-vulnerability-cwe-preconditions-impact)
- [8. Affected vs. Patched Versions](#8-affected-vs-patched-versions)
- [9. CVSS v4.0 & v3.1 — Calculating Consistently](#9-cvss-v40--v31--calculating-consistently)
- [10. Writing Quality: Titles, Summaries, Tone](#10-writing-quality-titles-summaries-tone)
- [11. Copy‑Paste Templates (EN)](#11-copypaste-templates-en)
- [12. Evidence Pack Checklist](#12-evidence-pack-checklist)
- [13. Opening the PR & Responding to Reviews](#13-opening-the-pr--responding-to-reviews)
- [14. Quality Bar & Common Pitfalls](#14-quality-bar--common-pitfalls)
- [15. Mini‑Patterns by Class (Examples)](#15-minipatterns-by-class-examples)
- [16. Study Resources (Curated Links)](#16-study-resources-curated-links)
- [17. FAQ](#17-faq)
- [18. Final Pre‑PR Checklist](#18-final-prepr-checklist)
- [19. Glossary](#19-glossary)
- [20. Suggested Repo Structure](#20-suggested-repo-structure)
- [21. License & Credits](#21-license--credits)

---

## 1. Overview

Contributing to GHSA means improving the **signal** around vulnerabilities: adding or correcting **CVSS v4.0 and v3.1**, providing **primary sources** (upstream fix commits, release notes), clarifying **affected ranges** based on the **first patched version**, and writing **objective, technical descriptions**. The result: faster, safer decisions by the entire ecosystem.

---

## 2. Ethics & Scope

- **Legality & disclosure:** Respect coordinated disclosure and embargoes. Do not publish dangerous PoCs that violate program rules or the law.
- **Verifiability:** Every claim should be backed by **traceable links**.
- **No speculation:** Prefer upstream evidence over third‑party summaries.

---

## 3. The 10‑Step Workflow

1. **Pick a target** advisory that is incomplete, inconsistent, or outdated.
2. **Collect primary sources** (fix commit, release notes, upstream issue/PR, CVE).
3. **Understand the bug** (class/CWE, preconditions, practical impact).
4. **Map affected vs. patched** (derive ranges from the first fixed release per branch).
5. **Compute CVSS v4.0 & v3.1** (defensible vectors and brief justifications).
6. **Draft a technical description** (overview → attack scenario → impact → versions → refs).
7. **Write the PR “Reason for change”** (clear, neutral, link‑backed).
8. **Assemble the Evidence Pack** (links, minimal excerpts, screenshots if helpful).
9. **Open the PR** with the right files/paths, minimal diff noise.
10. **Address reviews** promptly with further evidence or clarifications.

---

## 4. Repository Setup & Local Notes

- Fork **github/advisory‑database** and **clone** locally.
- Create one **branch per advisory** (e.g., `feat/ghsa-XXXX-cvss-v4-update`).
- Use small, descriptive commits (e.g., `docs(ghsa-XXXX): add fix commit + v4/v3.1 vectors`).
- Keep a local `notes/` directory with links, excerpts, and your scoring rationale.

---

## 5. How to Find Good Targets

Look for advisories that are:

- Missing **CVSS v4.0** (only v3.1 present) or lacking **scoring justifications**.
- Missing **primary sources** (no fix commit, no release notes, no upstream issue).
- Vague or inconsistent **descriptions** vs. NVD/OSV.
- Unclear **affected ranges** (not derived from first patched release).

**Useful places to search:**

- GHSA browser: <https://github.com/advisories>
- GitHub Advisory Database repo: <https://github.com/github/advisory-database>
- OSV: <https://osv.dev>
- NVD: <https://nvd.nist.gov>
- Ecosystem DBs:
  - Rust: <https://github.com/RustSec/advisory-db>
  - Go: <https://github.com/golang/vulndb>
  - PyPI: <https://github.com/pypa/advisory-database>
  - Ruby: <https://github.com/rubysec/ruby-advisory-db>
  - Composer/PHP: <https://github.com/FriendsOfPHP/security-advisories>

---

## 6. Primary Sources: Evidence Hierarchy

Prefer, in order:

1. **Fix commit(s)** (diff shows the precise change that removes the flaw).
2. **Release notes/changelog** explicitly referencing the fix.
3. **Upstream issue/PR** discussing root cause and resolution.
4. **Vendor security advisory** from the project/ecosystem.
5. **CVE/NVD/OSV** entries (good for cross‑checking, but validate upstream first).

Avoid blog posts without upstream references or articles lacking technical detail.

---

## 7. Understand the Vulnerability (CWE, Preconditions, Impact)

- **Class/CWE quick map:**
  - OS Command Injection / RCE → CWE‑78, CWE‑94
  - Prototype Pollution → CWE‑1321, CWE‑915
  - Path Traversal → CWE‑22
  - Regular Expression DoS (ReDoS) → CWE‑1333
  - Insecure Deserialization → CWE‑502
  - XSS → CWE‑79; CSRF → CWE‑352; SSRF → CWE‑918; XXE → CWE‑611
- **Key questions:**
  - Is authentication required? Any user interaction? Network‑reachable?
  - What’s the **real** impact (read/write/execute/disrupt)?
  - Any **scope change** (crossing a boundary: process/container/tenant)?

---

## 8. Affected vs. Patched Versions

- Identify the **first fixed version** per maintained branch from release notes or tags tied to the fix commit.
- Derive affected ranges as **“all versions < fixed”** within each branch respecting SemVer.
- Check for backports (`cherry‑pick`) to stable branches.

---

## 9. CVSS v4.0 & v3.1 — Calculating Consistently

### 9.1 Calculators

- **CVSS v4.0 (FIRST official):** <https://www.first.org/cvss/calculator/4.0>
- **CVSS v3.1 (FIRST):** <https://www.first.org/cvss/calculator/3.1>
- **CVSS v3.1 (NVD):** <https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator>

### 9.2 Five‑Step Process

1. Define the **representative attack case** (worst plausible given the facts).
2. Select **base metrics** (v4.0: AV/AC/AT/PR/UI/VC/VI/VA/SC…; v3.1: AV/AC/PR/UI/S/C/I/A).
3. **Justify each metric** in one line with upstream evidence.
4. Record the **full vector** and **score** for both v4.0 and v3.1.
5. If your score differs from OSV/NVD, explain **why** (scope, preconditions, deployment realities).

### 9.3 Handy Heuristics (Not Rules)

- **Remote Command Injection / RCE:** typically AV:N, AC:L, PR:N, UI:N; high C/I; scope may be **H** if boundary crossing occurs.
- **Prototype Pollution:** impact is contextual; justify based on realistic data/control flow.
- **Path Traversal (read):** confidentiality high if secrets are plausible; integrity/availability vary for write/delete.
- **ReDoS:** availability often high if the vulnerable regex runs on request path without timeouts.

> **Never inflate**. Defensibility beats severity inflation.

---

## 10. Writing Quality: Titles, Summaries, Tone

- **Title examples:**
  - ✅ `PackageName: OS Command Injection via unsanitized <param>`
  - ❌ `Critical bug!!!` or `security issue`
- **Description structure (3–6 concise paragraphs):**
  1. **Overview**: class, where it lives, prerequisites.
  2. **Attack Scenario**: how to trigger; what changes for the attacker.
  3. **Impact**: what the attacker gains/denies in typical deployments.
  4. **Affected/Fixed**: ranges and first patched version(s).
  5. **Mitigations** (if any) and **References** (primary sources first).
- **Tone:** technical, neutral, verifiable.

---

## 11. Copy‑Paste Templates (EN)

### 11.1 PR “Reason for change”

```
Reason for change:
- Add upstream primary sources (fix commit and first patched release).
- Provide precise affected version ranges per release notes and git history.
- Supply CVSS v4.0 and v3.1 vectors with concise, evidence-backed justifications.
- Clarify exploitation prerequisites and realistic impact, avoiding overstatement.
References: <fix-commit>, <release-notes>, <upstream-issue/PR>, <CVE/NVD>, <OSV>.
```

### 11.2 Advisory Description

```
Summary
A vulnerability in <component/module> allows <class, e.g., OS Command Injection> when <condition>. An attacker can <result> under <prerequisites>.

Details
The issue stems from <root cause>. When <trigger>, the code <behavior>. This enables <impact>. The vulnerability affects <ecosystem/package> versions <range>.

Attack Scenario
An unauthenticated/low-privileged attacker can <steps>. No user interaction is required (UI:N), and the attack is feasible over the network (AV:N).

Impact
Successful exploitation may lead to <RCE/data exfiltration/DoS/privilege escalation>. In common deployments, this results in <practical outcome>.

Affected and Patched Versions
Affected: <>= x.y.z and < a.b.c> across maintained branches.
Patched: upgrade to <a.b.c> or later, where commit <hash> applies input validation.

References
- Commit: <url-to-fix-commit>
- Release notes: <url>
- CVE/NVD: <url>
- OSV: <url>
- Upstream issue/PR: <url>
```

### 11.3 CVSS Justifications (concise)

```
CVSS v4.0: AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H (Score: X.Y)
- AV:N: The vulnerable code is reachable over the network without local access.
- AC:L: No special conditions required; default configuration is affected.
- PR:N: No authentication is required to trigger the flaw.
- UI:N: No user interaction is necessary.
- VC:H / VI:H: Successful exploitation discloses/modifies sensitive assets.
- SC:H: The impact crosses a security boundary (process/container/tenant).

CVSS v3.1: AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N (Score: X.Y)
- Mirrors the v4.0 rationale above, mapped to v3.1 semantics.
```

---

## 12. Evidence Pack Checklist

**What to include (must‑haves):**
- **Fix commit permalink** (exact hash) and, if useful, links to the specific lines showing the remediation.
- **Release notes / changelog** that **explicitly** mention the fix and the **first patched version** per maintained branch.
- **Upstream issue/PR** where maintainers discuss **root cause**, **impact**, and **resolution**.
- **CVE / NVD / OSV** entries for cross‑checking (useful, but do not replace upstream evidence).
- **Affected‑range derivation notes:** how you computed `>= x.y.z, < a.b.c` (per branch), plus any **backports/cherry‑picks**.
- **CVSS v4.0 & v3.1**: full vectors, scores, and **one‑line justification per base metric**.
- **Attack prerequisites**: auth required? user interaction? network reachability? deployment assumptions.
- **Scope change rationale** (if any): why `SC:H`/`S:C` (v4/v3.1) is warranted (boundary crossing, tenant/privilege domain).
- **Mitigations / workarounds** stated by upstream (if present) and their limitations.
- **Minimal reproduction/trigger** only if already public/allowed; keep it **safe and non‑destructive**.
- **Screenshots or code excerpts** (when clarifying), always tied to **permalinks**.

**Nice‑to‑haves (situational):**
- **Hashes/signatures** of patched release artifacts (to tie versions to binaries).
- **Downstream advisories** (distros/vendors) that corroborate versions/impact.
- **Migration guidance** (if fix requires config changes or breaking updates).

**Permalink tips:**
1. In GitHub, press `y` on a file view to lock the URL to the commit hash.
2. Use the **“Copy permalink”** option for lines/ranges to anchor evidence precisely.

**Quick git helpers:**
```bash
# Find the introducing or fixing commit quickly
git blame -L <start>,<end> path/to/file
git log --decorate --oneline -- path/to/file
# Show what changed in the fix commit
git show <fix_commit_hash>
```

---

## 13. Opening the PR & Responding to Reviews

- **Correct file paths** and schema per the advisory database guidelines.
- **PR title:** `GHSA-XXXX: clarify impact, primary sources, affected ranges, and CVSS v4/v3.1`.
- **PR body:** include your Reason for change, vectors, and links to sources.
- **Minimal diff:** avoid cosmetic reformatting.
- **CI:** ensure valid JSON/YAML; run repository linters/scripts if present.

**During review:**

- Provide **permalink hashes** to the exact fix lines.
- If diverging from NVD/OSV, explain in 1–2 paragraphs with upstream evidence.

---

## 14. Quality Bar & Common Pitfalls

- ❌ No **primary source** → high chance of rejection.
- ❌ **Inflated CVSS** without facts → adjust to the representative scenario.
- ❌ **Vague ranges** → derive from the **first patched** release and branches.
- ❌ Mixing **build‑time** vs **runtime** impacts.
- ❌ Bundling multiple issues into a single advisory.

---

## 15. Mini‑Patterns by Class (Examples)

**A) OS Command Injection (server‑side)**

- Title: `PackageX: OS Command Injection via unsanitized 'name' parameter`
- CVSS v4.0 (typical): `AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H`
- Key refs: fix commit switching to `execFile` + strict validation; release `v1.4.2`.

**B) Regular Expression DoS (ReDoS)**

- Title: `PackageY: Regular Expression Denial of Service (ReDoS) in URL parser`
- CVSS v4.0 (typical): `AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:S`
- Key refs: commit adding timeouts and input caps; release `v3.2.1`.

**C) Prototype Pollution**

- Title: `PackageZ: Prototype Pollution via merge() without key validation`
- CVSS v4.0: context‑dependent; justify based on realistic data/control flow chains.

**D) Path Traversal**

- Title: `PackageW: Path Traversal via unsanitized file path`
- Consider confidentiality (secret reads) vs. integrity/availability for writes.

---

## 16. Study Resources (Curated Links)

**Vulnerabilities & Hands‑on**

- PortSwigger Web Security Academy — <https://portswigger.net/web-security>
- Hacker101 (HackerOne) — <https://www.hacker101.com/>
- OWASP Top 10 (2021) — <https://owasp.org/Top10/>
- MITRE CWE Catalog — <https://cwe.mitre.org/>

**CVSS**

- FIRST CVSS v4.0 Calculator — <https://www.first.org/cvss/calculator/4.0>
- FIRST CVSS v3.1 Calculator — <https://www.first.org/cvss/calculator/3.1>
- NVD v3.1 Calculator — <https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator>

**Ecosystem & Data**

- OSV — <https://osv.dev>
- NVD — <https://nvd.nist.gov>
- SemVer — <https://semver.org/>

**Git & Reproducibility**

- Git — <https://git-scm.com/>
- Atlassian Git Tutorials — <https://www.atlassian.com/git/tutorials>

**Advisory Repos**

- GitHub Advisory Database — <https://github.com/github/advisory-database>
- RustSec — <https://github.com/RustSec/advisory-db>
- Go vulndb — <https://github.com/golang/vulndb>
- PyPA advisory‑database — <https://github.com/pypa/advisory-database>
- RubySec — <https://github.com/rubysec/ruby-advisory-db>
- FriendsOfPHP/security‑advisories — <https://github.com/FriendsOfPHP/security-advisories>

---

## 17. FAQ

**Do I always provide both v4.0 and v3.1?** Yes, if the schema supports both, include both vectors and scores.

**What if OSV/NVD disagrees with my vector?** Explain with upstream facts and practical deployment assumptions. Consistency > copying.

**No clear release notes?** Use the **fix commit** and tags; correlate with branch history and backports.

**Include PoC?** Only if already public/accepted by upstream. Avoid dangerous payloads in PRs.

---

## 18. Final Pre‑PR Checklist

- [ ] **Precise title**: `<Package>: <Class> via <vector/condition>` (no hype words).
- [ ] **Narrative complete**: Overview → Attack Scenario → Impact → Affected/Fixed → References.
- [ ] **Primary sources linked**: fix commit (permalink), release notes/changelog, upstream issue/PR; CVE/OSV for cross‑check.
- [ ] **Affected ranges derived** from the **first patched release** per maintained branch; backports documented.
- [ ] **CVSS provided**: v4.0 **and** v3.1 vectors + scores with one‑line metric justifications.
- [ ] **CWE(s) identified**; **prerequisites** (auth/UI/network) and **scope change** stated if applicable.
- [ ] **Severity consistent** with vectors and text; no overstatement.
- [ ] **Evidence Pack ready** in `notes/` (sources, cvss.md, ranges.md, screenshots if used).
- [ ] **Schema & paths valid** for the advisory database; CI **green** locally and on PR.
- [ ] **Minimal diff** (no cosmetic reformatting); repository style honored.
- [ ] **References use permalinks** (commit hashes, tagged releases), not moving branches.
- [ ] **Trigger/repro (if included)** is already public, safe, and lawful.
- [ ] **PR body includes** the Reason for change, vectors, scores, and links to sources.
- [ ] **Cross‑checked vs NVD/OSV**; any discrepancy **explained succinctly** with upstream evidence.
- [ ] **Project policies satisfied** (DCO/CLA/issue linking, if required).

---

## 19. Glossary

- **Advisory:** Public record describing a vulnerability.
- **CVE:** Standardized identifier for a vulnerability (MITRE/NIST ecosystem).
- **CWE:** Taxonomy of software weaknesses (root causes).
- **OSV:** Vulnerability database keyed by ecosystem/package/version.
- **CVSS:** Severity metric system (v4.0 and v3.1 in practice today).
- **Primary source:** Upstream artifacts (fix commit, release notes, issue/PR).

---

## 20. Suggested Repo Structure

```
.
├─ README.md                 # you are here
├─ /templates
│   ├─ PR-reason-for-change.md
│   ├─ advisory-description.md
│   └─ cvss-justifications.md
├─ /guides
│   ├─ scoring-cvss.md
│   ├─ deriving-affected-ranges.md
│   └─ evidence-pack.md
└─ /notes (example usage)
    └─ ghsa-<id>/
        ├─ sources.md
        ├─ cvss.md
        ├─ ranges.md
        └─ screenshots/
```

---

## 21. License & Credits

Consider licensing this repository under **MIT** or **CC BY 4.0** so others can reuse templates with attribution. Credits welcome via PRs. Happy contributing! 🚀

