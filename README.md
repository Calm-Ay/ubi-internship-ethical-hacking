# UBI Internship — Ethical Hacking Track · Stage 0 Capstone

**Author:** Rasaq Ayomide (Calm Ay)
**Programme:** UBI Internship — Ethical Hacking Track
**Stage:** Stage 0 — Foundations: Induction at the Gate
**Profile:** [calm-ay.github.io](https://calm-ay.github.io) · [LinkedIn](https://www.linkedin.com/in/rasaq-ayomide-sec) · [GitHub](https://github.com/Calm-Ay)

---

## Overview

Stage 0 is the foundational capstone of the UBI Ethical Hacking Track. The scenario: a 600-person fintech (Sankofa Digital) has a potential insider-assisted breach. A Tier-1 analyst closed a suspicious SSH login as "probably nothing." The Head of Security, Amaka Eze, disagrees. This report is the deliverable handed to the Sankofa Digital Incident Committee.

**Threat actor identified:** The Griot — named from a decoded Base64 payload in the evidence pack.

**Key finding:** An SSH login from `185.220.101.9` occurred on Jun 4 02:07 UTC under the account of an employee who was on annual leave Jun 3–7. A second session followed Jun 5 03:14 UTC. A post-offboarding account (`a.eze`, offboarded Apr 12) also appeared active in the same log window. Nine automated alerts were generated. All were closed by a single analyst — without peer review, and in one case, by the same person whose account was flagged.

---

## Capstone Deliverables

| # | Document | Description |
|---|----------|-------------|
| D1 | [Suspicious Login Evidence Table](./D1_Suspicious_Login_Evidence_Table.docx) | 10-row evidence table mapping every suspicious event to file, timestamp, and confidence rating |
| D2 | [Tier-1 Dismissal Pattern Analysis](./D2_Tier1_Dismissal_Pattern.docx) | Full analysis of how 9 alerts were closed across SD-40812 through SD-40866 — including the conflict of interest |
| D3 | [Business Impact &amp; Next Steps](./D3_Business_Impact_Next_Steps.docx) | Risk assessment, attacker profile, MITRE ATT&amp;CK mapping, NDPA obligations, and 72-hour action plan |
| D4 | [Judgment Essay](./D4_Judgment_Essay.docx) | Ethics call under ISC2 Code of Ethics + open-ended SIEM alert scenario |

---

## Desk Tasks — Written Answers

### Task: Hash Identification

Four hashes from the Sankofa incident bucket. Algorithm identified by length, charset, and prefix:

| # | Hash (truncated) | Algorithm | Giveaway |
|---|-----------------|-----------|----------|
| 1 | `5d41402abc4b...` (32 chars) | MD5 | 32 hex chars = 128-bit output. No prefix. |
| 2 | `aaf4c61ddcc5...` (40 chars) | SHA-1 | 40 hex chars = 160-bit output per NIST FIPS 180-4 §6.1 |
| 3 | `$2b$12$R9h/cIP...` | bcrypt | `$2b$` version prefix, cost factor `12`, modified Base64 charset |
| 4 | `2c26b46b68ff...` (64 chars) | SHA-256 | 64 hex chars = 256-bit output per NIST FIPS 180-4 §6.2 |

**Rotation urgency (most → least urgent):** MD5 → SHA-1 → SHA-256 → bcrypt.
MD5 is most urgent — precomputed rainbow tables make it effectively already cracked on exposure.

**Near-mistake:** Hash #2 (SHA-1) initially looked like RIPEMD-160 — both produce 40-char hex and 160-bit output with no prefix marker. Context resolved it: RIPEMD-160 appears in cryptocurrency/PGP contexts, not web credential stores. SHA-1 is the dominant legacy choice in fintech auth systems.

**Citation:** NIST FIPS 180-4; OWASP Password Storage Cheat Sheet (bcrypt section).

---

### Task: Ethics — SSO Password on Sticky Note

**Immediate action:** Do nothing visible. Do not read the credential, do not photograph it, do not touch the desk.

**Who and how:** Raise it privately with my direct manager via direct message — not at standup, not in a group channel. One record, one person, contained.

**Helping without shaming:** Frame it as a process gap, not a personal failure. The cultural risk of getting this wrong: if flagging a mistake leads to embarrassment, the next sticky note stays on the desk and never makes it into a ticket. The D2 dismissal pattern in this capstone is partly a product of that culture.

**Canon citations (ISC2 Code of Ethics):**
- **Canon I** — *"Protect society, the common good, necessary public trust and confidence, and the infrastructure."* An exposed SSO credential on a shared floor is a direct infrastructure risk. Inaction is a failure of this obligation.
- **Canon II** — *"Act honorably, honestly, justly, responsibly, and legally."* Acting responsibly means raising the issue through the right channel promptly. Acting justly means doing so fairly — not publicly, not punitively.

---

### Task: Password Policy Critique (v3.1 → v3.2)

Four flaws in Sankofa Digital Password Policy v3.1, benchmarked against NIST SP 800-63B:

**Flaw 1 — Fixed 8-character ceiling (not floor)**
An 8-character cap collapses available keyspace. NIST SP 800-63B §5.1.1.2: verifiers SHALL allow memorized secrets of at least 64 characters.
*Fix:* Minimum 12 characters, maximum at least 64. Passphrases encouraged.

**Flaw 2 — 30-day forced rotation**
NIST SP 800-63B §5.1.1.2: verifiers SHOULD NOT require periodic rotation and SHOULD only force change on evidence of compromise. Forced rotation produces predictable mutations (`Sankofa2025!` → `Sankofa2025!!`).
*Fix:* No mandatory rotation. Force reset only on confirmed or suspected compromise.

**Flaw 3 — Last-3 reuse window is the wrong control**
An artefact of the rotation anti-pattern. NIST SP 800-63B §5.1.1.2 prescribes breach corpus checking instead — compare candidate passwords against known-compromised lists. OWASP ASVS v4.0 Control V2.1.7 reinforces this.
*Fix:* Check new passwords against a breach corpus. Reject matches. Remove history window once rotation is removed.

**Flaw 4 — Verbal confirmation reset is a vishing invitation**
Phone-based identity proofing is trivially defeated by social engineering. NIST SP 800-63B §5.1.3 requires reset via a previously registered authenticator, an out-of-band channel bound to the account, or supervised in-person proofing with government ID.
*Fix:* Resets via time-limited email link to registered address, enrolled MFA authenticator, or in-person ID verification. Verbal/phone confirmation removed.

**Citations:** NIST SP 800-63B §§5.1.1.2, 5.1.3; OWASP ASVS v4.0 Controls V2.1.1, V2.1.7.

---

## Executive Summary

Between 3 and 8 June 2024, an external threat actor known as The Griot used a Sankofa employee's credentials to access the company's gateway server, stage customer and transaction data, and exfiltrate it to an external server. The employee was on annual leave throughout. Nine automated security alerts were generated. All were closed by a single analyst without peer review. The breach went undetected for five days. This report identifies the intrusion chain, documents the dismissal pattern that allowed it to persist, and recommends a mandatory dual-signature policy for all medium and above security ticket closures.

---

*Stage 0 — UBI Ethical Hacking Track · Submitted by Rasaq Ayomide (Calm Ay)*
