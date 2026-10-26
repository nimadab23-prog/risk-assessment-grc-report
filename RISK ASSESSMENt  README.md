# Vulnerability Risk Assessment & Compliance Mapping

A governance focused companion to my two hands on security labs: [Metasploitable2 Exploitation Lab](https://github.com/nimadab23-prog/metasploitable2-pentest-lab) and [DVWA Web Application Security Lab](https://github.com/nimadab23-prog/dvwa-security-lab). Those two projects answer "can I find and exploit a vulnerability." This one asks a different question: if these findings showed up in a real organization, how would a risk and compliance function actually handle them.

I'm treating the six findings from both labs as if they came out of a real internal penetration test, then doing what a GRC analyst does with that output: rate the risk, map each one to a recognized control framework, and turn it into a remediation plan with priorities, not just a list of what worked.

**This is a self directed learning project using intentionally vulnerable lab environments, not an assessment of a real organization.**

## Why this report exists

Technical pentesting answers "is this exploitable." Governance, risk, and compliance work answers "how much does this matter to the business, who owns fixing it, and how do we stop it happening again across the whole organization, not just this one box." Both are real skills and they're not the same one. This report is me practicing the second, using findings I generated myself rather than a textbook case study.

## Methodology

For each finding I assigned:

- **Likelihood** (Low / Medium / High), based on how easy the exploit was to run and how exposed that kind of service typically is in the real world
- **Impact** (Low / Medium / High), based on what an attacker actually gains: data exposure, system control, service disruption
- **Risk rating** = Likelihood x Impact, using the matrix below
- **Control mapping**, using NIST Cybersecurity Framework (CSF) 2.0 and ISO/IEC 27001:2022 Annex A

These ratings are my own qualitative judgment for this exercise, not a calculated probability or a measured business loss. A real assessment would also weigh the specific assets involved, existing controls, network exposure, and the organization's own risk acceptance criteria.

### Risk matrix

| | Impact: Low | Impact: Medium | Impact: High |
|---|---|---|---|
| **Likelihood: Low** | Low | Low | Medium |
| **Likelihood: Medium** | Low | Medium | High |
| **Likelihood: High** | Medium | High | Critical |

---

## Risk Register

| # | Finding | Source | Likelihood | Impact | Risk Rating |
|---|---|---|---|---|---|
| 1 | vsftpd 2.3.4 backdoor (root access) | Metasploitable2 | High | High | Critical |
| 2 | Java RMI insecure deserialization (root access) | Metasploitable2 | High | High | Critical |
| 3 | SQL injection + weak admin credential | DVWA | High | High | Critical |
| 4 | OS command injection | DVWA | High | High | Critical |
| 5 | Stored XSS | DVWA | Medium | Medium | Medium |
| 6 | Samba usermap_script (configuration unconfirmed) | Metasploitable2 | Medium | High | High |

---

## Detailed Findings & Control Mapping

### 1. vsftpd 2.3.4 Backdoor
**Risk rating: Critical**

A compromised software package gave unauthenticated root access with no barrier at all. This is about as severe as a single finding gets.

**Business impact:** Complete loss of confidentiality, integrity, and availability for the host. Data exfiltration, lateral movement, or outright destruction all become possible.

**Mapped controls:**
- NIST CSF 2.0: **GV.SC** (Cybersecurity Supply Chain Risk Management), verifying software integrity before deployment would have caught a tampered package
- ISO 27001:2022 Annex A: **A.5.21** (managing information security in the ICT supply chain), **A.8.8** (management of technical vulnerabilities), **A.8.9** (configuration management)

**Remediation:** Verify package integrity via checksums or signatures before installing anything, patch to a current supported version, and treat an unexpected open port (like the backdoor's port 6200) as a compromise indicator to monitor for.

**Priority:** Immediate.

---

### 2. Java RMI Insecure Deserialization
**Risk rating: Critical**

The RMI registry accepted and ran a remotely supplied object with no validation, again resulting in unauthenticated root access.

**Business impact:** Same severity class as finding 1: full compromise of the host and anything reachable from it.

**Mapped controls:**
- NIST CSF 2.0: **PR.AA** (Identity Management, Authentication, and Access Control), the service should never accept unauthenticated remote class loading in the first place
- NIST CSF 2.0: **PR.IR** (Technology Infrastructure Resilience), unnecessary services shouldn't be exposed on the network
- ISO 27001:2022 Annex A: **A.8.20** (network security), **A.8.22** (segregation of networks)

**Remediation:** Firewall the service away from untrusted networks, disable it entirely if unused, and apply class filtering protections where the platform supports them.

**Priority:** Immediate.

---

### 3. SQL Injection + Weak Admin Credential
**Risk rating: Critical**

User input went straight into a database query with no sanitization, which let me pull the entire user table including password hashes. One hash turned out to belong to the literal word "password", a separate credential hygiene failure sitting right on top of the first one.

**Business impact:** Direct exposure of all user data and credentials.

**Mapped controls:**
- NIST CSF 2.0: **PR.DS** (Data Security) and **PR.PS** (Platform Security), input is a trust boundary and needs to be treated as one
- ISO 27001:2022 Annex A: **A.8.26** (application security requirements), **A.8.28** (secure coding), **A.5.17** (authentication information, covering the weak credential specifically)

**Remediation:** Use parameterized queries or prepared statements, never build SQL from concatenated user input, and enforce a credential policy that rejects common or breached passwords, especially for privileged accounts.

**Priority:** Immediate.

---

### 4. OS Command Injection
**Risk rating: Critical**

User input went straight into a shell command with no validation, letting me run arbitrary commands on the host as the web server's own service account.

**Business impact:** Full remote code execution capability. Even though the compromised account was low privilege in my lab, that's still a foothold for pivoting, escalating, or reaching whatever data that account can touch.

**Mapped controls:**
- NIST CSF 2.0: **PR.PS** (Platform Security), this is fundamentally an insecure coding pattern
- ISO 27001:2022 Annex A: **A.8.28** (secure coding), **A.8.2** (privileged access rights, relevant to limiting what the service account itself can do)

**Remediation:** Never build shell commands from raw user input. Validate against a strict allowlist (confirm it's actually a well formed IP address, for example) before use, and run the web service under an account with the minimum privileges it actually needs.

**Priority:** Immediate.

---

### 5. Stored XSS
**Risk rating: Medium**

A persistent script injection in a guestbook field runs for every future visitor, not just whoever submitted it. Lower severity than the findings above since it doesn't grant direct system access, but it's a commonly exploited vector for session hijacking and credential phishing in production systems.

**Business impact:** Potential session token theft or convincing phishing delivered through a trusted domain. Damage is typically per user rather than full system compromise, which is why this sits at Medium rather than Critical.

**Mapped controls:**
- NIST CSF 2.0: **PR.PS** (Platform Security), **PR.DS** (Data Security, relevant to session integrity)
- ISO 27001:2022 Annex A: **A.8.26** (application security requirements), **A.8.28** (secure coding)

**Remediation:** Encode or sanitize input on the way in, encode output again on the way out, and never render raw user supplied HTML back to other visitors.

**Priority:** Address in the current remediation cycle.

---

### 6. Samba usermap_script
**Risk rating: High, configuration unconfirmed**

My exploit attempt failed due to a legacy cipher compatibility issue on my attacker machine's modern OpenSSL config, not because the vulnerability was disproven. I also couldn't independently confirm the vulnerable `username map script` setting was actually enabled on the target, the scan only confirmed the service was present, not its exact configuration.

**Business impact:** If the vulnerable configuration is present, this is another command injection path with the same severity as finding 4. Rated High instead of Critical specifically because of that unresolved uncertainty.

**Mapped controls:**
- NIST CSF 2.0: **ID.RA** (Risk Assessment), this finding is a good example of why a risk register needs a status for "unconfirmed," not just pass or fail
- ISO 27001:2022 Annex A: **A.8.8** (management of technical vulnerabilities), **A.8.9** (configuration management)

**Remediation:** Verify whether the configuration is actually enabled before closing or escalating this finding. If confirmed, fix it and reassess; if not, document the evidence that justifies closing it. Keep Samba patched either way.

**Priority:** Verify promptly, then route to Immediate or close based on what's found.

---

## Remediation Roadmap

| Priority | Timeframe | Findings |
|---|---|---|
| Immediate | 0 to 7 days | vsftpd backdoor, Java RMI, SQL injection, command injection |
| High | Prompt verification, then act | Samba usermap_script |
| Medium | Current remediation cycle | Stored XSS |

## Key Observations

Every finding across both labs traces back to one of two root causes: **untrusted input reaching a sensitive operation** (SQL injection, XSS, command injection), or **an unverified or unmaintained software and configuration baseline** (vsftpd backdoor, Java RMI exposure). That's a useful pattern to notice, since it means two focused organizational improvements, secure input handling standards and a maintained vulnerability/configuration baseline, would have prevented most of what showed up here, rather than needing six unrelated fixes.

## Limitations

This is a self directed learning exercise mapping real lab findings to real frameworks, not a report delivered to an actual client or employer. The two source labs were deliberately vulnerable practice environments, not production systems, and the risk ratings are my own qualitative judgment rather than measured business impact. The framework mappings reflect current NIST CSF 2.0 and ISO 27001:2022 structures as of this writing and are a reasonable starting point for discussion, not a certified compliance audit. The Samba finding in particular stays unresolved: a failed exploit attempt doesn't by itself prove a vulnerability is absent.

## Frameworks referenced
- [NIST Cybersecurity Framework (CSF) 2.0](https://www.nist.gov/cyberframework)
- [ISO/IEC 27001:2022, Information Security Management Systems](https://www.iso.org/standard/27001)
