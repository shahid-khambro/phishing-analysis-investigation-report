# Threat Intelligence Report: Sextortion Scam Email Analysis

**Report ID:** TIR-2026-001  
**Analyst:** Shahid ali  
**Date:** 2026-05-14  
**Last Updated:** 2026-06-10 (OSINT enrichment added)   
**Severity:** Medium (Social Engineering / Financial Fraud)

---

## 1. Executive Summary

This report documents the analysis of a sextortion extortion email received on **May 14, 2026**, purportedly from the threat actor group **"ShinyHunters."** The email attempts to coerce the recipient into paying **$2,000 USD in Bitcoin** by falsely claiming that compromising videos were recorded via malware installed on the victim's device.

Technical analysis of email headers, infrastructure, OSINT enrichment across multiple threat intelligence platforms, and content analysis confirms this is a **mass-distributed social engineering scam** with no evidence of actual device compromise. The email leverages psychological manipulation, brand impersonation of a known threat actor, and urgency tactics.

**Key Finding:** No actual compromise occurred. This is a bluff-based extortion campaign using a recycled template, routed through infrastructure belonging to **KDDI Corporation** — a legitimate Japanese ISP — indicating a compromised or abused mail relay.

---

## 2. Threat Actor Attribution

| Attribute | Value |
|-----------|-------|
| Claimed Identity | ShinyHunters hacking group |
| Likely Actor | Unknown — mass campaign operator |
| Attribution Confidence | Low — name likely borrowed for credibility |
| Motivation | Financial (cryptocurrency extortion) |
| Sophistication | Low |

**Note on ShinyHunters:** ShinyHunters is a real, known threat actor group responsible for several high-profile database breaches (e.g., Tokopedia, Wattpad, Mashable). Their name is abused in scam emails to instill fear. There is **no credible evidence** this email originates from the actual ShinyHunters group. Real APT groups do not operate mass sextortion campaigns.

---

## 3. Email Header Analysis

### 3.1 Raw Header Summary

```
From:    "You've been HACKED" <zkldg@re.commufa.jp>
To:      you <you>
Subject: Information about your online security
Date:    Thu, 14 May 2026 11:39:28 -0700
MsgID:   <28e5ac07f3371d1300aae510d4117fbd8b3d@re.commufa.jp>
```

### 3.2 Sending Infrastructure

| Field | Value | Notes |
|-------|-------|-------|
| Sending MTA | `mta-sp-e03.commufa.jp` | Japanese ISP (Commufa / KDDI) |
| Sending IP | `106.153.250.13` | Osaka, Japan — KDDI Corporation |
| Return-Path | `zkldg@re.commufa.jp` | Random-looking local part — likely compromised/abused account |
| Originating Host | `xrdanqum` | Internal hostname — suspicious, random string pattern |

### 3.3 Authentication Results

| Protocol | Result | Implication |
|----------|--------|-------------|
| **DKIM** | `pass` | Message not tampered in transit — only proves origin domain, not legitimacy |
| **SPF** | `pass` | Sending IP `106.153.250.13` is authorized for `re.commufa.jp` |
| **DMARC** | `pass (p=QUARANTINE)` | Domain policy is quarantine — all checks passed |

**Critical Observation:** All three authentication mechanisms passed. This does **not** mean the email is legitimate — it means the attacker either controls or has compromised a mail account on `commufa.jp` (a legitimate Japanese ISP). Passing SPF/DKIM/DMARC is **not a trust indicator** for content legitimacy. It only validates the sending path.

### 3.4 Routing Path

```
[Attacker / Compromised Account on commufa.jp]
        ↓
xrdanqum  (origin host — random string hostname, suspicious)
        ↓
mta-or-e03.commufa.jp  (outbound relay — Osaka, Japan — KDDI/AS2516)
        ↓
mta-sp-e03.commufa.jp  (sending MTA — 106.153.250.13 — KDDI/AS2516)
        ↓
mx.google.com  (Gmail MX — delivered to khambrotech@gmail.com)
```

**Timezone Consistency Check:**
- Email sent: `Thu, 14 May 2026 11:39:28 -0700 (PDT)` → UTC 18:39:28
- Commufa relay: `Fri, 15 May 2026 03:39:44 +0900 (JST)` → UTC 18:39:44
- Delta: 16 seconds (normal relay processing time). **No timestamp anomalies detected.**

---

## 4. OSINT Enrichment — IP: 106.153.250.13

Three threat intelligence platforms were queried for the sending IP address. Results are summarized below.

### 4.1 AbuseIPDB

| Field | Value |
|-------|-------|
| **Status** | Found in database |
| **Abuse Reports** | 27 reports submitted |
| **Confidence of Abuse** | 23% |
| **ISP** | KDDI Corporation |
| **Usage Type** | Fixed Line ISP |
| **ASN** | AS2516 |
| **Hostname** | `mta-sp-e03.commufa.jp` |
| **Domain** | `kddi.com` |
| **Country** | Japan |
| **City** | Osaka, Osaka |

**Analyst Note:** The 23% abuse confidence score and 27 prior reports confirm this IP has a known abuse history, consistent with a compromised mail relay being used for spam/scam campaigns. The IP is registered to KDDI Corporation (Japan's second-largest telco), meaning this is not attacker-owned infrastructure — it is **borrowed/abused legitimate infrastructure**.

### 4.2 MXToolbox / Sender Reputation

| Field | Value |
|-------|-------|
| **Location** | Shinagawa, Japan |
| **FWD/REV DNS Match** | **No** (mismatch — red flag) |
| **Hostname** | `mta-sp-e03.commufa.jp` |
| **Domain** | `commufa.jp` |
| **Network Owner** | KDDI Corporation |
| **Sender IP Reputation** | **Poor** |
| **Web Reputation** | Neutral |
| **Email Volume (Last Day)** | 4.1 |
| **Email Volume (Last Month)** | 4.0 |
| **Volume Change** | +13.51% ↑ |

**Block List Status:**

| Blocklist | Status |
|-----------|--------|
| BL.SPAMCOP.NET | Not Listed |
| CBL.ABUSEAT.ORG | Not Listed |
| PBL.SPAMHAUS.ORG | Not Listed |
| SBL.SPAMHAUS.ORG | Not Listed |

**Analyst Note:** The **"Poor" sender IP reputation** and **FWD/REV DNS mismatch** are significant red flags. Legitimate mail servers have matching forward and reverse DNS. The mismatch here indicates this IP is not primarily configured as a legitimate outbound mailer, supporting the compromised relay hypothesis. The slight uptick in email volume (+13.51%) may indicate an ongoing campaign. Clean blocklist status means this IP has not yet been widely listed, which would explain how it bypassed spam filters.

### 4.3 VirusTotal / WHOIS

| Field | Value |
|-------|-------|
| **Network** | 106.128.0.0/10 |
| **ASN** | AS2516 |
| **ASN Label** | KDDI CORPORATION |
| **Regional Internet Registry** | APNIC |
| **Country** | Japan (JP) |
| **Continent** | Asia (AS) |
| **WHOIS inetnum** | 106.128.0.0 – 106.191.255.255 |
| **Registered** | KDDI Corporation, Garden Air Tower, Iidabashi, Chiyoda-ku, Tokyo |
| **Abuse Contact** | abuse@dion.ne.jp |
| **Last Modified** | 2024-04-17 |

### 4.4 Domain OSINT — commufa.jp

| Field | Value |
|-------|-------|
| **VirusTotal Detections** | 0 / 48 engines |
| **Domain Age** | Not recent (established domain) |
| **Domain Category** | Unknown |
| **Website Popularity** | Low |
| **Server IP** | `219.117.35.237` |
| **Reverse DNS** | `www.commufa.jp` |
| **ISP** | Chubu Telecommunications Co. Inc. |
| **ASN** | AS18126 |
| **Country** | Japan |
| **Region** | Aichi (Nisshin city) |

**Analyst Note:** Commufa.jp is a legitimate regional ISP in Japan (subsidiary of KDDI), serving Chubu region residential and business customers. Zero detections across 48 VirusTotal engines confirm the domain itself is not malicious — the attacker is **abusing a legitimate ISP's infrastructure**, not operating their own. This is a classic tactic to inherit trust from reputable infrastructure.

### 4.5 OSINT Summary & Enriched Assessment

| Platform | Key Finding | Threat Signal |
|----------|-------------|---------------|
| AbuseIPDB | 27 reports, 23% abuse confidence | Medium |
| MXToolbox | Poor sender reputation, FWD/REV DNS mismatch | High |
| VirusTotal | 0/48 domain detections, KDDI-owned range | Low (legitimate infra) |
| Domain Check | Legitimate ISP, low popularity | Confirms abuse scenario |

**Consolidated Assessment:** The sending infrastructure belongs entirely to legitimate Japanese ISP (KDDI/Commufa). The attacker has **compromised or abused a mail account** on this infrastructure to send scam email. The IP has prior abuse reports and poor sender reputation, but remains off major blocklists — explaining successful delivery to Gmail inbox.

---

## 5. Payload Analysis

### 5.1 Encoding

The email body was encoded in **Base64** (`Content-Transfer-Encoding: base64`). This is commonly used in scam emails to:
- Evade simple keyword-based spam filters
- Obfuscate content from casual inspection of raw headers

Decoded content is **plain text** — no malicious attachments, executable code, tracking pixels, or embedded URLs present.

### 5.2 Social Engineering Techniques Identified

| Technique | Description | MITRE ATT&CK Ref |
|-----------|-------------|-----------------|
| **Fear Appeal** | Claims to hold compromising footage | T1566 |
| **False Authority** | Impersonates ShinyHunters threat group | T1656 |
| **Artificial Urgency** | 48-hour countdown timer | T1566.001 |
| **Isolation Tactic** | Instructs victim not to contact police or anyone | Social Engineering |
| **False Specificity** | Claims access via "Cargurus.com database" | Credibility building |
| **Sunk Cost Framing** | "Everything is stored on remote servers" — makes device reset seem futile | Manipulation |
| **Implied Omniscience** | "We will see your payment immediately" | False technical authority |

### 5.3 Extortion Demand

| Attribute | Value |
|-----------|-------|
| Amount | $2,000 USD equivalent |
| Currency | Bitcoin (BTC) |
| Wallet Address | `bc1qv2cjz69066atfumx054qyf5er72gxv9zt2ytaw` |
| Wallet Format | Bech32 (native SegWit, `bc1q` prefix) |
| Deadline | 48 hours from email open |

### 5.4 Bitcoin Wallet OSINT

The wallet `bc1qv2cjz69066atfumx054qyf5er72gxv9zt2ytaw` should be queried against:

- [Blockchain.com Explorer](https://www.blockchain.com/explorer) — transaction history
- [BitcoinAbuse.com](https://www.bitcoinabuse.com) — community abuse reports
- [ScamAlert.io](https://scamalert.io)

**Analyst Note:** Sextortion campaigns frequently rotate wallet addresses per campaign batch or per individual email to complicate blockchain tracing. The claim that "the wallet is generated specifically for you" is a social engineering tactic designed to make victims feel individually monitored and tracked.

---

## 6. Technical Indicators of Compromise (IOCs)

### 6.1 Network IOCs

| Type | Value | Source | Enrichment |
|------|-------|--------|------------|
| IPv4 | `106.153.250.13` | Email headers | AbuseIPDB: 27 reports, 23% abuse; Poor sender reputation; KDDI/AS2516; Osaka, Japan |
| IPv4 | `219.117.35.237` | commufa.jp DNS | Website server IP; Chubu Telecom / AS18126; Nisshin, Aichi, Japan |
| Domain | `re.commufa.jp` | Email headers | Sender domain — legitimate KDDI/Commufa subdomain |
| Domain | `commufa.jp` | OSINT | 0/48 VT detections; legitimate Japanese ISP |
| Domain | `mta-sp-e03.commufa.jp` | Email headers | Sending MTA hostname |
| Domain | `mta-or-e03.commufa.jp` | Email headers | Relay MTA hostname |
| Email | `zkldg@re.commufa.jp` | Email headers | Sender address — random local-part, likely compromised |

### 6.2 Cryptocurrency IOCs

| Type | Value | Notes |
|------|-------|-------|
| BTC Wallet | `bc1qv2cjz69066atfumx054qyf5er72gxv9zt2ytaw` | Bech32/SegWit format — check BitcoinAbuse.com |

### 6.3 Email IOCs

| Type | Value |
|------|-------|
| Message-ID | `28e5ac07f3371d1300aae510d4117fbd8b3d@re.commufa.jp` |
| Subject | `Information about your online security` |
| From Display Name | `You've been HACKED` |
| DKIM Selector | `default-1th84yt82rvi` |

### 6.4 ASN / Infrastructure

| Type | Value | Notes |
|------|-------|-------|
| ASN | AS2516 | KDDI Corporation — legitimate Japanese telco |
| ASN | AS18126 | Chubu Telecommunications Co. Inc. |
| Network Block | `106.128.0.0/10` | KDDI allocated range (APNIC) |
| Abuse Contact | `abuse@dion.ne.jp` | KDDI abuse reporting |

---

## 7. MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|--------|-----------|-----|---------|
| Reconnaissance | Gather Victim Identity Information | T1589 | Claims access to Cargurus account |
| Resource Development | Compromise Accounts | T1586 | Abused KDDI/Commufa mail account |
| Initial Access | Phishing | T1566 | Mass-distributed extortion email |
| Defense Evasion | Obfuscated Files or Information (Base64) | T1027 | Body encoded in Base64 |
| Defense Evasion | Impersonation | T1656 | Impersonates ShinyHunters group |
| Impact | Financial Theft (Extortion) | T1657 | $2,000 BTC demand |

---

## 8. Why This Is a Bluff — Technical Breakdown

The following evidence confirms no actual compromise occurred:

1. **No proof of compromise provided.** Legitimate attackers with actual footage provide a sample as proof (screenshot, video thumbnail, partial password). None was provided here.

2. **Generic, unverifiable claims.** "Cargurus.com database" breach claim is vague and designed to resonate with a broad audience. No specific account details, timestamps, or data samples were included.

3. **Recycled template language.** Phrases like "We will not share your videos... there is no reason to continue causing problems" appear word-for-word in thousands of documented sextortion templates circulating since at least 2018. This is a copy-paste campaign.

4. **Zero personalization.** No real password, no actual screenshot, no precise dates — all hallmarks of a bluff. Credential-based sextortion (a more advanced variant) includes a real leaked password to establish credibility. This email has none.

5. **Compromised legitimate ISP infrastructure.** Using `re.commufa.jp` (KDDI residential ISP) rather than any infrastructure plausibly linked to ShinyHunters. OSINT confirms this IP has prior abuse reports, consistent with a hijacked relay.

6. **Poor sender IP reputation confirmed by OSINT.** MXToolbox rates the sending IP as "Poor" reputation with a FWD/REV DNS mismatch — not consistent with a sophisticated threat actor operating their own infrastructure.

7. **Authentication pass ≠ content legitimacy.** DKIM/SPF/DMARC all passed — but this only validates the sending path through Commufa's servers, not the truth of any claims in the email body.

8. **"Do not contact police" is a deflection tactic.** This instruction exists purely to prevent the victim from getting advice that would immediately reveal the scam. Legitimate threats do not need to preemptively block law enforcement reporting.

---

## 9. Victim Guidance

If you or someone you know receives this email:

- **Do not pay.** Payment funds future campaigns and marks you as a compliant target for repeat extortion.
- **Do not reply** to the sender email.
- **Report the email:**
  - Internet Crime Complaint Center (IC3): [ic3.gov](https://www.ic3.gov)
  - FTC: [reportfraud.ftc.gov](https://reportfraud.ftc.gov)
  - Your national cybercrime authority
  - [BitcoinAbuse.com](https://www.bitcoinabuse.com) — report the BTC wallet
- **Report the sending IP to the ISP:** abuse@dion.ne.jp (KDDI abuse contact)
- **Mark as phishing** in your email client (Gmail → three dots → Report Phishing)
- **Run a standard AV/malware scan** for peace of mind — no actual infection is indicated.
- **Change passwords** on important accounts as general hygiene.

---

## 10. Defensive Recommendations

| Control Layer | Recommendation |
|---------------|---------------|
| **Email Gateway** | Tune spam filters for sextortion keywords + Base64-only body emails from residential ISP ranges |
| **DMARC Monitoring** | Enable DMARC aggregate reporting (rua) — even passing emails can reveal abuse patterns |
| **Threat Intel** | Ingest IOCs (IP `106.153.250.13`, wallet, Message-ID) into MISP or OpenCTI |
| **User Awareness** | Train employees to recognize urgency/shame-based social engineering; run phishing simulations |
| **Incident Response** | Build a sextortion runbook — most victims are too embarrassed to report; a clear process reduces dwell time |
| **Detection Rule** | Alert on: `Base64 body encoding` + `Bitcoin wallet regex` (`bc1q[a-z0-9]{39}`) in email body |
| **ISP Abuse Reporting** | Report to `abuse@dion.ne.jp` to assist in identifying/removing the compromised relay account |

---

## 11. Conclusion

This email is a **low-sophistication, high-volume sextortion campaign** with zero evidence of actual device compromise. OSINT enrichment across AbuseIPDB, MXToolbox, and VirusTotal confirms the sending infrastructure is a **legitimate Japanese ISP (KDDI Corporation)** being abused as a mail relay — with 27 prior abuse reports and a confirmed poor sender reputation, consistent with an ongoing spam operation.

The attacker relies entirely on psychological manipulation — fear, shame, and urgency — rather than any genuine technical capability. The impersonation of ShinyHunters is an attempt to borrow credibility from a known threat actor name.

No payment should be made. The appropriate response is to report, document, and discard.

---

## 12. Tools Used in This Analysis

| Tool | Purpose | URL |
|------|---------|-----|
| AbuseIPDB | IP abuse history and confidence scoring | https://www.abuseipdb.com |
| MXToolbox | Sender reputation, DNS analysis, blocklist check | https://mxtoolbox.com |
| VirusTotal | Domain/IP multi-engine analysis + WHOIS | https://www.virustotal.com |
| APNIC WHOIS | IP ownership and network registration | https://search.apnic.net |
| Google Admin Toolbox | Email header analysis | https://toolbox.googleapps.com |
| BitcoinAbuse.com | Cryptocurrency wallet abuse lookup | https://www.bitcoinabuse.com |

---

## 13. References

- MITRE ATT&CK Framework: https://attack.mitre.org
- FBI IC3 Sextortion Advisory: https://www.ic3.gov
- ShinyHunters Group Profile: various threat intelligence vendors
- Bitcoin Abuse Database: https://www.bitcoinabuse.com
- FTC Sextortion Guidance: https://consumer.ftc.gov/articles/what-know-about-sextortion
- KDDI Abuse Contact: abuse@dion.ne.jp

---

*Report prepared for SOC Analyst Portfolio — educational and professional development purposes.*  
*All IOCs are real and sourced directly from the analyzed email sample and OSINT enrichment.*
