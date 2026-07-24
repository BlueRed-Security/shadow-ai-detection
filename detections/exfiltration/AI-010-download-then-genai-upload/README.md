# AI-010: Bulk Data Download Followed by Generative AI Upload

| | |
|---|---|
| **ID** | AI-010 |
| **Severity** | High (this is a correlated exfiltration sequence, not a single-event signal) |
| **Category** | Exfiltration / Shadow AI |
| **Platforms** | Microsoft Defender XDR, Microsoft Sentinel |
| **Data source** | `CloudAppEvents` (Microsoft Defender for Cloud Apps) |
| **MITRE ATT&CK** | [T1567](https://attack.mitre.org/techniques/T1567/) Exfiltration Over Web Service, [T1074](https://attack.mitre.org/techniques/T1074/) Data Staged, [T1213](https://attack.mitre.org/techniques/T1213/) Data from Information Repositories |
| **Status** | Production-ready, requires threshold tuning |
| **Version** | 1.0.0 |

## What this detects

The exfiltration **chain**, not a single event. A user pulls a batch of files from a corporate repository (SharePoint, OneDrive, Box, Dropbox, Google Drive, a code host, Confluence) and then, within a short correlation window, uploads to a generative AI service. The rule joins the two halves on the same identity and only fires when a bulk download burst is followed by an AI upload.

## Why it matters

Either half of this sequence is unremarkable on its own. People download files all day, and people use AI all day. The value is in the order and the proximity: a burst of collection, then a push to a consumer AI tier, by the same person, in the same window. That is the shape of data being staged and moved out, and it is far higher confidence than any single upload event.

This is the deliberate counterpart to AI-004. AI-004 answers "did someone upload a file to AI" and is a good visibility rule with inevitable noise. AI-010 answers the harder and more serious question, "did someone gather a batch of corporate data and then move it into AI", and by requiring both conditions it produces a short, high-value alert stream you can actually work.

## Query files

| File | Use in |
|---|---|
| [`AI-010-download-then-genai-upload.kql`](AI-010-download-then-genai-upload.kql) | Defender XDR Advanced Hunting (uses `Timestamp`) |
| [`AI-010-download-then-genai-upload.yaml`](AI-010-download-then-genai-upload.yaml) | Microsoft Sentinel scheduled analytics rule (uses `TimeGenerated`) |

## Prerequisites

- Microsoft Defender for Cloud Apps streaming `CloudAppEvents`, with both download and upload actions populated for your connected apps
- The GenAI destination visible to Defender for Cloud Apps (as a connected or discovered app); this is the same dependency as AI-004
- The Sentinel rule uses `queryPeriod: 4h` so a single scheduled run can see a download burst and the upload that follows it

## Discovery query (run first)

Confirm the actual ActionType strings for downloads and uploads in your tenant, since they vary by connected and discovered app:

```kusto
CloudAppEvents
| where TimeGenerated > ago(7d)
| where ActionType has_any ("Download","Upload","FileDownloaded","FileUploaded","Sync","Get","Put")
| summarize Events = count() by ActionType, Application
| order by Events desc
```

Align `download_actions`, `upload_actions`, `source_apps` and `genai_apps` with what appears here before you rely on the rule.

## Deployment

**Defender XDR (Advanced Hunting / Custom Detection):**
1. Paste the `.kql`, run over `ago(7d)` to baseline
2. Set `min_download_count` above normal per-user download bursts in your org
3. Save as a Custom Detection on a 1h schedule

**Microsoft Sentinel:** import the `.yaml`; incidents group by Account so one user's sequence stays in one incident.

## Tuning parameters

| Parameter | Meaning | Guidance |
|---|---|---|
| `min_download_count` | Files pulled that count as "bulk" | Start at 15; raise in orgs where large legitimate downloads are common |
| `correlation_window` | How long after the download burst an AI upload still correlates | 2h default; shorten to tighten to deliberate sequences, lengthen to catch slower actors |
| `lookback` | Total window each run examines | Keep aligned with the Sentinel `queryPeriod` (4h) |

## Tuning guidance

| Situation | Action |
|---|---|
| Sync clients generate large download counts | Exclude sync ActionTypes (`FileSyncDownloaded`) from `download_actions`, keep interactive downloads |
| A migration or backup job pulls files in bulk | Exclude that service account; it is not an AI-upload actor anyway |
| Sanctioned AI tool is the upload destination | If enterprise AI with a DPA is approved, remove it from `genai_apps`; keep consumer tiers in scope |
| Developers clone repos constantly | Consider dropping code hosts from `source_apps`, or raise `min_download_count` for that group |
| Too many hits, mostly benign | Tighten `correlation_window` and confirm file overlap in triage before escalating |

Expected noise level after tuning: low. The two-condition join is what keeps this rule quiet while staying meaningful.

## Investigation runbook

1. **Confirm the file overlap.** The strongest confirmation is that the files in `UploadedFiles` match (or plausibly derive from) `DownloadedFiles`. Overlap turns correlation into evidence.
2. **Measure the tightness.** `MinutesFromBulkToUpload` near zero suggests a deliberate, possibly scripted, gather-and-push. Hours apart is weaker and may be coincidental.
3. **Assess the source sensitivity.** Where the files came from matters: a customer-data site or a source repository is a different exposure from a personal OneDrive of drafts.
4. **Identify the AI destination and tier.** A consumer ChatGPT account is unmanaged exfiltration. An enterprise AI resource with a DPA is a policy question, not necessarily an incident.
5. **Check the user context.** Correlate with HR or leaver status, unusual hours, and travel. Bulk collection then AI upload by a departing employee is a classic insider-exfiltration pattern.
6. **Pivot for the wider picture.** Combine with AI-004 (single uploads), AI-005 (API traffic) and AI-009 (Azure OpenAI volume) to see whether this is one event or part of sustained movement.
7. **Outcome paths.** Benign bulk work with a sanctioned destination is tuned out by approving the destination or the service account. An unsanctioned consumer-AI upload of sensitive source data escalates to a data-loss investigation, with the user's session and the AI app access reviewed.

## False positives

- Sync clients or backup/migration jobs generating high download counts (exclude by ActionType or account)
- Users legitimately moving their own non-sensitive files into a sanctioned AI tool (approve the destination)
- Coincidental timing where downloaded and uploaded files do not overlap (the file-overlap check resolves these)
- Bulk downloads followed by an unrelated upload to an app that merely resolves through an AI provider CDN (verify the destination)

## Coverage limitation

The rule depends on Defender for Cloud Apps seeing both sides. If the AI upload happens over a channel MDA does not observe (a raw API call, a local model, a browser extension moving data client-side), the upload half is invisible here and belongs to AI-005, AI-002 or AI-003 respectively. AI-010 is the cloud-app correlation; pair it with the endpoint and API rules for full exfiltration coverage.

## Version history

| Version | Date | Change |
|---|---|---|
| 1.0.0 | 2026-07 | Initial release: two-condition download-burst-then-AI-upload correlation, tunable download threshold and correlation window, source-repository and GenAI destination lists aligned with AI-004, file-overlap confirmation step, insider-exfiltration investigation path, cross-links to AI-002/003/004/005/009 |

---

**Need this deployed and tuned in your environment?** BlueRed Security builds production detection coverage for Microsoft Sentinel and Defender XDR. [Start with a Proof of Value](https://uaeblueredsecurity.com/).
