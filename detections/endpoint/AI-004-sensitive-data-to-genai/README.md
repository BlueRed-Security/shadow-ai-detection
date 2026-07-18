# AI-004: Sensitive Data Uploaded to Generative AI Services

| | |
|---|---|
| **ID** | AI-004 |
| **Severity** | High (data leaves the organization on upload) |
| **Category** | Endpoint / Shadow AI (data exfiltration) |
| **Platforms** | Microsoft Defender XDR, Microsoft Sentinel |
| **Data sources** | `CloudAppEvents` (primary); `DeviceNetworkEvents` + `DeviceFileEvents` (endpoint fallback) |
| **MITRE ATT&CK** | [T1567](https://attack.mitre.org/techniques/T1567/) Exfiltration Over Web Service |
| **Status** | Production-ready with Defender for Cloud Apps or DLP; degraded without it |
| **Version** | 1.0.0 |

## What this detects

Files uploaded from corporate identities into generative AI services. AI-001 answers "who is talking to AI." AI-004 answers the harder and higher-severity question: **who is sending files to AI.** A pasted paragraph is a policy conversation. A whole contract, database export or source tree uploaded into a consumer AI tier is a data-loss event with no DLP coverage and no contractual protection.

The primary query reads `CloudAppEvents` (Microsoft Defender for Cloud Apps), filtering upload actions to a list of GenAI applications and returning one row per user with every file they sent, upload volume and source IPs.

## Telemetry note (read before deploying)

Raw endpoint network tables cannot measure upload volume or file content. This detection therefore needs one of:

- **Microsoft Defender for Cloud Apps** populating `CloudAppEvents` with file upload actions and the destination app. This is the primary query.
- **Microsoft Purview Endpoint DLP**, or a **CASB/proxy** doing DLP on GenAI domains, as an equivalent source of egress-with-destination.

Without any of these, use the **endpoint fallback** (commented block in the `.kql`). It correlates a GenAI browser session with sensitive-file access by the same user in a short window. It does not confirm an upload, it infers staging, so it is lower confidence and needs tighter tuning.

This mirrors the reality every detection engineer hits here: confirming data-into-AI requires content-aware telemetry, not just netflow.

## Query files

| File | Use in |
|---|---|
| [`AI-004-sensitive-data-to-genai.kql`](AI-004-sensitive-data-to-genai.kql) | Defender XDR Advanced Hunting (uses `Timestamp`), primary + fallback |
| [`AI-004-sensitive-data-to-genai.yaml`](AI-004-sensitive-data-to-genai.yaml) | Microsoft Sentinel scheduled analytics rule (uses `TimeGenerated`) |

## Prerequisites

- Microsoft Defender for Cloud Apps connected and streaming `CloudAppEvents`
- For Sentinel: Microsoft 365 Defender data connector with `CloudAppEvents` streaming enabled
- For the fallback only: Defender for Endpoint with `DeviceNetworkEvents` and `DeviceFileEvents`

## Discovery query (run this first)

Upload `ActionType` strings and GenAI app names differ per tenant depending on which apps are sanctioned versus discovered. Before deploying, find what your tenant actually emits:

```kusto
CloudAppEvents
| where Timestamp > ago(7d)
| where ActionType has_any ("Upload", "FileUploaded", "Put", "Attachment")
| summarize Count = count() by Application, ActionType
| order by Count desc
```

Align `genai_apps` and `upload_actions` in the rule to the real values you see. Add any GenAI app that appears under a name not already in the list.

## Deployment

**Defender XDR (Advanced Hunting / Custom Detection):**
1. Run the discovery query, then the primary query over `ago(7d)` to baseline
2. Save as a Custom Detection on a 1h to 4h frequency

**Microsoft Sentinel:**
1. Import the `.yaml` via `Analytics > Import`
2. Incidents group by Account: one incident per user accumulating their uploads

## Tuning guidance

| Situation | Action |
|---|---|
| Microsoft Copilot is sanctioned with commercial data protection | Remove "Copilot" / "Microsoft Copilot" from `genai_apps`, or exclude it explicitly |
| A GenAI tool is approved for a specific team | Exclude that team's `AccountObjectId` set or device group, keep the rule global |
| High volume of tiny/benign uploads | Alert only when `DistinctFileCount >= 2` or filter `Files` to sensitive extensions |
| App shows only by URL, not by name | The `RawEventData has_any (genai_domains)` clause covers this; extend `genai_domains` if needed |
| Fallback fires on any file touch near a chat session | Narrow `sensitive_ext`, shorten the correlation window, or scope to high-value device groups |

Expected noise level after tuning: low. This is a high-severity rule by design; keep the threshold tight so every alert is worth an analyst's time.

## Investigation runbook

1. **Confirm it was an upload, not a download.** In `CloudAppEvents`, verify the `ActionType` is an upload/put, not a read. The fallback query cannot confirm this, so treat fallback hits as leads.
2. **Identify the files.** File names in the `Files` set that look like exports, dumps, backups or documents (`.sql`, `.csv`, `.xlsx`, `.pst`, `.zip`, `.pdf`) are the priority. Correlate with Purview sensitivity labels if you have them.
3. **Check the destination tier.** A consumer/free AI tier trains on input by default. An enterprise tier with a signed DPA is a different risk posture. Confirm which was used.
4. **Check the user's data access.** Pivot the user in `CloudAppEvents` and `DeviceFileEvents`: large reads from network shares, SharePoint/OneDrive or repo clones just before the upload indicate data was staged, not incidental.
5. **Correlate with AI-001 and AI-003.** Active GenAI sessions (AI-001) and an installed AI extension (AI-003) plus a file upload is a full data-exposure picture for that user.
6. **Outcome paths.** Confirmed sensitive-data upload to a consumer tier goes to your data-incident / DLP process and, if warranted, HR. Approved-tool usage becomes an exclusion. Repeated uploads by one user become an awareness and access-review action.

## False positives

- Approved GenAI tools with signed data-protection terms not yet excluded
- Enterprise Copilot or sanctioned assistants counted as GenAI uploads
- Fallback correlation firing on unrelated file activity near a chat session
- Automated or SDK uploads from sanctioned integrations (scope by account type)

## Version history

| Version | Date | Change |
|---|---|---|
| 1.0.0 | 2026-07 | Initial release: CloudAppEvents upload detection to GenAI apps, discovery query for per-tenant alignment, documented endpoint correlation fallback, Sentinel YAML with account-grouped incidents, investigation runbook |

---

**Need this deployed and tuned in your environment?** BlueRed Security builds production detection coverage for Microsoft Sentinel and Defender XDR. [Start with a Proof of Value](https://uaeblueredsecurity.com/).
