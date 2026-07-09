# AI-001: Unapproved Generative AI Service Usage from Corporate Endpoints

| | |
|---|---|
| **ID** | AI-001 |
| **Severity** | Medium (adjust to your AI usage policy) |
| **Category** | Endpoint / Shadow AI |
| **Platforms** | Microsoft Defender XDR, Microsoft Sentinel |
| **Data source** | `DeviceNetworkEvents` (Defender for Endpoint) |
| **MITRE ATT&CK** | [T1567](https://attack.mitre.org/techniques/T1567/) Exfiltration Over Web Service, [T1071.001](https://attack.mitre.org/techniques/T1071/001/) Web Protocols |
| **Status** | Production-ready, requires approved-list tuning |
| **Version** | 2.0.0 |

## What this detects

Browser-driven connections from corporate endpoints to generative AI services that are **not on the organization's approved list**: ChatGPT, Claude, Gemini, DeepSeek, Perplexity, Grok, Mistral, local model hubs and more than 30 tracked services.

The detection intentionally scopes to browser processes (Chrome, Edge, Firefox, Brave, Opera, Vivaldi, Arc). This captures interactive employee usage, which is where sensitive data gets pasted, while ignoring background SDK traffic, update checks and telemetry that would flood the results. API-based and non-browser AI traffic is covered separately by AI-005.

## Why it matters

Employees adopt AI tools faster than security teams can govern them. Every unapproved AI session is a channel where source code, credentials, customer records or internal documents can leave the organization with:

- No contractual data protection (consumer AI tiers train on user input unless disabled)
- No audit trail of what was shared
- No DLP coverage if the service is not in your sanctioned app catalog
- Direct compliance exposure under GDPR, NIS2 and sector regulations

This is a visibility detection first. In most environments the first 7 days of results become the input for the actual AI usage policy conversation.

## Query files

| File | Use in |
|---|---|
| [`AI-001-unapproved-genai-services.kql`](AI-001-unapproved-genai-services.kql) | Defender XDR Advanced Hunting (uses `Timestamp`) |
| [`AI-001-unapproved-genai-services.yaml`](AI-001-unapproved-genai-services.yaml) | Microsoft Sentinel scheduled analytics rule (uses `TimeGenerated`) |

## Prerequisites

- Microsoft Defender for Endpoint onboarded devices (P1 or P2)
- For Sentinel: Microsoft 365 Defender data connector with `DeviceNetworkEvents` streaming enabled
- `RemoteUrl` population depends on the endpoint seeing SNI or DNS context. Coverage is high for browser traffic

## Deployment

**Defender XDR (Advanced Hunting / Custom Detection):**
1. Paste the `.kql` file into Advanced Hunting
2. Edit `approved_ai_domains` to reflect your sanctioned AI tools
3. Run over `ago(7d)` first to baseline, then save as a Custom Detection rule on a 1h or 3h frequency if you want alerting from Defender directly

**Microsoft Sentinel:**
1. Import the `.yaml` via `Analytics > Import` or deploy through your repository CI/CD
2. Recommended: create a watchlist named `ApprovedAITools` with a `Domain` column and switch the rule to the watchlist variant (commented block inside the query). This lets SOC analysts maintain the approved list without editing the rule

## Tuning guidance

| Situation | Action |
|---|---|
| Copilot, Gemini or another tool is company-approved | Add its domains to `approved_ai_domains` or the `ApprovedAITools` watchlist |
| Grammarly or similar assistants are tolerated but not approved | Move them to a separate lower-severity rule instead of deleting them, they still process document content externally |
| Developer teams generate heavy hits on `huggingface.co` | Scope an exclusion to their device group rather than removing the domain globally |
| Too many single-connection results | Raise the trigger to `ConnectionCount > 5` or alert only on `DistinctServiceCount >= 2` |
| Security team runs AI evaluations | Exclude their analyst device group |

Expected noise level after tuning: low. Before tuning: medium to high, dominated by whatever AI tool your organization already uses unofficially.

## Investigation runbook

1. **Identify the user and volume.** One connection is browsing. Two hundred connections across a workday is active usage.
2. **Check the service category.** A chat assistant (`chatgpt.com`) carries different risk than a hosted inference hub (`huggingface.co`) or a companion AI (`character.ai`).
3. **Correlate with file activity.** Pivot to `DeviceFileEvents` and `DeviceEvents` for the same user in the same window: file uploads, large clipboard operations and browser file-picker events indicate data leaving, not just questions being asked (see AI-004).
4. **Check the user's role and data access.** Usage by someone with access to source code, financial data or customer PII escalates the priority.
5. **Outcome paths.** Confirmed policy violation goes to HR/management per your AUP process. Tool worth sanctioning goes to the AI governance backlog. Benign one-off gets the user added to awareness comms.

## False positives

- Marketing, research or security teams legitimately evaluating AI tools
- Embedded AI features inside sanctioned SaaS (some products call AI provider domains from the browser session)
- Shared kiosk devices where per-user attribution is weak

## Version history

| Version | Date | Change |
|---|---|---|
| 2.0.0 | 2026-07 | Full rewrite: approved-list model, 30+ services, per-service aggregation, Sentinel YAML with entity mapping and alert details, investigation runbook |
| 1.0.0 | 2026-04 | Initial release (`network-ai-usage.kql`) |

---

**Need this deployed and tuned in your environment?** BlueRed Security builds production detection coverage for Microsoft Sentinel and Defender XDR. [Start with a Proof of Value](https://uaeblueredsecurity.com/).
