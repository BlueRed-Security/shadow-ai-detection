# AI-006: OAuth Consent Granted to Unsanctioned AI Applications

| | |
|---|---|
| **ID** | AI-006 |
| **Severity** | Medium (raise to High for admin consent or sensitive Graph scopes) |
| **Category** | Identity / Shadow AI |
| **Platforms** | Microsoft Defender XDR, Microsoft Sentinel |
| **Data source** | `AuditLogs` (Entra ID) for Sentinel, `CloudAppEvents` for Defender XDR |
| **MITRE ATT&CK** | [T1528](https://attack.mitre.org/techniques/T1528/) Steal Application Access Token, [T1098](https://attack.mitre.org/techniques/T1098/) Account Manipulation |
| **Status** | Production-ready, requires approved-app tuning |
| **Version** | 1.0.0 |

## What this detects

Users granting OAuth consent to third-party AI applications in Entra ID: an AI notetaker, an "AI email assistant", a browser side-panel agent, a ChatGPT-style plugin. The event of interest is the consent grant itself and the Microsoft Graph permissions attached to it (`Mail.Read`, `Files.Read.All`, `Calendars.Read`, `offline_access` and similar).

This is shadow AI at the identity layer. Where AI-001, AI-004 and AI-005 watch network egress and file uploads, this rule watches the grant. Once a user (or an admin) consents, the app receives a standing token and reads data through the Graph API directly from Microsoft infrastructure. Nothing crosses the endpoint or the proxy again, so the network-based rules never see it.

## Why it matters

An OAuth grant to an AI app is a durable, invisible data channel:

- An "AI meeting assistant" with `Calendars.Read` and `OnlineMeetings.Read` can enumerate and join every meeting on the calendar.
- An "AI inbox" app with `Mail.Read` and `offline_access` can read the entire mailbox indefinitely, including after the user forgets it exists.
- A single **admin consent** to an AI app grants those scopes tenant-wide, for every user at once.
- Consent phishing uses exactly this mechanism: the malicious app is often themed as an AI productivity tool precisely because users now expect AI apps to ask for broad access.

The token does not expire with a password reset and is not covered by DLP. Revocation is a deliberate act, which means an unnoticed grant persists for months.

## Query files

| File | Use in |
|---|---|
| [`AI-006-oauth-consent-ai-apps.kql`](AI-006-oauth-consent-ai-apps.kql) | Defender XDR Advanced Hunting, `CloudAppEvents` (uses `Timestamp`) |
| [`AI-006-oauth-consent-ai-apps.yaml`](AI-006-oauth-consent-ai-apps.yaml) | Microsoft Sentinel scheduled analytics rule, `AuditLogs` (uses `TimeGenerated`) |

The two platforms expose consent events in different tables. The Defender XDR query reads `CloudAppEvents` (requires the Entra ID app connected to Defender for Cloud Apps). The Sentinel rule reads `AuditLogs` natively (Entra ID diagnostic settings streaming to the workspace). Deploy whichever matches your connected data; both encode the same logic.

## Prerequisites

- **Sentinel:** Entra ID (Azure Active Directory) diagnostic settings sending `AuditLogs` to the workspace
- **Defender XDR:** Entra ID app connected in Microsoft Defender for Cloud Apps so consent activity populates `CloudAppEvents`
- Directory roles that permit reading service principal and OAuth grant events

## Discovery query (run first)

Inventory the AI apps and consent activity already present, so you tune to your tenant rather than guess:

```kusto
AuditLogs
| where TimeGenerated > ago(30d)
| where OperationName in ("Consent to application", "Add delegated permission grant",
                          "Add app role assignment grant to user")
| extend TargetApp = tostring(TargetResources[0].displayName)
| summarize Consents = count(), Users = dcount(tostring(InitiatedBy)) by TargetApp
| order by Consents desc
```

Anything AI-themed that you do not recognize is a candidate for review; anything you trust goes into `approved_app_ids`.

## Deployment

**Defender XDR (Advanced Hunting / Custom Detection):**
1. Paste the `.kql` into Advanced Hunting and run over `ago(30d)` to baseline
2. Move trusted AppIds into `approved_app_ids`
3. Save as a Custom Detection on a 1h schedule

**Microsoft Sentinel:**
1. Import the `.yaml` via `Analytics > Import`
2. Incidents group by Account so one identity's grants stay in a single incident

## Tuning guidance

| Situation | Action |
|---|---|
| An AI app is officially sanctioned | Add its AppId to `approved_app_ids` so it stops firing |
| Copilot / Microsoft first-party apps appear | Add their AppIds to the approved list; they are expected |
| A department is piloting an approved AI tool | Approve the specific AppId, not the vendor name, so look-alike apps still alert |
| Too many single user consents, few risky | Raise severity only when `IsAdminConsent` is Yes or `TouchesSensitiveScope` is Yes |
| App names do not match the list | Run the discovery query and extend `ai_app_names` with what your tenant actually shows |

Expected noise level after tuning: low. Consent to a new AI app is a discrete, meaningful event, not background chatter.

## Investigation runbook

1. **Read the granted scopes.** The `Scopes` field is the whole story. `Mail.Read`, `Files.Read.All`, `Sites.Read.All` and `offline_access` mean standing access to content. `User.Read` alone is low risk.
2. **Admin or user consent?** `AdminConsent = Yes` means tenant-wide exposure from a single click. Prioritize it over any number of individual user grants.
3. **Identify the app and publisher.** Match the AppId against the Entra ID enterprise applications blade. An unverified publisher on an AI-themed app that requests mail or files is the classic consent-phishing signature.
4. **Check who granted it and from where.** A grant from an unusual IP or immediately after a phishing email points to consent phishing rather than shadow AI adoption.
5. **Assess data reach.** With the scopes in hand, determine exactly what the app can read: which mailboxes, which sites, which calendars.
6. **Outcome paths.** Sanctioned tool becomes an approved AppId. Unsanctioned but benign AI app goes through your AI governance and app-approval process. Unknown app with sensitive scopes and an unverified publisher is revoked immediately (`Revoke-AzureADUserAllRefreshToken` / remove the service principal grant) and handled as a potential consent-phishing incident.

## False positives

- First-party Microsoft apps (Copilot, Office) requesting expected scopes
- Sanctioned AI tools already through your approval process (approve the AppId)
- Administrators pre-consenting to an app during an approved rollout
- Re-consent prompts after a permission change on an already-trusted app

## Coverage limitation

This rule fires on the **consent event**. An app consented to before the rule was deployed will not re-alert until it requests new permissions. Run the discovery query once at deployment to sweep existing grants, and periodically audit enterprise applications for AI apps holding sensitive scopes that predate the detection.

## Version history

| Version | Date | Change |
|---|---|---|
| 1.0.0 | 2026-07 | Initial release: consent and permission-grant operations, AI app inventory, sensitive Graph scope flagging, admin vs user consent split, Defender XDR (`CloudAppEvents`) and Sentinel (`AuditLogs`) variants, discovery query, consent-phishing investigation path |

---

**Need this deployed and tuned in your environment?** BlueRed Security builds production detection coverage for Microsoft Sentinel and Defender XDR. [Start with a Proof of Value](https://uaeblueredsecurity.com/).
