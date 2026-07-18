# AI-003: Unmanaged AI Browser Extensions and IDE Plugins

| | |
|---|---|
| **ID** | AI-003 |
| **Severity** | Medium (raise to High if the extension requests broad host permissions) |
| **Category** | Endpoint / Shadow AI |
| **Platforms** | Microsoft Defender XDR, Microsoft Sentinel |
| **Data sources** | `DeviceFileEvents`, `DeviceRegistryEvents` (Defender for Endpoint) |
| **MITRE ATT&CK** | [T1176](https://attack.mitre.org/techniques/T1176/) Browser Extensions |
| **Status** | Production-ready, requires approved-list and known-AI-ID tuning |
| **Version** | 1.0.0 |

## What this detects

Browser extensions installed on corporate endpoints, surfaced from two independent signals and merged per user, device and extension:

1. **Local install**: an extension `manifest.json` (or `_metadata`) written under a browser Extensions directory. The 32-character extension ID is parsed from the folder path.
2. **Managed forcelist**: extension IDs pushed through policy (`ExtensionInstallForcelist` / `ExtensionSettings` registry keys). This catches org-deployed AI extensions that never generate a user download.

The rule uses the same approved-list model as AI-001: sanctioned extension IDs are excluded, everything else surfaces. A curated `known_ai_extension_ids` list flags high-confidence AI extensions (`IsKnownAI = true`) so they sort to the top, but the detection is useful before that list is complete, because every unapproved install is visible.

## Why it matters

Grammarly, Monica, Merlin, Sider, "ChatGPT for Google", Compose AI and dozens of similar assistants install as browser extensions or IDE plugins. Most app-control and CASB policies never treat them as AI tools:

- They are waved through as ordinary browser or editor activity
- Functionally they do what a chatbot does: send page content, selected text or clipboard data to a third-party model
- Many request broad host permissions (`<all_urls>`), so they can read every page the user visits, including internal apps, email and source-control web UIs
- Standalone-domain detections (AI-001) miss them, because the extension's traffic often rides inside the browser session or goes to the vendor's own API endpoint

This is a visibility detection. In most environments the first finding is simply that no approved-extension list exists yet.

## Query files

| File | Use in |
|---|---|
| [`AI-003-ai-browser-extensions.kql`](AI-003-ai-browser-extensions.kql) | Defender XDR Advanced Hunting (uses `Timestamp`) |
| [`AI-003-ai-browser-extensions.yaml`](AI-003-ai-browser-extensions.yaml) | Microsoft Sentinel scheduled analytics rule (uses `TimeGenerated`) |

## Prerequisites

- Microsoft Defender for Endpoint onboarded devices (P1 or P2)
- For Sentinel: Microsoft 365 Defender data connector with `DeviceFileEvents` and `DeviceRegistryEvents` streaming enabled
- Chromium-based browsers (Chrome, Edge, Brave, Vivaldi, Opera) write extension packages to disk on install; Firefox uses a different layout (`.xpi`), partially covered by the path list

## Deployment

**Defender XDR (Advanced Hunting / Custom Detection):**
1. Paste the `.kql` into Advanced Hunting and run over `ago(7d)` to baseline installs
2. Populate `approved_extension_ids` from that baseline so sanctioned tools stop firing
3. Save as a Custom Detection on a 12h to 24h frequency

**Microsoft Sentinel:**
1. Import the `.yaml` via `Analytics > Import`
2. Incidents group by Account so one user's extension activity stays in a single incident

## Populating the known-AI extension list

The detection ships with Grammarly (`kbfnbcaeplbcioakkpcpgfkobkghlhen`) as a verified example. To build your own high-confidence list:

1. Search the Chrome Web Store and Edge Add-ons for the AI assistants relevant to your org
2. The extension ID is the 32-character string in the store URL: `chromewebstore.google.com/detail/<name>/<ID>`
3. Add each ID to `known_ai_extension_ids`
4. For unknown IDs the rule surfaces, the query builds an `ExtensionStoreUrl` you can open to identify the extension, then either approve it or add it to the known-AI list

Treat the known-AI list as a living artifact. New AI extensions ship weekly; a quarterly refresh keeps `IsKnownAI` meaningful.

## Tuning guidance

| Situation | Action |
|---|---|
| A company-approved extension keeps firing | Add its ID to `approved_extension_ids` |
| Developer teams install many IDE/browser dev extensions | Scope an exclusion to their device group rather than approving IDs globally |
| `manifest.json` fires on every browser update | Extension updates rewrite the manifest under a new version folder; alert only on `Sources has "Local install"` combined with `FirstSeen` in the window, or dedupe on ExtId per device over a longer period |
| Too many benign installs during baseline | Set the rule to alert only when `IsKnownAI == true` until the approved list is mature, then widen it |
| Forcelist entries from a sanctioned rollout | Add those IDs to `approved_extension_ids`; keep the signal on for everything else |

Expected noise level after tuning: low. Before tuning: medium, dominated by whatever extensions your users already run.

## Investigation runbook

1. **Identify the extension.** Open the `ExtensionStoreUrl` (or search the ID). Confirm whether it is an AI assistant and what data it handles.
2. **Check the permissions.** Broad host access (`<all_urls>`, "read and change all your data on all websites") on an AI extension means it can exfiltrate any page the user opens. This raises severity.
3. **Check who installed it and where.** A forcelist deployment is an IT/policy decision to review with the owner. A user-initiated local install is an unsanctioned-software conversation.
4. **Correlate with data access.** Pivot the user in `DeviceNetworkEvents` (AI-001) and `CloudAppEvents` (AI-004): an AI extension plus active GenAI sessions plus access to sensitive files is a data-exposure pattern, not an isolated install.
5. **Outcome paths.** Sanctioned tool goes on the approved list. Unapproved but benign goes through your unsanctioned-software process and awareness comms. High-permission AI extension on a high-access user escalates to a data-risk review and removal.

## False positives

- Legitimate, sanctioned extensions not yet added to the approved list
- Browser updates rewriting an existing extension's manifest under a new version folder
- Developer and security tooling extensions on engineering device groups
- Portable browser profiles synced across devices (same ExtId appears on multiple hosts)

## Version history

| Version | Date | Change |
|---|---|---|
| 1.0.0 | 2026-07 | Initial release: dual signal (local manifest install + managed forcelist), 32-char ID parsing, approved-list model with known-AI flagging, Sentinel YAML with account-grouped incidents, investigation runbook |

---

**Need this deployed and tuned in your environment?** BlueRed Security builds production detection coverage for Microsoft Sentinel and Defender XDR. [Start with a Proof of Value](https://uaeblueredsecurity.com/).
