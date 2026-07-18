# AI-005: Non-Browser AI API Traffic from Corporate Endpoints

| | |
|---|---|
| **ID** | AI-005 |
| **Severity** | Medium (raise to High for automated/scheduled data movement) |
| **Category** | Endpoint / Shadow AI |
| **Platforms** | Microsoft Defender XDR, Microsoft Sentinel |
| **Data source** | `DeviceNetworkEvents` (Defender for Endpoint) |
| **MITRE ATT&CK** | [T1567](https://attack.mitre.org/techniques/T1567/) Exfiltration Over Web Service, [T1071.001](https://attack.mitre.org/techniques/T1071/001/) Web Protocols |
| **Status** | Production-ready, requires approved-integration tuning |
| **Version** | 1.0.0 |

## What this detects

Connections from corporate endpoints to generative AI provider APIs made by **non-browser processes**: scripts, SDKs, CLI tools, agents and custom applications calling `api.openai.com`, `api.anthropic.com`, Google Gemini/Vertex, Mistral, Cohere, Perplexity, DeepSeek, Groq, Hugging Face inference, plus enterprise cloud AI (Azure OpenAI, AWS Bedrock).

This is the mirror image of AI-001. AI-001 scopes to browsers to capture interactive employee usage. AI-005 scopes to everything except browsers to capture the programmatic channel. Together they cover the full surface; separately, each stays clean and avoids double-counting.

## Why it matters

API traffic is where automated, high-volume data movement lives, and it is completely invisible to a browser-focused rule:

- A scheduled job piping a customer table or log export through an LLM for "enrichment"
- A developer script summarizing internal documents or source code
- An unsanctioned AI agent or framework (LangChain, AutoGPT-style tooling) with broad file and tool access
- Test or CI pipelines calling AI APIs with real data instead of fixtures

One script can send far more data than any human ever pastes into a chat window, and it runs unattended. The endpoint is where this first becomes visible.

## Query files

| File | Use in |
|---|---|
| [`AI-005-nonbrowser-ai-api-traffic.kql`](AI-005-nonbrowser-ai-api-traffic.kql) | Defender XDR Advanced Hunting (uses `Timestamp`) |
| [`AI-005-nonbrowser-ai-api-traffic.yaml`](AI-005-nonbrowser-ai-api-traffic.yaml) | Microsoft Sentinel scheduled analytics rule (uses `TimeGenerated`) |

## Prerequisites

- Microsoft Defender for Endpoint onboarded devices (P1 or P2)
- For Sentinel: Microsoft 365 Defender data connector with `DeviceNetworkEvents` streaming enabled
- `RemoteUrl` population depends on the endpoint seeing SNI/DNS. Coverage is good for standard HTTPS API clients; a hardcoded-IP client can slip through (see below)

## Deployment

**Defender XDR (Advanced Hunting / Custom Detection):**
1. Paste the `.kql` into Advanced Hunting and run over `ago(7d)` to baseline
2. Add sanctioned integrations to `approved_ai_api_domains` and exclude dev/CI device groups
3. Save as a Custom Detection on a 1h schedule

**Microsoft Sentinel:**
1. Import the `.yaml` via `Analytics > Import`
2. Incidents group by Account so one identity's API activity stays in a single incident

## Relationship to AI-001

Keep both rules deployed. They are intentionally complementary:

| | AI-001 | AI-005 |
|---|---|---|
| Process scope | Browsers only | Everything except browsers |
| Catches | Interactive employee chat usage | Scripts, SDKs, agents, automation |
| Typical volume | Per-session, human-paced | Bursty, automated, high-volume |
| Endpoints | GenAI web app domains | GenAI provider API hosts |

Do not merge them. The browser/non-browser split is what keeps each rule low-noise.

## Tuning guidance

| Situation | Action |
|---|---|
| An approved Azure OpenAI resource is in use | Add its `<resource>.openai.azure.com` host to `approved_ai_api_domains` |
| Sanctioned product calls an AI API from a known binary | Exclude that `InitiatingProcessFileName`, or better, exclude by signed publisher / folder path |
| Dev and data science teams generate steady API hits | Exclude their device group; new members inherit coverage |
| CI/CD runners call AI APIs with test data | Scope out the runner device group and address test-data policy separately |
| `python.exe` / `node.exe` appear for both benign and risky calls | Do not exclude the interpreter globally; pivot on endpoint, volume and command line instead |

Expected noise level after tuning: low in standard environments, medium in engineering-heavy ones before device-group exclusions.

## Investigation runbook

1. **Identify the process and command line.** The `Processes` and `CommandLines` fields tell you whether this is a known tool, an interpreter running a script, or something unexpected. `curl.exe`/`powershell.exe` to an LLM API is worth a closer look than a signed app.
2. **Assess volume and cadence.** Human-like sporadic calls differ from a tight loop or a scheduled burst. High `ConnectionCount` with regular timing suggests automation moving data.
3. **Check the endpoint and provider.** An enterprise Azure OpenAI resource with a DPA is different from `api.openai.com` on a consumer key. Confirm which was called.
4. **Correlate with data access.** Pivot the user/device in `DeviceFileEvents` and `CloudAppEvents` (AI-004): large reads from shares, DB exports or repo clones near the API activity indicate data being fed to the model.
5. **Check the account context.** A service account or scheduled-task context calling AI APIs is unusual and may indicate an unmanaged automation or a compromised credential.
6. **Outcome paths.** Sanctioned integration becomes an approved-domain or process exclusion. Unsanctioned developer automation goes through your AI governance and data-handling process. Unknown process plus high-volume data movement escalates to a data-risk or incident investigation.

## False positives

- Sanctioned applications and integrations calling AI APIs (approve by host or process)
- Developer and data science workflows on known device groups
- Security or IT tooling that embeds AI features
- Telemetry or update clients that happen to resolve through an AI provider CDN (rare; verify the host)

## Coverage limitation

Non-browser TLS clients expose the destination via SNI, which populates `RemoteUrl` in most cases. A client that connects to a hardcoded IP without SNI, or through a tunnel, will not match on domain. Where this matters, pair AI-005 with egress proxy or firewall logs that resolve destinations independently.

## Version history

| Version | Date | Change |
|---|---|---|
| 1.0.0 | 2026-07 | Initial release: non-browser process scoping, AI provider API endpoint list including Azure OpenAI and AWS Bedrock, command-line capture for triage, approved-integration model, Sentinel YAML with account-grouped incidents, investigation runbook |

---

**Need this deployed and tuned in your environment?** BlueRed Security builds production detection coverage for Microsoft Sentinel and Defender XDR. [Start with a Proof of Value](https://uaeblueredsecurity.com/).
