# shadow-ai-detection

Production-ready detections for **shadow AI** on Microsoft Sentinel and Defender XDR: the unsanctioned and unmonitored use of generative AI across corporate endpoints, identities and cloud apps. Every rule ships as a Defender XDR KQL query, a Sentinel analytics YAML, and a README with tuning and an investigation runbook.

Maintained by [BlueRed Security](https://uaeblueredsecurity.com/), a detection engineering practice for Microsoft Sentinel and Defender XDR.

## Why shadow AI

Employees adopt AI tools faster than security teams can govern them. The exposure is not one channel but several: browser sessions to consumer AI, local models that never touch the network, AI browser extensions that app-control waves through, and files uploaded straight into a consumer tier that trains on the input. Most AI governance programs have a policy but no telemetry. This repo is the telemetry.

## Detection catalog

| ID | Detection | Data source | ATT&CK | Status |
|---|---|---|---|---|
| [AI-001](detections/endpoint/AI-001-unapproved-genai-services/) | Unapproved generative AI service usage | `DeviceNetworkEvents` | T1567, T1071.001 | Published |
| [AI-002](detections/endpoint/AI-002-local-llm-execution/) | Local LLM execution and model file activity | `DeviceProcessEvents`, `DeviceFileEvents` | T1204 | Published |
| [AI-003](detections/endpoint/AI-003-ai-browser-extensions/) | Unmanaged AI browser extensions and IDE plugins | `DeviceFileEvents`, `DeviceRegistryEvents` | T1176 | Published |
| [AI-004](detections/endpoint/AI-004-sensitive-data-to-genai/) | Sensitive data uploaded to generative AI | `CloudAppEvents` | T1567 | Published |
| [AI-005](detections/endpoint/AI-005-nonbrowser-ai-api-traffic/) | Non-browser / API-based AI traffic | `DeviceNetworkEvents` | T1567, T1071.001 | Published |
| [AI-006](detections/identity/AI-006-oauth-consent-ai-apps/) | OAuth consent to unsanctioned AI apps | `AuditLogs`, `CloudAppEvents` | T1528, T1098 | Published |
| [AI-007](detections/identity/AI-007-ai-meeting-notetaker-bots/) | AI meeting notetaker and transcription bots | `OfficeActivity`, `CloudAppEvents` | T1213, T1114 | Published |
| [AI-008](detections/azure-openai/AI-008-unsanctioned-azure-openai-provisioning/) | Unsanctioned Azure OpenAI provisioning | `AzureActivity` | T1578, T1583.006 | Published |
| [AI-009](detections/azure-openai/AI-009-anomalous-azure-openai-consumption/) | Anomalous Azure OpenAI consumption | `AzureDiagnostics` | T1567, T1530 | Published |
| [AI-010](detections/exfiltration/AI-010-download-then-genai-upload/) | Bulk download followed by GenAI upload | `CloudAppEvents` | T1567, T1074 | Published |

AI-001 through AI-005 map the five core endpoint shadow-AI channels: browser usage, local models, browser extensions, files uploaded to AI, and non-browser API traffic. AI-006 through AI-010 extend the coverage into the identity, cloud (Azure OpenAI) and exfiltration layers: OAuth consent to AI apps, AI meeting notetaker bots, unsanctioned Azure OpenAI provisioning, anomalous Azure OpenAI consumption, and the bulk-download-then-AI-upload exfiltration chain. Together they cover shadow AI across endpoint, identity, cloud and data-egress. The roadmap is deliberately paced so each rule ships production-ready rather than as a stub.

## Repository layout

```
detections/
  endpoint/      Endpoint-visible shadow AI (AI-001..AI-005)
  identity/      Identity and access-driven AI risk (AI-006, AI-007)
  azure-openai/  Azure OpenAI / enterprise AI service abuse (AI-008, AI-009)
  exfiltration/  Data-out-to-AI patterns (AI-010)
docs/            Deployment notes and shared references
```

Each detection folder contains:

- `<ID>-<slug>.kql`: Defender XDR Advanced Hunting query (uses `Timestamp`)
- `<ID>-<slug>.yaml`: Microsoft Sentinel scheduled analytics rule (uses `TimeGenerated`)
- `README.md`: what it detects, why it matters, prerequisites, deployment, tuning, investigation runbook, false positives

## How to deploy

**Defender XDR (Advanced Hunting / Custom Detection):** paste the `.kql` into Advanced Hunting, run over `ago(7d)` to baseline, tune the inline lists, then save as a Custom Detection rule.

**Microsoft Sentinel:** import the `.yaml` via `Analytics > Import`, or deploy through your repository CI/CD. Entity mappings, alert details and incident grouping are already defined in each rule.

Read the per-detection README before deploying. Every rule needs environment-specific tuning (approved-tool lists, device-group exclusions, per-tenant action strings); the READMEs tell you exactly what to adjust.

## A note on tuning

These rules are built to be honest about noise. Most start as **visibility** detections: the first week of results is the input to your actual AI usage policy, not a finished alert stream. Baseline first, tune with approved-lists and device groups, then raise severity where it matters. The tuning tables in each README exist so you are not deleting signal to silence noise.

## About BlueRed Security

BlueRed Security builds and tunes production detection coverage for Microsoft Sentinel and Defender XDR: detection engineering sprints, continuous detection engineering, and proof-of-value engagements. If you want these detections deployed and tuned in your environment, or a broader detection program built around MITRE ATT&CK coverage, [start with a Proof of Value](https://uaeblueredsecurity.com/).

## Disclaimer

These detections are provided as-is for defensive security use. Validate and tune every rule in a test workspace before production deployment. KQL is illustrative of the detection logic and may need adjustment for your schema version and data connectors.
