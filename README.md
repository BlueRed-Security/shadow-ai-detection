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

AI-001 through AI-005 map the five core shadow-AI channels end to end: browser usage, local models, browser extensions, files uploaded to AI, and non-browser API traffic. More detections (AI-006 onward) are planned across the identity, cloud (Azure OpenAI) and exfiltration categories. The roadmap is deliberately paced so each rule ships production-ready rather than as a stub.

## Repository layout

```
detections/
  endpoint/      Endpoint-visible shadow AI (AI-001..AI-005)
  identity/      Identity and access-driven AI risk (planned)
  azure-openai/  Azure OpenAI / enterprise AI service abuse (planned)
  exfiltration/  Data-out-to-AI patterns (planned)
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
