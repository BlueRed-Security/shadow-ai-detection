# AI-009: Anomalous Azure OpenAI Consumption and Data-in-Prompt Exfiltration

| | |
|---|---|
| **ID** | AI-009 |
| **Severity** | Medium (raise to High for new caller IP with sustained high volume) |
| **Category** | Azure OpenAI / Shadow AI |
| **Platforms** | Microsoft Sentinel |
| **Data source** | `AzureDiagnostics` (Azure OpenAI resource diagnostic logs) |
| **MITRE ATT&CK** | [T1567](https://attack.mitre.org/techniques/T1567/) Exfiltration Over Web Service, [T1530](https://attack.mitre.org/techniques/T1530/) Data from Cloud Storage |
| **Status** | Production-ready, requires baseline tuning |
| **Version** | 1.0.0 |

## What this detects

On the Azure OpenAI resources you already govern, anomalous consumption that resembles bulk data being pushed through the model: a caller IP whose request volume spikes far above its own 7-day baseline, or a caller IP that has never touched the resource before and arrives at high volume. The query self-baselines per resource and per caller, so "anomalous" means anomalous for that caller, not against a global threshold.

## Why it matters

A sanctioned Azure OpenAI resource is trusted egress by design. That is exactly what makes it a good laundering point. High-volume prompting is a real exfiltration channel: feed the model records, ask for "summaries" or "classification", and the sensitive input travels in the prompt, where classic DLP and content inspection do not look. Because the destination is your own approved AI resource, nothing about the network path looks wrong.

A script pushing a customer table through the model in a tight loop is indistinguishable from heavy legitimate use unless you baseline each caller and alert on deviation. This rule supplies that baseline, and separately flags a caller IP that has never used the resource before, which is often the first sign of a new automation or a misused credential.

## Platform note and dependency on AI-008

Azure OpenAI diagnostic logs reach `AzureDiagnostics` only when diagnostic settings are enabled on the resource with the `RequestResponse` and `Audit` categories. This is a Sentinel detection with no endpoint variant. If diagnostics are off, the rule sees nothing. That is the direct reason AI-008 (provisioning) exists: you cannot monitor usage on a resource that was stood up outside governance and never brought under logging. Deploy AI-008 to find shadow resources and AI-009 to watch the governed ones.

## Query files

| File | Use in |
|---|---|
| [`AI-009-anomalous-azure-openai-consumption.kql`](AI-009-anomalous-azure-openai-consumption.kql) | Sentinel Logs / Log Analytics interactive hunting (uses `TimeGenerated`) |
| [`AI-009-anomalous-azure-openai-consumption.yaml`](AI-009-anomalous-azure-openai-consumption.yaml) | Microsoft Sentinel scheduled analytics rule |

## Prerequisites

- Diagnostic settings on each Azure OpenAI resource streaming `RequestResponse` (and ideally `Audit`) to the Sentinel workspace
- At least 7 days of history for the baseline to be meaningful; before that the rule leans on the new-caller-IP signal
- The Sentinel rule uses `queryPeriod: 8d` so the scheduled run can read the baseline window; keep that if you change the schedule

## How the logic works

The query builds three parts. It reads the Azure OpenAI diagnostics, computes a per-resource per-IP hourly baseline over the prior 7 days, then compares the current hour against it. A result fires when the current volume clears the noise floor (`min_requests_current`) and either exceeds the baseline by `spike_multiplier`, or comes from a caller IP with no baseline at all. `SpikeRatio` quantifies how far above normal the caller is.

## Deployment

1. Confirm diagnostics are on for your Azure OpenAI resources
2. Run the query interactively for a week and watch the distribution of `SpikeRatio` and `CurrentRequests`
3. Set `min_requests_current` above your normal per-hour-per-caller volume and `spike_multiplier` to a level that clears routine peaks
4. Import the `.yaml` on a 1h schedule; incidents group by caller IP

## Tuning guidance

| Situation | Action |
|---|---|
| A busy production app drives steady high volume | Its baseline absorbs it; only real spikes fire. Confirm after a week |
| Legitimate batch jobs run on a schedule | Raise `spike_multiplier`, or exclude the app's known egress IP if it is stable |
| New-caller-IP fires on dynamic egress IPs | Baseline on a stable identity where available, or accept new-IP as informational and alert only on `SpikeRatio` |
| Too few requests to baseline | Keep the new-caller-IP branch, relax the volume floor, revisit once history builds |
| You want token volume, not request count | If your diagnostics include request/response size, extend the summarize to sum those fields and baseline on bytes instead of count |

Expected noise level after tuning: low, because the comparison is per caller. The main tuning cost is the first week of baselining.

## Investigation runbook

1. **New IP or a spike?** `IsNewCallerIP = Yes` at high volume is a fresh automation or a misused key. A known IP with a high `SpikeRatio` is an existing caller behaving abnormally.
2. **Whose resource and which model.** Confirm the Azure OpenAI resource and deployment. A production model suddenly serving a new heavy caller is the case to chase.
3. **Correlate with data source reads.** Pivot the timeframe against cloud storage and database access (AI-010, storage diagnostics). Bulk reads from a share or DB export just before the spike indicate data being staged and pushed through the model.
4. **Identify the caller.** Resolve the IP to an app, VM, or user. A service identity that normally does light traffic now running a loop is the signal.
5. **Assess intent and content where possible.** If prompt logging is enabled and permitted, sample the requests. Record-shaped input at scale is exfiltration-by-summary; interactive natural language is likely heavy legitimate use.
6. **Outcome paths.** Legitimate batch use is baselined or excluded. Unsanctioned automation goes through data-handling review. A misused credential or unexpected identity escalates to an incident, and the caller is scoped out of the resource while investigated.

## False positives

- A newly deployed legitimate application on first run (baseline absorbs it after a day)
- Scheduled batch enrichment jobs (exclude the stable egress IP or raise the multiplier)
- Load testing or capacity work against the resource
- A stable app whose egress IP changed, appearing as a new caller

## Coverage limitation

The rule can only see resources with diagnostics enabled, and its precision depends on what those diagnostics contain. Request count is always available; request and response size are not always logged, so the default baselines on volume. Where size is available, baselining on bytes is a stronger exfiltration signal, and the tuning table shows how to switch. For resources outside logging entirely, AI-008 is the control that surfaces them.

## Version history

| Version | Date | Change |
|---|---|---|
| 1.0.0 | 2026-07 | Initial release: per-resource per-caller self-baselining over 7 days, spike-ratio and new-caller-IP branches, noise-floor and multiplier controls, dependency on AI-008 for coverage, byte-based baselining guidance, exfiltration-by-summary investigation path |

---

**Need this deployed and tuned in your environment?** BlueRed Security builds production detection coverage for Microsoft Sentinel and Defender XDR. [Start with a Proof of Value](https://uaeblueredsecurity.com/).
