# AI-008: Unsanctioned Azure OpenAI / Cognitive Services Provisioning

| | |
|---|---|
| **ID** | AI-008 |
| **Severity** | Medium (raise to High for human callers creating OpenAI accounts in unknown subscriptions) |
| **Category** | Azure OpenAI / Shadow AI infrastructure |
| **Platforms** | Microsoft Sentinel (Azure control plane) |
| **Data source** | `AzureActivity` |
| **MITRE ATT&CK** | [T1578](https://attack.mitre.org/techniques/T1578/) Modify Cloud Compute Infrastructure, [T1583.006](https://attack.mitre.org/techniques/T1583/006/) Acquire Infrastructure: Web Services |
| **Status** | Production-ready, requires approved-scope tuning |
| **Version** | 1.0.0 |

## What this detects

Creation of Azure OpenAI and related Cognitive Services resources, and model deployments on them, outside your approved subscriptions and resource groups. It watches the Azure Resource Manager control plane for `Microsoft.CognitiveServices/accounts/write`, deployment writes, and the Machine Learning workspace and online-endpoint equivalents, then filters out the scopes you have declared governed.

## Why it matters

Enterprise Azure OpenAI can be governed well, with content filtering, diagnostic logging, private networking and a data-handling review. All of that applies only to the resources security knows about. A resource created in an unmonitored subscription is a fully capable GPT-class endpoint, standing behind your Azure identity, with none of those guardrails.

Two distinct risks converge here. The first is shadow AI adoption: a team that wants Azure OpenAI, cannot wait for the governed path, and provisions its own, then pipes real data through it. The second is misuse: an over-privileged or compromised identity standing up AI infrastructure for data staging, model abuse, or cost-driven abuse (crypto-style resource abuse has an AI analogue in large model deployments). The same control-plane event surfaces both.

## Platform note

`AzureActivity` is an Azure control-plane table in Log Analytics and Sentinel. It is not a Defender XDR Advanced Hunting table, so this detection ships as a Sentinel hunting query and a Sentinel analytics rule only. There is no endpoint variant, because provisioning a cloud resource is a control-plane action rather than something visible on a device.

## Query files

| File | Use in |
|---|---|
| [`AI-008-unsanctioned-azure-openai-provisioning.kql`](AI-008-unsanctioned-azure-openai-provisioning.kql) | Sentinel Logs / Log Analytics interactive hunting (uses `TimeGenerated`) |
| [`AI-008-unsanctioned-azure-openai-provisioning.yaml`](AI-008-unsanctioned-azure-openai-provisioning.yaml) | Microsoft Sentinel scheduled analytics rule |

## Prerequisites

- Azure Activity data connector streaming `AzureActivity` into the Sentinel workspace, covering every subscription in scope (not only the ones you already trust)
- Knowledge of which subscription IDs and resource groups are your sanctioned AI platform

## Deployment

1. Populate `approved_subscription_ids` and `approved_resource_groups` with your governed AI scopes
2. Run the query over `ago(30d)` to baseline; expect infrastructure-as-code service principals redeploying known resources
3. Import the `.yaml` and run on a 1h schedule; incidents group by the calling account

## Tuning guidance

| Situation | Action |
|---|---|
| A governed subscription hosts all sanctioned Azure OpenAI | Add its subscription ID to `approved_subscription_ids` |
| IaC pipelines redeploy known resources via a service principal | Exclude that principal, or scope to `HumanCaller = Yes` for the high-signal subset |
| A sandbox subscription is expected to have AI resources | Approve that subscription or resource group explicitly |
| Deployments (not account creation) dominate | Split the rule: alert only on `accounts/write` for new resources, treat deployment writes as informational |
| Machine Learning workspaces are noisy in a data-science org | Remove the `MACHINELEARNINGSERVICES` operations and keep this rule OpenAI-only |

Expected noise level after tuning: low. Provisioning a Cognitive Services account is an infrequent, high-signal event once IaC principals are excluded.

## Investigation runbook

1. **Human or service principal?** `HumanCaller = Yes` for a new OpenAI account is the priority. A known IaC principal redeploying a known resource is usually benign.
2. **Which subscription and resource group?** An unfamiliar subscription outside your governed scope is the core signal. Confirm ownership and intent with the subscription owner.
3. **Account creation vs deployment.** `accounts/write` creates a new endpoint. `deployments/write` adds a model to an existing one. New account creation in an unmanaged scope is the higher risk.
4. **Check the resulting resource.** Verify whether diagnostic logging, content filtering and network restrictions were configured. A shadow resource typically has none, which is also why AI-009 (usage monitoring) cannot see it until it is brought under logging.
5. **Assess the caller's rights.** Determine how the caller had permission to create Cognitive Services resources here. Over-broad Contributor at subscription scope is a governance finding in itself.
6. **Outcome paths.** Sanctioned-but-ungoverned resource is brought under management (diagnostic settings, content filter, network) and the scope is added to the approved list. Genuinely unsanctioned infrastructure is decommissioned through change control. A caller who should not have had provisioning rights triggers an access review, and unexpected creation by a service principal escalates to a possible identity-compromise investigation.

## False positives

- Infrastructure-as-code pipelines deploying approved resources (exclude the principal)
- Approved sandbox or dev subscriptions expected to hold AI resources (approve the scope)
- Redeployments and configuration updates to already-known resources
- Platform teams standing up the sanctioned AI service (approve once identified)

## Coverage limitation

This rule sees provisioning, not usage. A shadow resource created before deployment will not re-alert; sweep existing Cognitive Services resources across all subscriptions once at deployment (`az cognitiveservices account list` or Resource Graph). Usage and data-in-prompt monitoring on resources you do control is AI-009's job, and it depends on diagnostic logging being enabled, which shadow resources usually lack.

## Version history

| Version | Date | Change |
|---|---|---|
| 1.0.0 | 2026-07 | Initial release: Cognitive Services and Azure ML provisioning operations, approved subscription and resource-group model, human vs service-principal caller split, Sentinel-only platform scoping, existing-resource sweep guidance, links to AI-009 for usage monitoring |

---

**Need this deployed and tuned in your environment?** BlueRed Security builds production detection coverage for Microsoft Sentinel and Defender XDR. [Start with a Proof of Value](https://uaeblueredsecurity.com/).
