# AI-002: Local LLM Execution and Model File Activity

| | |
|---|---|
| **ID** | AI-002 |
| **Severity** | Medium (raise to High for devices with sensitive data access) |
| **Category** | Endpoint / Shadow AI |
| **Platforms** | Microsoft Defender XDR, Microsoft Sentinel |
| **Data sources** | `DeviceProcessEvents`, `DeviceFileEvents` (Defender for Endpoint) |
| **MITRE ATT&CK** | [T1204](https://attack.mitre.org/techniques/T1204/) User Execution (contextual mapping, see note below) |
| **Status** | Production-ready, requires ML team exclusions |
| **Version** | 2.0.0 |

## What this detects

Two independent signals of local LLM usage on corporate endpoints, merged into one result per user and device:

1. **Runtime execution**: known local LLM binaries (Ollama, LM Studio, Jan, GPT4All, KoboldCpp, llama.cpp server and CLI, AnythingLLM, Msty) or command lines containing LLM tooling indicators (`ollama run`, `.gguf`, `text-generation-webui`, `vllm serve` and others). Command line matching survives binary renaming.
2. **Model file activity**: GGUF, GGML or llamafile model files written to disk. This catches the multi-gigabyte model download itself, which happens even when the runtime is disguised or portable.

A device showing both signals is a confirmed local LLM setup, not a stray file.

**MITRE note:** running a local LLM is not an adversary technique by itself, so the T1204 mapping is contextual (unsanctioned software execution). The detection value is data risk visibility, and in rarer cases, catching offensive tooling: attackers use offline models to generate payloads and phishing content without touching monitored cloud AI services.

## Why it matters

Local LLMs are the blind spot in most AI governance programs. Cloud AI usage (AI-001) at least crosses the network where a proxy or CASB can see it. A local model processes everything offline:

- No proxy logs, no CASB events, no API audit trail
- A user can feed an entire customer database or source tree into the model
- Model outputs (generated code, documents) enter company workflows with no provenance
- On developer machines, local models often run with access to mounted repos and credentials

The endpoint is the only place this activity is visible. If Defender for Endpoint does not catch it, nothing will.

## Query files

| File | Use in |
|---|---|
| [`AI-002-local-llm-execution.kql`](AI-002-local-llm-execution.kql) | Defender XDR Advanced Hunting (uses `Timestamp`) |
| [`AI-002-local-llm-execution.yaml`](AI-002-local-llm-execution.yaml) | Microsoft Sentinel scheduled analytics rule (uses `TimeGenerated`) |

## Prerequisites

- Microsoft Defender for Endpoint onboarded devices (P1 or P2)
- For Sentinel: Microsoft 365 Defender data connector with `DeviceProcessEvents` and `DeviceFileEvents` streaming enabled

## Deployment

**Defender XDR (Advanced Hunting / Custom Detection):**
1. Paste the `.kql` into Advanced Hunting and run over `ago(7d)` to baseline
2. Review hits from ML engineers and developers, then scope exclusions by device group
3. Save as a Custom Detection on a 1h to 24h frequency

**Microsoft Sentinel:**
1. Import the `.yaml` via `Analytics > Import`
2. Incidents group by Host: one incident per device, accumulating both signal types

## Tuning guidance

| Situation | Action |
|---|---|
| ML or data science team runs local models legitimately | Exclude their device group in the rule scope, not individual users. New team members inherit coverage automatically |
| Sanctioned local AI deployment (approved Ollama rollout) | Add the deployment path to an exclusion (`FolderPath startswith`) and keep monitoring everything else |
| Developers hit on `.gguf` in project dependency folders | Add path exclusions for known package caches, keep user profile and Downloads paths in scope |
| `node.exe` or `python.exe` noise from generic tooling | The rule intentionally avoids matching bare interpreters. If you extend the process list, always pair interpreters with command line indicators |
| Single `FileModified` events on existing models | Alert only when `SignalCount == 2` or `EventCount > 3` for a quieter rule |

Expected noise level: low in standard corporate environments, medium in engineering-heavy ones before device group exclusions.

## Investigation runbook

1. **Confirm the setup.** Both signals present (runtime plus model files) means an installed, functioning local LLM. Model files alone may be a download in progress or file sync.
2. **Identify the model and size.** The `Details` field carries folder path and file size. A 4 GB general chat model suggests personal experimentation. Fine-tuned or code-specific models on a workstation with repo access deserve more attention.
3. **Check what the user has access to.** Pivot the user in `DeviceFileEvents` around the same window: large reads from network shares, database exports or repo clones just before LLM activity indicate data being staged for local processing.
4. **Check process lineage.** An LLM runtime launched by a script, scheduled task or another user context (not interactive) is unusual and worth escalating.
5. **Outcome paths.** Personal experimentation goes through your unsanctioned software process. ML team usage becomes a device group exclusion. Data staging plus local LLM on a high-access user escalates to a data risk investigation.

## False positives

- ML engineers and researchers with legitimate local model workflows
- Approved offline AI pilots (air-gapped or privacy-driven deployments)
- Package caches containing `.gguf` test fixtures (rare, path-excludable)
- Security teams evaluating AI tooling

## Version history

| Version | Date | Change |
|---|---|---|
| 2.0.0 | 2026-07 | Full rewrite: dual signal design (process + model file), command line indicators resilient to renaming, removed noisy bare `node.exe` matching, Sentinel YAML with host-grouped incidents, investigation runbook |
| 1.0.0 | 2026-04 | Initial release (`local-llm-usage.kql`) |

---

**Need this deployed and tuned in your environment?** BlueRed Security builds production detection coverage for Microsoft Sentinel and Defender XDR. [Start with a Proof of Value](https://uaeblueredsecurity.com/).
