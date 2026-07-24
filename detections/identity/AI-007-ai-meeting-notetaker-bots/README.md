# AI-007: AI Meeting Notetaker and Transcription Bots in Microsoft 365

| | |
|---|---|
| **ID** | AI-007 |
| **Severity** | Medium (raise to High for bots on external invites or executive meetings) |
| **Category** | Identity / Shadow AI |
| **Platforms** | Microsoft Defender XDR, Microsoft Sentinel |
| **Data source** | `OfficeActivity` (Teams) for Sentinel, `CloudAppEvents` for Defender XDR |
| **MITRE ATT&CK** | [T1213](https://attack.mitre.org/techniques/T1213/) Data from Information Repositories, [T1114](https://attack.mitre.org/techniques/T1114/) Email and Communication Collection |
| **Status** | Visibility detection, requires tenant tuning |
| **Version** | 1.0.0 |

## What this detects

AI notetaker and transcription bots operating inside Microsoft 365: Otter, Fireflies, Fathom, Read.ai, tl;dv, Fellow, Sembly, Avoma, Supernormal and similar. The rule looks for these bots joining Teams meetings as a participant, being installed as a Teams app, or recording and transcribing meeting content.

It is the operational counterpart to AI-006. AI-006 fires at the moment a user consents to the app. AI-007 fires when the bot is actually working: joining the meeting and capturing the conversation, including the case AI-006 cannot see, where the bot arrives on an **external participant's** invite rather than through any internal grant.

## Why it matters

A meeting transcript is frequently the most sensitive artifact an organization produces, and the least governed:

- It is unfiltered. People say things in a meeting they would never write in a document, and the bot captures all of it verbatim.
- It covers the topics that matter most: live deals, roadmap, personnel decisions, incident response, legal strategy.
- It leaves the tenant entirely. Audio and transcript are stored on a third-party consumer platform, indexed, and in some tiers used to train the vendor's models.
- The external-invite path bypasses your controls completely. When a vendor or job candidate brings their own notetaker into your meeting, no app is installed in your tenant and no consent is granted, yet your conversation is recorded.

## Query files

| File | Use in |
|---|---|
| [`AI-007-ai-meeting-notetaker-bots.kql`](AI-007-ai-meeting-notetaker-bots.kql) | Defender XDR Advanced Hunting, `CloudAppEvents` (uses `Timestamp`) |
| [`AI-007-ai-meeting-notetaker-bots.yaml`](AI-007-ai-meeting-notetaker-bots.yaml) | Microsoft Sentinel scheduled analytics rule, `OfficeActivity` (uses `TimeGenerated`) |

## Prerequisites

- **Sentinel:** Microsoft 365 (Office 365) data connector with the Teams workload streaming `OfficeActivity`
- **Defender XDR:** Microsoft 365 / Teams audit connected in Defender for Cloud Apps so participant and app events populate `CloudAppEvents`
- Teams audit logging enabled in the Microsoft 365 compliance / Purview audit configuration

## Telemetry reality (read before deploying)

Native meeting-participant logging is uneven across tenants and Teams versions. Some bots appear as named participants, some as app installs, some only through the recording or transcript event, and a bot on an external invite may surface only as an unfamiliar display name. This is a **visibility detection first**. The first few weeks of results are the input to your notetaker policy, not a finished alert stream. Run the discovery query, learn your real footprint, then tighten.

## Discovery query (run first)

```kusto
OfficeActivity
| where TimeGenerated > ago(30d)
| where OfficeWorkload has "Teams"
| extend Name = tolower(strcat(tostring(Members), " ", AddOnName, " ", TargetUserOrGroupName))
| where Name has_any ("otter","fireflies","fathom","read.ai","tl;dv","tldv","fellow","sembly","avoma","notetaker","bot")
| summarize Events = count() by AddOnName, Operation
| order by Events desc
```

Whatever names appear here are the ground truth for your `notetaker_names` list and your approved list.

## Deployment

**Defender XDR (Advanced Hunting / Custom Detection):** paste the `.kql`, baseline over `ago(30d)`, approve sanctioned notetakers, save as a Custom Detection on a 1h schedule.

**Microsoft Sentinel:** import the `.yaml`; incidents group by Account (meeting organizer).

## Tuning guidance

| Situation | Action |
|---|---|
| Org has a sanctioned notetaker (e.g. Copilot) | Add its display name to `approved_notetakers` |
| A bot recurs for one team that piloted a tool | Approve that specific bot name, keep the rest alerting |
| Many low-value single hits | Raise severity only when `DistinctMeetingCount` is high or the organizer is in a sensitive group |
| Bot names do not match | Run the discovery query and extend `notetaker_names` |
| External-invite bots are the concern | Prioritize results where the bot name is not a known internal user and the meeting had external participants |

Expected noise level after tuning: low to medium, depending on how many notetakers your users have adopted.

## Investigation runbook

1. **Identify the bot and its vendor.** The `Bots` field names the tool. Confirm whether it is sanctioned, tolerated, or unknown.
2. **Internal grant or external invite?** If the organizer or an internal user installed or consented to it, this is internal shadow AI (pair with AI-006). If the bot came in with an external participant, it is an external data-capture exposure and your controls did not touch it.
3. **Assess the meetings.** `DistinctMeetingCount` and the organizer tell you the exposure. A notetaker across an executive's recurring meetings is materially different from one on a single internal sync.
4. **Determine what was captured.** Recording plus transcript means full content left the tenant. Confirm where it is stored and under what data terms.
5. **Check the data terms.** A consumer tier that trains on input is a different risk from an enterprise agreement with a DPA and no-training clause.
6. **Outcome paths.** Sanctioned tool becomes an approved name. Unsanctioned internal adoption goes through AI governance and the app is removed if disallowed. External-invite recording is addressed through meeting policy (block anonymous/external app participants, disable external recording) and, where sensitive content was captured, a data-exposure review.

## False positives

- Sanctioned, contracted notetakers (approve by name)
- Microsoft first-party transcription / Copilot recap (approve)
- A user's display name coincidentally containing a keyword (verify against the participant identity)
- Test or demo meetings used to evaluate a tool

## Coverage limitation

If a bot never surfaces in Teams audit (for example a purely client-side recorder capturing system audio on the endpoint), this rule will not see it. That failure mode is closer to endpoint capture and is covered by AI-002 (local execution) and AI-003 (extensions/plugins) rather than here. Pair the three for meeting-capture coverage.

## Version history

| Version | Date | Change |
|---|---|---|
| 1.0.0 | 2026-07 | Initial release: notetaker/transcription bot inventory, participant and app-install and recording actions, internal-grant vs external-invite framing, Defender XDR (`CloudAppEvents`) and Sentinel (`OfficeActivity`) variants, discovery query, meeting-policy remediation path |

---

**Need this deployed and tuned in your environment?** BlueRed Security builds production detection coverage for Microsoft Sentinel and Defender XDR. [Start with a Proof of Value](https://uaeblueredsecurity.com/).
