# Shadow AI Detection Tuning Guide

This guide helps security teams tune Shadow AI detections to reduce false positives and improve signal quality in production environments.

---

## Tuning Objectives

The goal of tuning is to:

- Reduce false positives
- Maintain high detection fidelity
- Adapt detections to the organization’s environment
- Improve analyst efficiency

---

## General Tuning Strategy

Always tune detections based on:

- User roles (developer vs non-technical)
- Approved tools and services
- Environment-specific behavior
- Frequency and patterns of activity

---

## Network-based AI Usage Tuning

### Common sources of noise:

- Approved AI tools (e.g., Copilot)
- Security or research teams
- Developer environments

---

### Recommended tuning:

#### 1. Allow approved domains

Example:
```kusto id="tdf48f"
| where RemoteUrl !has_any ("approved-ai-domain.com")
