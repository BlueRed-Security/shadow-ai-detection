# shadow-ai-detection
# Shadow AI Detection

Detect unauthorized AI usage in your environment (ChatGPT, Copilot, Gemini, Ollama, local LLMs).

Modern organizations are increasingly exposed to **Shadow AI** - unapproved use of AI tools that can lead to:
- Data exfiltration
- Intellectual property leakage
- Compliance violations
- Loss of visibility and control

This repository provides **production-ready detection rules** to help security teams identify and monitor AI usage across enterprise environments.

---

## Coverage

The detections in this repository focus on:

- Network-based AI usage (OpenAI, Anthropic, Google AI, Copilot)
- Local LLM execution (Ollama, GGUF, llama.cpp, LM Studio)
- AI-powered extensions (Copilot, ChatGPT, Grammarly, Codeium)
- Suspicious AI-related processes and command-line activity

---

## Supported Platforms

- Microsoft Defender XDR
- Microsoft Sentinel

All detections are written using **KQL (Kusto Query Language)**.

## Repository Structure

/kql
network-ai-usage.kql
local-llm-usage.kql
ai-extensions.kql

/docs
investigation-guide.md
tuning-guide.md

## Investigation Guidance

Each detection should be validated with:
- User context (who executed the activity)
- Process lineage
- Network connections
- Frequency and behavioral patterns

False positives are expected in developer-heavy environments and should be tuned accordingly.

---

## Important

These detections are designed as a **starting point**.  
Proper tuning and correlation are required for production environments.

---

## Need help implementing this?

If you want to:
- Deploy and tune these detections
- Identify real detection gaps in your environment
- Reduce false positives and improve signal quality

https://uaeblueredsecurity.com/

---

## License

MIT License
