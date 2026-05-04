<div align="right">
  <a href="README-pt.md">🇧🇷 Leia em Português</a>
</div>

# 🛡️ AI Trust & Security Auditor

> **SOC & GRC Dashboard for LLM Threat Intelligence**

An enterprise-grade, front-end dashboard built to simulate a Level 1 Security Operations Center (SOC) environment, focused specifically on auditing Artificial Intelligence models and detecting data exfiltration.

## 🎯 Objective
This project was developed to practice and demonstrate Blue Team operations, specifically monitoring, intercepting, and analyzing malicious interactions with LLMs (Large Language Models) based on industry standards.

## 🚀 Core Features
*   **Deterministic Scan Profiles:** Granular auditing focused on specific threat vectors:
    *   **OWASP LLM Top 10:** Detects Prompt Injections, Jailbreaks, and SSRF attempts.
    *   **Data Privacy (PII/DLP):** Tracks unauthorized leakage of sensitive data (CPF, Passports, Credit Cards) simulating LGPD/GDPR compliance checks.
*   **Live Audit Terminal:** Real-time log generation mapping the "heartbeat" of the security scans.
*   **Forensic Payload Viewer:** Deep-dive modal revealing network metadata (Source IP, Endpoint), the raw malicious user prompt, and the exact security rule triggered by the firewall.
*   **Dynamic Risk Scoring:** Algorithmic calculation of system severity based on the volume and type of intercepted anomalies.

## 💻 Tech Stack
*   **Frontend:** Next.js, React, Tailwind CSS (Custom Dark/Neon UI).
*   **Backend / Logic:** Python, FastAPI (simulated dynamic payload generation).

## 🧠 Security Concepts Applied
*   Threat Monitoring & Log Analysis.
*   Data Loss Prevention (DLP).
*   Incident Response Simulation (Blocked vs. Flagged events).
