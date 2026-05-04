<div align="right">
  <a href="README.md">🇺🇸 Read in English</a>
</div>

# 🛡️ AI Trust & Security Auditor

> **Dashboard de SOC & GRC para Inteligência de Ameaças em LLMs**

Um dashboard front-end de nível corporativo construído para simular um ambiente de Centro de Operações de Segurança (SOC) Nível 1, focado especificamente na auditoria de modelos de Inteligência Artificial e detecção de exfiltração de dados.

## 🎯 Objetivo
Este projeto foi desenvolvido para praticar e demonstrar operações de Blue Team, especificamente o monitoramento, interceptação e análise de interações maliciosas com LLMs (Large Language Models) com base em padrões da indústria.

## 🚀 Principais Funcionalidades
*   **Perfis de Varredura Determinísticos:** Auditoria granular focada em vetores de ameaças específicos:
    *   **OWASP LLM Top 10:** Detecta tentativas de Prompt Injection, Jailbreaks e SSRF.
    *   **Privacidade de Dados (PII/DLP):** Rastreia o vazamento não autorizado de dados sensíveis (CPF, Passaportes, Cartões de Crédito) simulando verificações de conformidade com a LGPD.
*   **Terminal de Auditoria ao Vivo:** Geração de logs em tempo real mapeando o "batimento cardíaco" das varreduras de segurança.
*   **Visualizador Forense de Payload:** Modal de investigação profunda que revela metadados de rede (IP de Origem, Endpoint), o prompt malicioso bruto do usuário e a regra de segurança exata acionada pelo firewall.
*   **Pontuação Dinâmica de Risco:** Cálculo algorítmico da gravidade do sistema com base no volume e tipo de anomalias interceptadas.

## 💻 Stack Tecnológico
*   **Frontend:** Next.js, React, Tailwind CSS (UI Customizada Dark/Neon).
*   **Backend / Lógica:** Python, FastAPI (geração dinâmica de payloads simulados).

## 🧠 Conceitos de Segurança Aplicados
*   Monitoramento de Ameaças & Análise de Logs.
*   Prevenção contra Perda de Dados (DLP).
*   Simulação de Resposta a Incidentes (Eventos Bloqueados vs. Sinalizados).
