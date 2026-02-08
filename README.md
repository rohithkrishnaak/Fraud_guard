# 🛡️ Fraud Guard - AI-Powered Phishing & Fraud Detection

![Project Status](https://img.shields.io/badge/Status-Active-success)
![Python Version](https://img.shields.io/badge/Python-3.9%2B-blue)
![Tech Stack](https://img.shields.io/badge/Stack-FastAPI%20%7C%20Streamlit%20%7C%20Gemini-orange)

**Fraud Guard** is a "Compound AI System" designed to detect financial fraud, phishing attempts, and malicious URLs in real-time. Unlike simple AI wrappers, it uses a **multi-stage defense pipeline** combining deterministic rules (Regex), threat intelligence (Google Safe Browsing), and Generative AI (Gemini 1.5) for psychological analysis.

## 🚀 Key Features

* **🔒 Privacy Firewall:** Automatically redacts PII (emails, phone numbers) *before* data leaves the local server to ensure user privacy.
* **⚡ Hybrid Analysis:**
    * **Static Engine:** Instantly flags known scam keywords (e.g., "urgent", "otp", "suspended") using Regex.
    * **Threat Intel:** Verifies URLs against Google's **Safe Browsing Database** to detect known malware/phishing sites.
    * **AI Reasoning:** Uses **Google Gemini 1.5** to detect psychological triggers (urgency, fear, greed) and tone anomalies.
* **📝 Structured Explainability:** Returns a detailed JSON report with a color-coded Risk Score (0-100), technical flags, and human-readable explanations.
* **⚡ Real-Time Latency:** Optimized for sub-2-second analysis speeds.

---

## 🛠️ Tech Stack

| Component | Technology | Role |
| :--- | :--- | :--- |
| **Frontend** | [Streamlit](https://streamlit.io/) | Interactive User Interface |
| **Backend API** | [FastAPI](https://fastapi.tiangolo.com/) | REST API & Logic Orchestration |
| **AI Model** | [Google Gemini 1.5 Flash](https://ai.google.dev/) | Context-Aware Reasoning Engine |
| **Threat Intel** | [Google Safe Browsing API](https://developers.google.com/safe-browsing) | Malicious URL Verification |
| **Validation** | [Pydantic](https://docs.pydantic.dev/) | Data Schema & Output Enforcement |

---

## ⚙️ How It Works (The Pipeline)

1.  **Input:** User pastes suspicious text or URL.
2.  **Sanitization:** System strips sensitive PII (Emails/Phones) to protect user identity.
3.  **Signal Extraction:**
    * Extracts URLs and checks them against Google's Threat Database.
    * Scans for hard-coded scam patterns (e.g., "Verify Bank Account").
4.  **Context Construction:** The system bundles the *Sanitized Text* + *Safe Browsing Status* + *Keyword Matches* into a context packet.
5.  **AI Analysis:** The "Cybersecurity Expert" persona (LLM) analyzes the packet for intent and tone.
6.  **Response:** The Frontend displays a Risk Score, Verdict (Safe/High Risk), and explanation.

---

## 💻 Installation & Setup

### Prerequisites
* Python 3.9 or higher
* Google Cloud API Key (for Gemini & Safe Browsing)

### 1. Clone the Repository
```bash
git clone [https://github.com/yourusername/Fraud_guard.git](https://github.com/yourusername/Fraud_guard.git)
cd Fraud_guard
