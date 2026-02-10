# 🛡️ Fraud Guard: AI-Powered Phishing & Scam Detector

**Fraud Guard** is a comprehensive tool designed to analyze suspicious text and URLs for fraudulent activity. It uses a multi-layered approach combining a BERT-based Machine Learning model with heuristic analysis to identify psychological triggers and technical red flags.

## ✨ Key Features

* **ML-Powered Analysis**: Uses a fine-tuned BERT model to detect spam and phishing patterns with high confidence.
* **Psychological Trigger Detection**: Identifies tactics like "Urgency" (e.g., "verify now") and "Authority Impersonation".
* **Technical Flagging**: Detects "Malicious Links" redirecting to known phishing domains and "Header Mismatches" in emails.
* **Multilingual Support**: Automatically detects and translates non-English text to English before analysis.
* **Smart Sanitization**: Masks sensitive information like emails and phone numbers before processing to protect user privacy.
* **URL Safety Check**: Integrated with Google Safe Browsing to flag known malicious URLs.

## 🛠️ Tech Stack

* **Backend**: FastAPI
* **Frontend**: Streamlit
* **ML Integration**: Hugging Face Transformers (`bert-tiny`)
* **Data Validation**: Pydantic
* **Utilities**: `urlextract`, `deep-translator`, `langdetect`

## 🚀 Getting Started

### 1. Prerequisites
* Python 3.9+
* A Google Safe Browsing API Key (optional but recommended)

### 2. Installation
```bash
# Clone the repository
git clone [https://github.com/your-username/fraud-guard.git](https://github.com/your-username/fraud-guard.git)
cd fraud-guard

# Install required dependencies
pip install -r requirements.txt
