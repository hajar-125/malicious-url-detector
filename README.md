<p align="center">
  <img src="https://img.shields.io/badge/Python-3776AB?style=flat&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/FastAPI-009688?style=flat&logo=fastapi&logoColor=white"/>
  <img src="https://img.shields.io/badge/Docker-2496ED?style=flat&logo=docker&logoColor=white"/>
  <img src="https://img.shields.io/badge/Scikit--learn-F7931E?style=flat&logo=scikit-learn&logoColor=white"/>
  <img src="https://img.shields.io/badge/Pandas-150458?style=flat&logo=pandas&logoColor=white"/>
</p>

<h1 align="center">🔍 Malicious URL Detection Engine</h1>

<p align="center">
  An end-to-end machine learning pipeline that detects malicious URLs using lexical feature extraction, WHOIS querying, and a REST API — containerized with Docker.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/status-active-brightgreen?style=flat"/>
  <img src="https://img.shields.io/badge/license-MIT-blue?style=flat"/>
  <img src="https://img.shields.io/badge/made%20with-Python-1f425f?style=flat"/>
</p>

---

## 📌 Overview

Phishing and malicious URLs are one of the most common vectors for cyberattacks. This project builds a full detection pipeline — from raw data ingestion to a deployable REST API — capable of classifying a URL as **malicious** or **legitimate** in real time.

The system processes over **100,000 URLs**, extracts meaningful features from their structure, and serves predictions through a **FastAPI** endpoint containerized with **Docker**.

---

## ✨ Features

- **Automated data pipeline** — ingests, cleans, and balances 100k+ URL records using Python and Pandas
- **Custom feature extraction** — analyzes lexical structure (length, special characters, entropy, subdomains) and queries WHOIS databases for domain metadata
- **ML classification** — trained model distinguishing malicious from legitimate URLs
- **REST API** — FastAPI endpoint serving real-time predictions
- **Dockerized** — fully containerized for reproducible deployment anywhere

---

## 🗂 Project structure
```
malicious-url-detector/
│
├── app.py                  # FastAPI application entry point
├── train_model.py          # Model training script
├── data_collector.py       # Data ingestion and balancing pipeline
├── feature_extractor.py    # Lexical + WHOIS feature extraction
├── phishing_xgb_model.json # Trained XGBoost model
├── feature_importance.png  # Feature importance visualization
├── dataset_final.csv       # Processed dataset (not tracked by git)
├── requirements.txt        # Python dependencies
├── Dockerfile              # Container configuration
├── .gitignore
└── README.md
```

## ⚙️ How it works
```
Raw URLs (100k+)
      │
      ▼
Data Pipeline (cleaning + balancing)
      │
      ▼
Feature Extraction
  ├── Lexical features (length, dots, hyphens, entropy, @ symbols...)
  └── WHOIS features (domain age, registrar, expiry date...)
      │
      ▼
ML Classifier (training + evaluation)
      │
      ▼
FastAPI REST endpoint → Docker container → Prediction
```

---

## 🧠 Features extracted

| Feature | Description |
|--------|-------------|
| `url_length` | Total character length of the URL |
| `num_dots` | Number of dots in the domain |
| `num_hyphens` | Number of hyphens |
| `num_subdomains` | Number of subdomains |
| `has_ip` | Whether the URL uses an IP address instead of domain |
| `has_at_symbol` | Presence of `@` in the URL |
| `entropy` | Shannon entropy of the URL string |
| `domain_age` | Age of the domain in days (via WHOIS) |
| `is_shortened` | Whether a URL shortener is detected |
| `path_length` | Length of the URL path |

---

## 🚀 Getting started

### Prerequisites
- Python 3.9+
- Docker (optional but recommended)

### Dataset
Download the phishing URL dataset from [Kaggle — Malicious URLs Dataset](https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset) and place it as:
```
data/phishing_dataset.csv
```


## 🌐 API usage

Once running, the API is available at `http://localhost:8000`

**Predict a single URL:**
```bash
curl -X POST http://localhost:8000/predict \
  -H "Content-Type: application/json" \
  -d '{"url": "http://suspicious-login-verify.com/account?id=1234"}'
```

**Response:**
```json
{
  "url": "http://suspicious-login-verify.com/account?id=1234",
  "prediction": "malicious",
  "confidence": 0.94
}
```

**Interactive docs:** visit `http://localhost:8000/docs` for the auto-generated Swagger UI.



## 🛠 Tech stack

| Layer | Technology |
|-------|-----------|
| Language | Python 3.9 |
| Data processing | Pandas, NumPy |
| Feature engineering | Custom lexical module, `python-whois` |
| Machine learning | XGBoost, Scikit-learn |
| API | FastAPI, Uvicorn |
| Containerization | Docker |



## 👩‍💻 Author

**Hajar Benbassou**
Final-year AI & Data Science Engineering student at ENSAM Rabat

[![LinkedIn](https://img.shields.io/badge/LinkedIn-0A66C2?style=flat&logo=linkedin&logoColor=white)](https://linkedin.com/in/hajar-benbassou)
[![GitHub](https://img.shields.io/badge/GitHub-181717?style=flat&logo=github&logoColor=white)](https://github.com/hajar-125)
[![Email](https://img.shields.io/badge/Email-EA4335?style=flat&logo=gmail&logoColor=white)](mailto:benbassou.hajar@gmail.com)
