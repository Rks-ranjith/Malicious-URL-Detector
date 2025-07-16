# 🛡️ Malicious URL Detector using Machine Learning

A **Streamlit web app** that detects **malicious URLs** using a trained machine learning model. It helps users check if a URL is safe or potentially malicious (phishing, malware, defacement).


---

## 🚀 Live Demo

👉 [Click here to try the app](https://rks-ranjith-malicious-url-detector.streamlit.app)  
💻 [GitHub Repository](https://github.com/Rks-ranjith/malicious-url-detector)

---

## 📂 Features

✅ Predicts whether a URL is:
- 🟢 Safe
- 🔴 Malicious (phishing, malware, defacement)

✅ Uses a **trained ML model (`model.pkl`)** built with `scikit-learn`  
✅ Clean and interactive **Streamlit interface**  
✅ Real-time predictions for security enthusiasts and learners

---

## 📦 Tech Stack

- **Python**
- **Streamlit** (for frontend)
- **scikit-learn** + **joblib** (model training & loading)
- **pandas**, **re** (feature extraction)

---

## ⚙️ Setup and Run Locally

1️⃣ **Clone the repository:**
```bash
git clone https://github.com/Rks-ranjith/malicious-url-detector.git
cd malicious-url-detector

---

🧠 About the Model
The machine learning model was trained on a labeled dataset containing URLs categorized as:

Benign

Malware

Phishing

Defacement

Features extracted include:

URL length

Number of special characters

HTTPS presence

Number of digits/letters

Use of shortening services

Presence of IP addresses in the URL

The final model was saved as model.pkl using joblib for lightweight deployment with Streamlit.

--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
📄 Folder Structure
malicious-url-detector/
│
├── app.py               # Streamlit frontend code
├── model.pkl            # Trained ML model
├── requirements.txt     # Project dependencies
└── README.md            # Project overview

-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
🤝 Contributing
Contributions, issues, and feature requests are welcome!

Fork the repository

Create a new branch (git checkout -b feature/your-feature)

Commit your changes (git commit -m 'Add your feature')

Push to the branch (git push origin feature/your-feature)

Open a Pull Request

-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

🛡️ Disclaimer
This tool is intended for educational and learning purposes only. Do not solely rely on it for high-stakes security analysis.

✨ Author
👤 Ranjithkumar S (@Rks-ranjith)
