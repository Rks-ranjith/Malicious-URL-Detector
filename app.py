import streamlit as st
import joblib
from feature_extractor import extract_features
import requests
from urllib.parse import urlparse
import gdown
import os

# Load model from Google Drive if not present
model_path = "malicious_url_model.pkl"
gdrive_file_id = "1t71-8vQVZowK05KfeRO-JAjRNQQSV0aU"  # Replace this

if not os.path.exists(model_path):
    url = f"https://drive.google.com/uc?id={gdrive_file_id}"
    gdown.download(url, model_path, quiet=False)

model = joblib.load(model_path)
labels = ['Benign', 'Defacement', 'Phishing', 'Malware']

# Your API Keys
VT_API_KEY = st.secrets["VT_API_KEY"]
GSB_API_KEY = st.secrets["GSB_API_KEY"]

# VirusTotal Check
def check_virustotal(api_key, url):
    params = {'apikey': api_key, 'resource': url}
    response = requests.post('https://www.virustotal.com/vtapi/v2/url/report', data=params)
    if response.status_code == 200:
        result = response.json()
        positives = result.get('positives', 0)
        total = result.get('total', 0)
        return result, f"{positives}/{total} engines flagged this URL"
    else:
        return None, "VirusTotal check failed"

# Google Safe Browsing Check
def check_google_safe_browsing(api_key, url):
    api_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    payload = {
        "client": {"clientId": "malicious-url-scanner", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    params = {'key': api_key}
    response = requests.post(api_url, params=params, json=payload)

    if response.status_code == 200:
        result = response.json()
        if "matches" in result:
            return True, "⚠️**Threat detected**"
        else:
            return False, "✅ No threats found"
    else:
        return None, "❌ Google Safe Browsing check failed"

MODEL_SUSPICION_THRESHOLD = 50.0

TRUSTED_DOMAINS = [
    "google.com", "www.google.com",
    "youtube.com", "www.youtube.com",
    "github.com", "www.github.com",
    "wikipedia.org", "www.wikipedia.org"
]

def is_trusted_domain(url):
    domain = urlparse(url).netloc.lower()
    return any(trusted_domain == domain for trusted_domain in TRUSTED_DOMAINS)

st.set_page_config(page_title="Malicious URL Scanner", page_icon="🛡️")
st.title("🛡️ Malicious URL Scanner")
url = st.text_input("🔗 Enter a URL to scan:")

if st.button("🔍 Scan URL"):
    if not url:
        st.warning("Please enter a valid URL.")
    else:
        vt_result, vt_status = check_virustotal(VT_API_KEY, url) if VT_API_KEY else (None, "VirusTotal check is disabled")
        vt_positives = vt_result.get("positives", 0) if vt_result else 0
        vt_threat = vt_positives > 0
        st.markdown(f"🛡️ **VirusTotal:** {vt_status}")

        gsb_threat, gsb_status = check_google_safe_browsing(GSB_API_KEY, url) if GSB_API_KEY else (None, "Google Safe Browsing check is disabled")
        gsb_threat = gsb_threat or False
        st.markdown(f"🔍 **Google Safe Browsing:** {gsb_status}")

        # Extract Features
        features = extract_features(url)

        # Rename columns to match model's expected feature names
        features.rename(columns={
            'url_length': 'url_len',
            'shortining_service': 'Shortining_Service'
        }, inplace=True)

        # Align features columns to model's expected input
        features = features[model.feature_names_in_]

        # Predict
        proba = model.predict_proba(features)[0]
        prediction = proba.argmax()
        confidence = max(proba) * 100
        label = labels[prediction]

        # Threat Intel Logic
        if vt_threat or gsb_threat:
            st.warning("⚠️ Threat detected by external sources.")
            if prediction == 0:
                prediction = 2
                label = labels[prediction]
        else:
            if is_trusted_domain(url) and prediction != 0:
                label = "Benign"
                st.success("URL is from a trusted domain and external sources marked it as safe.")
            else:
                label = labels[prediction]
                if prediction == 0:
                    st.success("External sources found no threat -- URL appears to be safe.")
                else:
                    if confidence >= MODEL_SUSPICION_THRESHOLD:
                        st.info(f"⚠️ External sources found no threat, but model suspects **{label}** with {confidence:.2f}% confidence. Proceed with caution!")
                    else:
                        st.success(f"External sources found no threat. Model predicted **{label}** with low confidence ({confidence:.2f}%), likely safe.")

        # Display final result
        st.markdown(f"🧠 **Model Prediction:** {label}")
        st.markdown(f"🔐 **Confidence:** {confidence:.2f}%")

        if label == 'Benign':
            st.success("This URL appears safe. No immediate threat detected.")
        else:
            st.error("This URL may be malicious. Avoid clicking or entering sensitive info.")
