import streamlit as st
import joblib
from feature_extractor import extract_features
import requests
from urllib.parse import urlparse
import gdown
import os
import time
import pandas as pd
import io

# Load model from Google Drive if not present
model_path = "malicious_url_model.pkl"
gdrive_file_id = "1t71-8vQVZowK05KfeRO-JAjRNQQSV0aU"  # Replace this

if not os.path.exists(model_path):
    url = f"https://drive.google.com/uc?id={gdrive_file_id}"
    gdown.download(url, model_path, quiet=False)

model = joblib.load(model_path)
labels = ['Benign', 'Defacement', 'Phishing', 'Malware']

# Your API Keys (use secrets.toml or enter manually in bulk section)
VT_API_KEY = st.secrets.get("VT_API_KEY", None)
GSB_API_KEY = st.secrets.get("GSB_API_KEY", None)

# ------------------- VirusTotal Check -------------------
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

# ------------------- Google Safe Browsing Check -------------------
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
            return True, "⚠️ Threat detected"
        else:
            return False, "✅ No threats found"
    else:
        return None, "❌ Google Safe Browsing check failed"

# ------------------- Config -------------------
MODEL_SUSPICION_THRESHOLD = 50.0  # % confidence threshold
VT_RATE_LIMIT_PER_MIN = 4
VT_DELAY_SEC = int(60 / VT_RATE_LIMIT_PER_MIN)  # 15s delay for free API

TRUSTED_DOMAINS = [
    "google.com", "www.google.com",
    "youtube.com", "www.youtube.com",
    "github.com", "www.github.com",
    "wikipedia.org", "www.wikipedia.org"
]

def is_trusted_domain(url):
    domain = urlparse(url).netloc.lower()
    return any(trusted_domain == domain for trusted_domain in TRUSTED_DOMAINS)

# ------------------- Streamlit UI -------------------
st.set_page_config(page_title="Malicious URL Scanner", page_icon="🛡️")
st.title("🛡️ Malicious URL Scanner")

# ========== SINGLE URL SCAN ==========
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
        features.rename(columns={'url_length': 'url_len','shortining_service': 'Shortining_Service'}, inplace=True)
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
                st.success("Trusted domain and external sources marked safe.")
            else:
                label = labels[prediction]
                if prediction == 0:
                    st.success("External sources found no threat -- URL appears safe.")
                else:
                    if confidence >= MODEL_SUSPICION_THRESHOLD:
                        st.info(f"⚠️ No external threat, but model suspects **{label}** ({confidence:.2f}% confidence).")
                    else:
                        st.success(f"No external threat. Model predicted **{label}** with low confidence ({confidence:.2f}%). Likely safe.")

        st.markdown(f"🧠 **Model Prediction:** {label}")
        st.markdown(f"🔐 **Confidence:** {confidence:.2f}%")

        if label == 'Benign':
            st.success("This URL appears safe. No immediate threat detected.")
        else:
            st.error("This URL may be malicious. Avoid clicking or entering sensitive info.")

# ========== BULK CSV ANALYSIS ==========
st.subheader("📂 Bulk CSV Analysis")

uploaded = st.file_uploader("Upload CSV with column 'url'", type=["csv"])
user_vt_api = st.text_input("VirusTotal API Key (optional, overrides secrets)", type="password")
user_gsb_api = st.text_input("Google Safe Browsing API Key (optional, overrides secrets)", type="password")
max_vt_calls = st.number_input("Max VirusTotal calls (0 = unlimited)", min_value=0, value=0, step=1)

if st.button("🚀 Start Bulk Scan") and uploaded:
    try:
        df_in = pd.read_csv(uploaded)
        if 'url' not in df_in.columns:
            st.error("CSV must contain a column named 'url'.")
        else:
            urls = df_in['url'].dropna().astype(str)
            vt_api_key = user_vt_api or VT_API_KEY
            gsb_api_key = user_gsb_api or GSB_API_KEY
            max_vt = None if max_vt_calls == 0 else int(max_vt_calls)

            results = []
            progress = st.progress(0)

            for idx, url in enumerate(urls, start=1):
                try:
                    features = extract_features(url)
                    features.rename(columns={'url_length': 'url_len','shortining_service': 'Shortining_Service'}, inplace=True)
                    features = features[model.feature_names_in_]

                    proba = model.predict_proba(features)[0]
                    prediction = proba.argmax()
                    confidence = float(max(proba))
                    label = labels[prediction]

                    # VT throttling
                    vt_result, vt_status = (None, "VT disabled")
                    if vt_api_key and (max_vt is None or idx <= max_vt):
                        vt_result, vt_status = check_virustotal(vt_api_key, url)
                        time.sleep(VT_DELAY_SEC)

                    gsb_result, gsb_status = (None, "GSB disabled")
                    if gsb_api_key:
                        gsb_result, gsb_status = check_google_safe_browsing(gsb_api_key, url)

                    # Combine logic
                    if isinstance(vt_result, dict) and vt_result.get("positives", 0) > 0:
                        final = "Malicious (VirusTotal)"
                    elif gsb_result is True:
                        final = "Malicious (SafeBrowsing)"
                    else:
                        if confidence >= MODEL_SUSPICION_THRESHOLD / 100:
                            final = label
                        else:
                            final = "Needs Manual Review"

                    results.append({
                        "URL": url,
                        "ML_Prediction": label,
                        "Confidence": round(confidence * 100, 2),
                        "VirusTotal_Status": vt_status,
                        "SafeBrowsing_Status": gsb_status,
                        "Final_Classification": final
                    })
                except Exception as e:
                    results.append({
                        "URL": url,
                        "ML_Prediction": None,
                        "Confidence": None,
                        "VirusTotal_Status": None,
                        "SafeBrowsing_Status": None,
                        "Final_Classification": f"Error: {e}"
                    })

                progress.progress(int(idx / len(urls) * 100))

            results_df = pd.DataFrame(results)

            # Summary
            st.write("### Quick Summary")
            st.write(results_df['Final_Classification'].value_counts())

            st.write("### Detailed Results")
            st.dataframe(results_df)

            # Download
            csv_bytes = results_df.to_csv(index=False).encode("utf-8")
            st.download_button("⬇️ Download Detailed Report", csv_bytes, "url_analysis_report.csv", "text/csv")

    except Exception as e:
        st.error(f"Bulk scan failed: {e}")
