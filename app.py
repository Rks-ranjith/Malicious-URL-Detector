import streamlit as st
import joblib
from feature_extractor import extract_features
import requests
from urllib.parse import urlparse
import gdown
import os
import time
import pandas as pd
import plotly.express as px

# ------------------- Load Model -------------------
model_path = "malicious_url_model.pkl"
gdrive_file_id = "1t71-8vQVZowK05KfeRO-JAjRNQQSV0aU"  # Replace this with your file id if needed

if not os.path.exists(model_path):
    url = f"https://drive.google.com/uc?id={gdrive_file_id}"
    gdown.download(url, model_path, quiet=False)

model = joblib.load(model_path)
labels = ['Benign', 'Defacement', 'Phishing', 'Malware']

# ------------------- API Keys -------------------
VT_API_KEY = st.secrets.get("VT_API_KEY", None)
GSB_API_KEY = st.secrets.get("GSB_API_KEY", None)

# ------------------- VirusTotal Check -------------------
def check_virustotal(api_key, url):
    params = {'apikey': api_key, 'resource': url}
    try:
        response = requests.post('https://www.virustotal.com/vtapi/v2/url/report', data=params, timeout=30)
    except Exception as e:
        return None, f"VirusTotal request failed: {e}"
    if response.status_code == 200:
        result = response.json()
        positives = result.get('positives', 0)
        total = result.get('total', 0)
        return result, f"{positives}/{total} engines flagged"
    else:
        return None, f"VirusTotal check failed (status {response.status_code})"

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
    try:
        response = requests.post(api_url, params=params, json=payload, timeout=15)
    except Exception as e:
        return None, f"Safe Browsing request failed: {e}"

    if response.status_code == 200:
        result = response.json()
        if "matches" in result:
            return True, "⚠️ Threat detected"
        else:
            return False, "✅ No threats found"
    else:
        return None, f"❌ Safe Browsing check failed (status {response.status_code})"

# ------------------- Config -------------------
MODEL_SUSPICION_THRESHOLD = 50.0  # % (used for display and final decision comparison)
VT_DELAY_SEC = 15  # Free VT API: ~4 requests/minute; throttle to avoid rate-limits

TRUSTED_DOMAINS = [
    "google.com", "www.google.com", "youtube.com", "www.youtube.com",
    "github.com", "www.github.com", "wikipedia.org", "www.wikipedia.org"
]

def is_trusted_domain(url):
    try:
        domain = urlparse(url).netloc.lower()
        return any(trusted_domain == domain for trusted_domain in TRUSTED_DOMAINS)
    except Exception:
        return False

# ------------------- Fast Bulk Scanner -------------------
def fast_bulk_scan(urls, model, model_threshold=0.80, vt_api_key=None, gsb_api_key=None, vt_call_cap=None, progress_callback=None):
    """
    urls: iterable of URL strings
    model_threshold: float 0-1 threshold to accept model prediction without external checks
    vt_api_key, gsb_api_key: API keys (or None to skip)
    vt_call_cap: optional cap on number of VT calls
    progress_callback: optional function(progress_fraction, message) to update UI (e.g., Streamlit progress)
    """
    urls = list(urls)
    n = len(urls)
    if n == 0:
        return []

    # Phase 1: ML-only pass (fast)
    ml_rows = []
    for i, url in enumerate(urls, start=1):
        try:
            features = extract_features(url)
            features.rename(columns={'url_length': 'url_len', 'shortining_service': 'Shortining_Service'}, inplace=True)
            features = features[model.feature_names_in_]
            proba = model.predict_proba(features)[0]
            pred_idx = proba.argmax()
            confidence = float(max(proba))  # 0-1
            label = labels[pred_idx]
            ml_rows.append({
                "URL": url,
                "ML_Prediction": label,
                "ML_Confidence": confidence
            })
        except Exception as e:
            ml_rows.append({"URL": url, "ML_Prediction": None, "ML_Confidence": 0.0, "Error": str(e)})

        if progress_callback:
            progress_callback(i / (n * 2), f"ML pass {i}/{n}")  # first half progress reserved for ML pass

    # Phase 2: Decide which need external checks
    to_check = []
    results = []
    for r in ml_rows:
        url = r["URL"]
        conf = r.get("ML_Confidence", 0.0)
        lbl = r.get("ML_Prediction")
        if conf >= model_threshold:
            # accept model's decision without external checks
            results.append({
                "URL": url,
                "ML_Prediction": lbl,
                "Confidence(%)": round(conf * 100, 2),
                "Final_Classification": lbl,
                "VirusTotal": "skipped (high-confidence)",
                "SafeBrowsing": "skipped (high-confidence)"
            })
        else:
            to_check.append((url, lbl, conf))

    # Phase 3: External checks only for to_check set
    vt_cache = {}
    gsb_cache = {}
    vt_calls = 0
    m = len(to_check)
    for idx, (url, lbl, conf) in enumerate(to_check, start=1):
        # update progress callback (second half)
        if progress_callback:
            progress_callback(0.5 + (idx / (m * 2)), f"External checks {idx}/{m}")

        # GSB check
        gsb_result, gsb_status = (None, "GSB disabled")
        if gsb_api_key:
            if url in gsb_cache:
                gsb_result, gsb_status = gsb_cache[url]
            else:
                gsb_result, gsb_status = check_google_safe_browsing(gsb_api_key, url)
                gsb_cache[url] = (gsb_result, gsb_status)

        # VirusTotal (only if GSB didn't flag)
        vt_result, vt_status = (None, "VT disabled")
        if vt_api_key and (not gsb_result):
            if vt_call_cap is None or vt_calls < vt_call_cap:
                if url in vt_cache:
                    vt_result, vt_status = vt_cache[url]
                else:
                    vt_result, vt_status = check_virustotal(vt_api_key, url)
                    vt_cache[url] = (vt_result, vt_status)
                    vt_calls += 1
                    # throttle
                    time.sleep(VT_DELAY_SEC)
            else:
                vt_status = "VT call cap reached"

        # Combine logic
        if isinstance(vt_result, dict) and vt_result.get("positives", 0) > 0:
            final = "Malicious (VirusTotal)"
        elif gsb_result is True:
            final = "Malicious (SafeBrowsing)"
        else:
            final = lbl if conf >= (MODEL_SUSPICION_THRESHOLD / 100.0) else "Needs Manual Review"

        results.append({
            "URL": url,
            "ML_Prediction": lbl,
            "Confidence(%)": round(conf * 100, 2),
            "VirusTotal": vt_status,
            "SafeBrowsing": gsb_status,
            "Final_Classification": final
        })

    # combine and return
    return results

# ------------------- Streamlit UI -------------------
st.set_page_config(page_title="Malicious URL Scanner", page_icon="🛡️")
st.title("🛡️ Malicious URL Scanner")

# ========== SINGLE URL SCAN ==========
url = st.text_input("🔗 Enter a URL to scan:")

if st.button("🔍 Scan URL"):
    if not url:
        st.warning("Please enter a valid URL.")
    else:
        vt_result, vt_status = check_virustotal(VT_API_KEY, url) if VT_API_KEY else (None, "VirusTotal disabled")
        vt_threat = vt_result.get("positives", 0) > 0 if vt_result else False
        st.markdown(f"🛡️ **VirusTotal:** {vt_status}")

        gsb_threat, gsb_status = check_google_safe_browsing(GSB_API_KEY, url) if GSB_API_KEY else (None, "Safe Browsing disabled")
        gsb_threat = gsb_threat or False
        st.markdown(f"🔍 **Google Safe Browsing:** {gsb_status}")

        try:
            features = extract_features(url)
            features.rename(columns={'url_length': 'url_len','shortining_service': 'Shortining_Service'}, inplace=True)
            features = features[model.feature_names_in_]

            proba = model.predict_proba(features)[0]
            prediction = proba.argmax()
            confidence = max(proba) * 100
            label = labels[prediction]

            if vt_threat or gsb_threat:
                st.warning("⚠️ Threat detected by external sources.")
                if prediction == 0:
                    label = "Phishing"
            else:
                if is_trusted_domain(url) and prediction != 0:
                    label = "Benign"
                    st.success("Trusted domain marked safe.")
                else:
                    if prediction == 0:
                        st.success("External sources found no threat -- URL appears safe.")
                    elif confidence >= MODEL_SUSPICION_THRESHOLD:
                        st.info(f"⚠️ Model suspects **{label}** ({confidence:.2f}% confidence).")
                    else:
                        st.success(f"Model predicted **{label}** with low confidence ({confidence:.2f}%). Likely safe.")

            st.markdown(f"🧠 **Model Prediction:** {label}")
            st.markdown(f"🔐 **Confidence:** {confidence:.2f}%")

            if label == 'Benign':
                st.success("This URL appears safe.")
            else:
                st.error("This URL may be malicious. Avoid it.")
        except Exception as e:
            st.error(f"Single URL scan failed: {e}")

# ========== BULK CSV UPLOAD ==========
st.subheader("📂 Bulk CSV Analysis")
uploaded = st.file_uploader("Upload CSV with column 'url'", type=["csv"])

if uploaded:
    try:
        df_in = pd.read_csv(uploaded)
        if 'url' not in df_in.columns:
            st.error("CSV must contain a column named 'url'.")
        else:
            urls = df_in['url'].dropna().astype(str).tolist()
            progress_bar = st.progress(0)
            status_text = st.empty()

            def progress_hook(frac, message=None):
                try:
                    progress_bar.progress(min(max(int(frac * 100), 0), 100))
                except Exception:
                    pass
                if message:
                    status_text.text(message)

            results = fast_bulk_scan(
                urls,
                model,
                model_threshold=0.80,
                vt_api_key=VT_API_KEY,
                gsb_api_key=GSB_API_KEY,
                vt_call_cap=200,
                progress_callback=progress_hook
            )

            progress_bar.progress(100)
            status_text.text("Completed")

            results_df = pd.DataFrame(results)

            st.write("### Quick Summary")
            if 'Final_Classification' in results_df.columns and not results_df.empty:
                st.write(results_df['Final_Classification'].value_counts())
            else:
                st.write("No results to show.")

            # 📊 Summary chart (Plotly pie)
            if not results_df.empty and 'Final_Classification' in results_df.columns:
                st.write("### Summary Chart")
                summary_counts = results_df['Final_Classification'].value_counts().reset_index()
                summary_counts.columns = ["Classification", "Count"]
                fig = px.pie(
                    summary_counts,
                    names="Classification",
                    values="Count",
                    title="Final Classification Distribution",
                    hole=0.3
                )
                st.plotly_chart(fig, use_container_width=True)

            st.write("### Detailed Results")
            st.dataframe(results_df)

            csv_bytes = results_df.to_csv(index=False).encode("utf-8")
            st.download_button("⬇️ Download Detailed Report", csv_bytes,
                               "url_analysis_report.csv", "text/csv")

    except Exception as e:
        st.error(f"Bulk scan failed: {e}")
