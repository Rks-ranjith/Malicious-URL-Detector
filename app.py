# app.py
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
from typing import Optional, Tuple, Dict, Any

# ------------------- Config / Constants -------------------
MODEL_PATH = "malicious_url_model.pkl"
GDRIVE_FILE_ID = "1t71-8vQVZowK05KfeRO-JAjRNQQSV0aU"  # replace if needed

MODEL_SUSPICION_THRESHOLD = 50.0  # percent for UI messages (not used for VT/GSB override)
VT_DELAY_SEC = 15  # throttle between VT calls (free API ~4/min)
VT_CALL_CAP_DEFAULT = 200

TRUSTED_DOMAINS = {
    "google.com", "www.google.com",
    "youtube.com", "www.youtube.com",
    "github.com", "www.github.com",
    "wikipedia.org", "www.wikipedia.org"
}

# ------------------- Load model -------------------
if not os.path.exists(MODEL_PATH):
    gdrive_url = f"https://drive.google.com/uc?id={GDRIVE_FILE_ID}"
    gdown.download(gdrive_url, MODEL_PATH, quiet=False)

model = joblib.load(MODEL_PATH)
labels = ['Benign', 'Defacement', 'Phishing', 'Malware']

# ------------------- API Keys -------------------
VT_API_KEY = st.secrets.get("VT_API_KEY", None)
GSB_API_KEY = st.secrets.get("GSB_API_KEY", None)

# ------------------- Helper API functions -------------------
def check_virustotal(api_key: str, url: str) -> Tuple[Optional[Dict[str, Any]], str]:
    """Return (result_dict_or_None, status_text)."""
    params = {'apikey': api_key, 'resource': url}
    try:
        resp = requests.post('https://www.virustotal.com/vtapi/v2/url/report', data=params, timeout=30)
    except Exception as e:
        return None, f"VirusTotal request failed: {e}"
    if resp.status_code == 200:
        j = resp.json()
        positives = j.get('positives', 0)
        total = j.get('total', 0)
        return j, f"{positives}/{total} engines flagged"
    else:
        return None, f"VirusTotal check failed (status {resp.status_code})"

def check_google_safe_browsing(api_key: str, url: str) -> Tuple[Optional[bool], str]:
    """Return (matches_boolean_or_None, status_text)."""
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
        resp = requests.post(api_url, params=params, json=payload, timeout=15)
    except Exception as e:
        return None, f"Safe Browsing request failed: {e}"
    if resp.status_code == 200:
        data = resp.json()
        if "matches" in data:
            return True, "⚠️ Threat detected"
        else:
            return False, "✅ No threats found"
    else:
        return None, f"Safe Browsing failed (status {resp.status_code})"

def is_trusted_domain(url: str) -> bool:
    try:
        domain = urlparse(url).netloc.lower()
        return domain in TRUSTED_DOMAINS
    except Exception:
        return False

# ------------------- Fusion Classification -------------------
def classify_url(
    url: str,
    model,
    vt_api_key: Optional[str] = None,
    gsb_api_key: Optional[str] = None,
    vt_cache: Optional[Dict[str, Tuple[Optional[Dict[str,Any]], str]]] = None,
    gsb_cache: Optional[Dict[str, Tuple[Optional[bool], str]]] = None,
    vt_call_cap: Optional[int] = None,
    vt_calls_made: Optional[Dict[str, int]] = None,
    model_threshold: float = 0.80
) -> Dict[str, Any]:
    """
    Perform ML scoring, then consult VT and GSB as needed.
    vt_cache/gsb_cache are in-memory caches (dicts) shared across runs.
    vt_calls_made is a dict to track number of VT calls (passed by reference).
    Returns a result dictionary for this URL.
    """
    vt_cache = vt_cache if vt_cache is not None else {}
    gsb_cache = gsb_cache if gsb_cache is not None else {}
    vt_calls_made = vt_calls_made if vt_calls_made is not None else {"count": 0}

    # ML prediction
    try:
        features = extract_features(url)
        features.rename(columns={'url_length': 'url_len', 'shortining_service': 'Shortining_Service'}, inplace=True)
        features = features[model.feature_names_in_]
        proba = model.predict_proba(features)[0]
        pred_idx = int(proba.argmax())
        ml_label = labels[pred_idx]
        ml_conf_pct = float(max(proba)) * 100.0
    except Exception as e:
        return {
            "URL": url,
            "ML_Prediction": None,
            "Confidence(%)": 0.0,
            "VirusTotal": "error",
            "SafeBrowsing": "error",
            "Final_Classification": f"Error: {e}"
        }

    # Trusted domains: short-circuit to Benign
    if is_trusted_domain(url):
        return {
            "URL": url,
            "ML_Prediction": ml_label,
            "Confidence(%)": round(ml_conf_pct, 2),
            "VirusTotal": "trusted domain",
            "SafeBrowsing": "trusted domain",
            "Final_Classification": "Benign"
        }

    # 1) Google Safe Browsing (cheap) - use cache
    gsb_result = None
    gsb_status = "GSB disabled"
    if gsb_api_key:
        if url in gsb_cache:
            gsb_result, gsb_status = gsb_cache[url]
        else:
            gsb_result, gsb_status = check_google_safe_browsing(gsb_api_key, url)
            gsb_cache[url] = (gsb_result, gsb_status)
        # If GSB flags, mark malicious immediately
        if gsb_result is True:
            return {
                "URL": url,
                "ML_Prediction": ml_label,
                "Confidence(%)": round(ml_conf_pct, 2),
                "VirusTotal": "skipped (GSB flagged)",
                "SafeBrowsing": gsb_status,
                "Final_Classification": "Phishing"
            }

    # 2) VirusTotal - consult only if available and not flagged by GSB
    vt_result = None
    vt_status = "VT disabled"
    if vt_api_key:
        # check cap
        if (vt_call_cap is None) or (vt_calls_made["count"] < vt_call_cap):
            if url in vt_cache:
                vt_result, vt_status = vt_cache[url]
            else:
                vt_result, vt_status = check_virustotal(vt_api_key, url)
                vt_cache[url] = (vt_result, vt_status)
                vt_calls_made["count"] += 1
                # throttle to respect VT free limits
                time.sleep(VT_DELAY_SEC)
            # If VT reports positives -> malicious
            if isinstance(vt_result, dict) and vt_result.get("positives", 0) > 0:
                return {
                    "URL": url,
                    "ML_Prediction": ml_label,
                    "Confidence(%)": round(ml_conf_pct, 2),
                    "VirusTotal": vt_status,
                    "SafeBrowsing": gsb_status,
                    "Final_Classification": "Phishing"
                }
        else:
            vt_status = "VT call cap reached"

    # If neither external flagged, decide using ML but be conservative:
    # If ML label is Benign -> Benign. Otherwise require high ML confidence to mark malicious.
    if ml_label == "Benign":
        final = "Benign"
    else:
        final = ml_label if (ml_conf_pct >= model_threshold * 100.0) else "Needs Manual Review"

    return {
        "URL": url,
        "ML_Prediction": ml_label,
        "Confidence(%)": round(ml_conf_pct, 2),
        "VirusTotal": vt_status,
        "SafeBrowsing": gsb_status,
        "Final_Classification": final
    }

# ------------------- Bulk scanner (uses classify_url + caching) -------------------
def fast_bulk_scan(
    urls,
    model,
    model_threshold: float = 0.80,
    vt_api_key: Optional[str] = None,
    gsb_api_key: Optional[str] = None,
    vt_call_cap: Optional[int] = VT_CALL_CAP_DEFAULT,
    progress_callback=None
):
    urls = list(urls)
    n = len(urls)
    if n == 0:
        return []

    vt_cache: Dict[str, Tuple[Optional[Dict[str,Any]], str]] = {}
    gsb_cache: Dict[str, Tuple[Optional[bool], str]] = {}
    vt_calls_made = {"count": 0}
    results = []

    for i, url in enumerate(urls, start=1):
        if progress_callback:
            progress_callback((i - 1) / n, f"Scanning {i}/{n}")

        res = classify_url(
            url,
            model,
            vt_api_key=vt_api_key,
            gsb_api_key=gsb_api_key,
            vt_cache=vt_cache,
            gsb_cache=gsb_cache,
            vt_call_cap=vt_call_cap,
            vt_calls_made=vt_calls_made,
            model_threshold=model_threshold
        )
        results.append(res)

    if progress_callback:
        progress_callback(1.0, "Completed")

    return results

# ------------------- Streamlit UI (single file with sidebar navigation) -------------------
st.set_page_config(page_title="Malicious URL Scanner", page_icon="🛡️", layout="wide")
st.title("🛡️ Malicious URL Scanner")

# Sidebar navigation
st.sidebar.title("Mode")
mode = st.sidebar.radio("Choose mode:", ["🔗 Single URL Scan", "📂 Bulk URL Analysis"])
st.sidebar.markdown("---")
st.sidebar.write("Model suspicion threshold (used when VT/GSB are not conclusive)")
model_threshold_input = st.sidebar.slider("Model threshold (%)", min_value=50, max_value=99, value=80)

# Single URL Scan
if mode == "🔗 Single URL Scan":
    st.header("🔗 Single URL Scan")
    url_input = st.text_input("Enter a URL to scan:")
    if st.button("🔍 Scan URL"):
        if not url_input:
            st.warning("Please enter a valid URL.")
        else:
            with st.spinner("Scanning..."):
                res = classify_url(
                    url_input,
                    model,
                    vt_api_key=VT_API_KEY,
                    gsb_api_key=GSB_API_KEY,
                    vt_call_cap=VT_CALL_CAP_DEFAULT,
                    model_threshold=(model_threshold_input / 100.0)
                )
            st.write("### Result")
            st.json(res)
            fc = res.get("Final_Classification", "")
            if fc == "Benign":
                st.success("✅ This URL appears safe.")
            elif "Phishing" in fc or "Malicious" in fc:
                st.error("⚠️ This URL may be malicious. Avoid it.")
            elif "Needs Manual Review" in fc:
                st.info("ℹ️ Needs manual review.")
            else:
                st.warning(fc)

# Bulk CSV Analysis
else:
    st.header("📂 Bulk URL Analysis")
    st.markdown("Upload a CSV with a column named `url`. The app will run ML, then consult GSB and VT when necessary.")
    uploaded = st.file_uploader("Upload CSV with column 'url'", type=["csv"])
    vt_cap = st.number_input("VT call cap (per run)", min_value=0, max_value=10000, value=VT_CALL_CAP_DEFAULT, step=10)
    if uploaded:
        try:
            df_in = pd.read_csv(uploaded)
            if 'url' not in df_in.columns:
                st.error("CSV must contain a column named 'url'.")
            else:
                urls = df_in['url'].dropna().astype(str).tolist()

                progress_bar = st.progress(0)
                status = st.empty()

                def progress_hook(frac, message=None):
                    try:
                        progress_bar.progress(min(max(int(frac * 100), 0), 100))
                    except Exception:
                        pass
                    if message:
                        status.text(message)

                with st.spinner("Running bulk scan..."):
                    results = fast_bulk_scan(
                        urls,
                        model,
                        model_threshold=(model_threshold_input / 100.0),
                        vt_api_key=VT_API_KEY,
                        gsb_api_key=GSB_API_KEY,
                        vt_call_cap=int(vt_cap),
                        progress_callback=progress_hook
                    )

                progress_bar.progress(100)
                status.text("Completed")

                results_df = pd.DataFrame(results)

                st.subheader("Quick Summary")
                if 'Final_Classification' in results_df.columns and not results_df.empty:
                    st.write(results_df['Final_Classification'].value_counts())
                else:
                    st.write("No results to show.")

                # Plotly pie chart summary (no matplotlib needed)
                if not results_df.empty and 'Final_Classification' in results_df.columns:
                    summary_counts = results_df['Final_Classification'].value_counts().reset_index()
                    summary_counts.columns = ["Classification", "Count"]
                    fig = px.pie(summary_counts, names="Classification", values="Count",
                                 title="Final Classification Distribution", hole=0.3)
                    st.plotly_chart(fig, use_container_width=True)

                st.subheader("Detailed Results")
                st.dataframe(results_df)

                csv_bytes = results_df.to_csv(index=False).encode("utf-8")
                st.download_button("⬇️ Download Detailed Report", csv_bytes,
                                   "url_analysis_report.csv", "text/csv")
        except Exception as e:
            st.error(f"Bulk scan failed: {e}")
