import re
import pandas as pd
from urllib.parse import urlparse

def extract_features(url):
    def count_chars(url, chars):
        return [url.count(c) for c in chars]

    def abnormal_url(url):
        hostname = urlparse(url).hostname or ''
        return 1 if hostname not in url else 0

    def http_secure(url):
        return 1 if urlparse(url).scheme == 'https' else 0

    def digit_count(url):
        return sum(c.isdigit() for c in url)

    def letter_count(url):
        return sum(c.isalpha() for c in url)

    def shortening_service(url):
        pattern = r"(bit\.ly|goo\.gl|tinyurl|ow\.ly|t\.co|is\.gd|buff\.ly|cut\.ly|adf\.ly|bitly\.com)"
        return 1 if re.search(pattern, url) else 0

    def having_ip(url):
        pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        return 1 if re.search(pattern, url) else 0

    def contains_keywords(url):
        keywords = ['login', 'signin', 'verify', 'secure', 'account', 'update']
        return sum(keyword in url.lower() for keyword in keywords)

    def suspicious_tld(url):
        tlds = ['.tk', '.ml', '.ga', '.cf', '.gq']
        parsed = urlparse(url)
        return 1 if any(parsed.netloc.endswith(tld) for tld in tlds) else 0

    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    path = parsed_url.path
    query = parsed_url.query

    special_chars = ['@', '?', '-', '=', '.', '#', '%', '+', '$', '!', '*', ',', '//']
    special_char_counts = count_chars(url, special_chars)

    features = pd.DataFrame([[  
        len(url),                 # url_length
        len(domain),              # domain_length
        len(path),                # path_length
        len(query),               # query_length
        *special_char_counts,     # special chars
        abnormal_url(url),        # abnormal_url
        http_secure(url),         # https
        digit_count(url),         # digits
        letter_count(url),        # letters
        shortening_service(url),  # shortining_service (typo kept to match model)
        having_ip(url),           # having_ip_address
        contains_keywords(url),   # suspicious_words
        suspicious_tld(url)       # suspicious_tld
    ]], columns=[
        'url_length', 'domain_length', 'path_length', 'query_length',
        '@', '?', '-', '=', '.', '#', '%', '+', '$', '!', '*', ',', '//',
        'abnormal_url', 'https', 'digits', 'letters',
        'shortining_service', 'having_ip_address',
        'suspicious_words', 'suspicious_tld'
    ])

    return features
