import streamlit as st
from tensorflow.keras.models import load_model
import numpy as np
import pandas as pd
import joblib
import tldextract
import re
import warnings
from math import log2
from urllib.parse import urlparse, parse_qs
from collections import Counter
from Levenshtein import distance as levenshtein

warnings.filterwarnings("ignore", category=UserWarning)

# UI setup
st.set_page_config(page_title="Malicious URL Detector", layout="centered")
st.title("🔒 Malicious URL Detection")
st.write("Paste a URL to check if it's **Safe** or **Malicious**")

url_input = st.text_input("Enter a URL:")

# Load model
@st.cache_resource
def load_artifacts():
    model = load_model(r"E:\New folder\project2\malicious_url_detector.h5")
    return model

model = load_artifacts()

# Feature extraction functions
def hamming_bit_patterns(url):
    counts = {'00': 0, '01': 0, '10': 0, '11': 0}
    bin_list = [format(ord(c), '08b') for c in url]

    for i in range(len(bin_list) - 1):
        for b1, b2 in zip(bin_list[i], bin_list[i+1]):
            pair = b1 + b2
            if pair in counts:
                counts[pair] += 1

    total_pairs = sum(counts.values())
    if total_pairs == 0:
        return [0, 0, 0, 0, 0]

    hamming_1 = (counts['00'] + counts['11']) / total_pairs  # same bits
    hamming_00 = counts['00'] / total_pairs
    hamming_10 = counts['10'] / total_pairs
    hamming_01 = counts['01'] / total_pairs
    hamming_11 = counts['11'] / total_pairs

    return [hamming_1, hamming_00, hamming_10, hamming_01, hamming_11]

def ngram_entropy(url, n=2):
    if len(url) < n:
        return 0.0
    ngrams = [url[i:i+n] for i in range(len(url) - n + 1)]
    count = Counter(ngrams)
    total = len(ngrams)
    return -sum((c / total) * log2(c / total) for c in count.values())
# Prediction
trusted_tlds = ['com', 'org', 'net', 'int', 'edu', 'gov', 'mil']
trusted_domains = ['amazon.com', 'google.com', 'youtube.com', 'facebook.com', 'twitter.com']


def url_count_sensitive_words(url):
    sensitive_words = [
        # Financial keywords
        'account', 'bank', 'credit', 'debit', 'ssn', 'pin', 'tax', 'loan', 'payment', 'finance',
        # General sensitive keywords
        'login', 'admin', 'secure', 'verify', 'update', 'password', 'auth', 'token', 'pay',
        'id', 'user', 'credentials', 'security', 'billing', 'wallet', 'transaction', 'bitcoin',
        'alert', 'emergency', 'confirm'
    ]
    url_lower = url.lower()
    return sum(1 for word in sensitive_words if word in url_lower)

def tld_is_sus(url, trusted_tlds):
    ext = tldextract.extract(url)
    return int(ext.suffix not in trusted_tlds)

def pdomain_min_distance(url, trusted_domains):
    ext = tldextract.extract(url)
    return min(levenshtein(ext.domain, d) for d in trusted_domains)

def subdomain_len(url):
    ext = tldextract.extract(url)
    return len(ext.subdomain)

def subdomain_count_dot(url):
    ext = tldextract.extract(url)
    return ext.subdomain.count('.') if ext.subdomain else 0
  
# Feature extraction function
def extract_features(url):
    parsed = urlparse(url)
    path = parsed.path
    query = parsed.query
    pdomain = parsed.netloc.split(':')[0].split('@')[-1].split('.')
    tld = parsed.netloc.split('.')[-1] if '.' in parsed.netloc else ''
    path_components = [p for p in path.split('/') if p]

    hamming_1, hamming_00, hamming_10, hamming_01, hamming_11 = hamming_bit_patterns(url)
    _2bentropy = ngram_entropy(url, 2)
    _3bentropy = ngram_entropy(url, 3)
    url_lower = url.lower()
    url_count_sensitive_financial_words = len([pattern for pattern in [r'login', r'secure', r'account', r'bank', r'payment', r'credit', r'debit', r'finance', r'investment', r'insurance'] if re.search(pattern, url_lower)])

    features = {
        'url_len': len(url),
        'url_entropy': len(set(url)) / len(url) if len(url) > 0 else 0,
        'url_hamming_1': hamming_1,
        'url_hamming_00': hamming_00,
        'url_hamming_10': hamming_10,
        'url_hamming_01': hamming_01,
        'url_hamming_11': hamming_11,
        'url_2bentropy': _2bentropy,
        'url_3bentropy': _3bentropy,
        'url_count_dot': url.count('.'),
        'url_count_https': url.lower().count('https'),
        'url_count_http': url.lower().count('http'),
        "url_count_perc": url.count("%"),
        "url_count_hyphen": url.count("-"),
        'url_count_www': url.lower().count('www'),
        'url_count_atrate': url.count('@'),
        'url_count_hash': url.count('#'),
        'url_count_semicolon': url.count(';'),
        'url_count_underscore': url.count('_'),
        'url_count_ques': url.count('?'),
        'url_count_equal': url.count('='),
        'url_count_amp': url.count('&'),
        'url_count_letter': sum(c.isalpha() for c in url),
        'url_count_digit': sum(c.isdigit() for c in url),
        'url_count_sensitive_financial_words': url_count_sensitive_financial_words,
        'url_count_sensitive_words': url_count_sensitive_words(url),
        'url_nunique_chars_ratio': len(set(url)) / len(url) if url else 0,
        'path_len': len(path),
        'path_count_no_of_dir': path.count('/'),
        'path_count_no_of_embed': path.count('<embed>'),
        'path_count_zero': path.count('0'),
        'path_count_pertwent': path.count('%20'),
        'path_has_any_sensitive_words': int(any(word in path.lower() for word in ['login', 'admin', 'bank', 'secure', 'account'])),
        'path_count_lower': sum(c.islower() for c in path),
        'path_count_upper': sum(c.isupper() for c in path),
        'path_count_nonascii': sum(1 for c in path if ord(c) > 127),
        'path_has_singlechardir': int(any(len(comp) == 1 for comp in path_components)),
        'path_has_upperdir': int('..' in path_components),
        'query_len': len(query),
        'query_count_components': len(parse_qs(query)),
        'pdomain_len': len(parsed.netloc),
        'pdomain_count_hyphen': parsed.netloc.count('-'),
        'pdomain_count_atrate': parsed.netloc.count('@'),
        'pdomain_count_non_alphanum': sum(1 for c in parsed.netloc if not c.isalnum()),
        'pdomain_count_digit': sum(c.isdigit() for c in parsed.netloc),
        'tld_len': len(tld),
        'tld_is_sus': tld_is_sus(url, []),  # Replace [] with your trusted TLDs list
        'subdomain_len': subdomain_len(url),
        'subdomain_count_dot': subdomain_count_dot(url)
    }
    # Convert the features dictionary to a DataFrame
    features_df = pd.DataFrame([features])

    # Pad or truncate the DataFrame to ensure it has exactly 56 columns
    if features_df.shape[1] < 56:
        # Pad with zeros if the DataFrame has fewer than 56 columns
        for i in range(56 - features_df.shape[1]):
            features_df[f'padding_{i}'] = 0.0  # Padding with float values
    elif features_df.shape[1] > 56:
        # Truncate if the DataFrame has more than 56 columns
        features_df = features_df.iloc[:, :56]

    # Ensure all values are numeric
    features_df = features_df.apply(pd.to_numeric, errors='coerce').fillna(0)

    return features_df


if url_input:
    try:
        features = extract_features(url_input)
        pred = model.predict(features)[0][0]
        print(pred)
        if pred > 0.5:
            st.error("🚨 This URL is **Malicious**")
        else:
            st.success("✅ This URL is **Safe**")
    except Exception as e:
        st.warning(f"Error: {e}")
