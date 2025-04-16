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
src_input = st.text_input("Enter source for URL:")


# Load model
@st.cache_resource
def load_artifacts():
    model = load_model(r"E:\New folder\project2\malicious_url_detector.h5")
    #print(model.summary())
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
import re

def url_has_login(url):
    return int('login' in url.lower())


    
def url_has_client(url):
    return int('client' in url.lower())

def url_has_server(url):
    return int('server' in url.lower())

def url_has_admin(url):
    return int('admin' in url.lower())

def url_has_ip(url):
    # IP address in the domain (e.g., http://192.168.1.1/login)
    match = re.search(r'((\d{1,3}\.){3}\d{1,3})', url)
    return int(bool(match))

def url_isshorted(url):
    shorteners = [
        'bit.ly', 'goo.gl', 'tinyurl.com', 'ow.ly', 'is.gd', 'buff.ly',
        'adf.ly', 'bit.do', 't.co', 'cutt.ly', 'shorturl.at'
    ]
    for shortener in shorteners:
        if shortener in url.lower():
            return 1
    return 0


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
def extract_features(url, source):
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
        'url': url,
        'source': source,  # define this if needed
        'url_has_login': url_has_login(url),
        'url_has_client': url_has_client(url),
        'url_has_server': url_has_server(url),
        'url_has_admin': url_has_admin(url),
        'url_has_ip': url_has_ip(url),
        'url_isshorted': url_isshorted(url),
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
        'tld': tld,
        'tld_is_sus': tld_is_sus(url, [
    'com', 'org', 'net', 'edu', 'gov', 'mil', 'int',
    'in', 'uk', 'us', 'ca', 'de', 'fr', 'au', 'jp', 'nz',
    'ch', 'it', 'es', 'nl', 'se', 'no', 'fi', 'br', 'cn',
    'kr', 'ru', 'za', 'ae', 'ie', 'sg', 'hk', 'my', 'id',
    'ph', 'pl', 'be', 'at', 'cz', 'dk', 'gr', 'pt', 'mx',
    'tr', 'sa', 'ar', 'co', 'th', 'vn', 'tw', 'il'
]),
        'pdomain_min_distance':pdomain_min_distance(url, trusted_domains),
        'subdomain_len': subdomain_len(url),
        'subdomain_count_dot': subdomain_count_dot(url)
    }
    # Convert the features dictionary to a DataFrame
    features_df = pd.DataFrame([features])
     # Convert the features dictionary to a DataFrame
    features_df = pd.DataFrame([features])
    
    # Remove non-numeric columns for prediction
    numeric_features = features_df.drop(['url', 'source', 'tld'], axis=1, errors='ignore')
    
    # Ensure all values are numeric
    numeric_features = numeric_features.apply(pd.to_numeric, errors='coerce').fillna(0)
    
    print(features_df)  # Keep this for debugging
    
    return numeric_features
    # # Pad or truncate the DataFrame to ensure it has exactly 56 columns
    # if features_df.shape[1] < 59:
    #     # Pad with zeros if the DataFrame has fewer than 56 columns
    #     for i in range(59 - features_df.shape[1]):
    #         features_df[f'padding_{i}'] = 0.0  # Padding with float values
    # elif features_df.shape[1] > 59:
    #     # Truncate if the DataFrame has more than 56 columns
    #     features_df = features_df.iloc[:, :59]

    # Ensure all values are numeric
    # features_df = features_df.apply(pd.to_numeric, errors='coerce').fillna(0)
    
    # print(features_df)

if url_input and src_input:
    try:
        features = extract_features(url_input, src_input)
        print("Extracted Features:")
        print(features)  # ← Add this
        print(features.shape)  # ← Verify shape matches model input
        
        pred = model.predict(features)[0][0]
        print("\nRaw Prediction Value:", pred)  # ← Add this
        
        if pred ==1:
            st.error("🚨 This URL is **Malicious**")
        else:
            st.success("✅ This URL is **Safe**")
    except Exception as e:
        st.warning(f"Error: {e}")
