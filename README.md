# 🔒 Malicious URL Detector

A deep learning-based system for detecting malicious URLs using feature extraction and neural network classification.  This project was developed for AI Lab and achieves **94. 07% validation accuracy** in identifying potentially harmful web addresses.

## 📋 Table of Contents
- [Overview](#overview)
- [Features](#features)
- [Model Architecture](#model-architecture)
- [Dataset](#dataset)
- [Installation](#installation)
- [Usage](#usage)
- [Project Structure](#project-structure)
- [Performance Metrics](#performance-metrics)
- [Technologies Used](#technologies-used)
- [Future Improvements](#future-improvements)

## 🎯 Overview

This project implements a malicious URL detection system that analyzes **59 distinct features** extracted from URLs to classify them as either safe or malicious. The system provides robust defense against phishing attempts, malware distribution, and other web-based threats.

### Key Highlights
- **94% Accuracy** on test dataset
- **AUC Score:  0.95** demonstrating excellent classification performance
- Real-time URL analysis through interactive web interface
- Trained on **6. 7 million URLs** from multiple sources (PhishTank, Majestic Million, etc.)

## ✨ Features

The system extracts and analyzes multiple categories of features:

### URL-Level Features
- **Length & Entropy**: URL length, character entropy, unique character ratios
- **Special Characters**: Counts of dots, hyphens, @, %, #, semicolons, underscores
- **Protocol Analysis**: HTTP/HTTPS detection and counting
- **Suspicious Keywords**: Detection of 'login', 'admin', 'client', 'server', 'bank', 'secure'
- **URL Shorteners**: Detection of bit.ly, goo.gl, tinyurl, etc.
- **IP Address Detection**: Identifies URLs using raw IP addresses

### Domain Features
- **Primary Domain Analysis**: Length, hyphen count, special character analysis
- **TLD Validation**: Checks against trusted top-level domains (com, org, edu, gov, etc.)
- **Domain Distance**: Levenshtein distance from trusted domains (google.com, amazon.com, etc.)
- **Subdomain Analysis**: Length and complexity metrics

### Path & Query Features
- **Path Analysis**:  Directory depth, sensitive word detection, character case analysis
- **Query Parameters**: Component counting and structure analysis
- **Encoding Detection**: Identifies suspicious encoding patterns (%20, etc.)

### Advanced Features
- **Hamming Bit Patterns**: Binary representation analysis (00, 01, 10, 11 patterns)
- **N-gram Entropy**: 2-gram and 3-gram entropy calculations
- **Financial Keywords**: Detection of payment/banking-related terms

## 🧠 Model Architecture

### Deep Neural Network
```
Input Layer (59 features)
    ↓
Dense Layer (256 neurons, ReLU)
    ↓
Dropout (30%)
    ↓
Dense Layer (128 neurons, ReLU)
    ↓
Dropout (20%)
    ↓
Dense Layer (64 neurons, ReLU)
    ↓
Output Layer (1 neuron, Sigmoid)
```

### Training Configuration
- **Optimizer**: Adam
- **Loss Function**: Binary Crossentropy
- **Batch Size**: 512
- **Epochs**: 20 (with early stopping)
- **Validation Split**: 20%
- **Early Stopping**: Patience of 3 epochs

## 📊 Dataset

The model was trained on a comprehensive dataset containing:
- **Total URLs**: ~6.7 million
- **Malicious URLs**: ~1.4 million (21.5%)
- **Benign URLs**: ~5.3 million (78.5%)

### Data Sources
- PhishTank (phishing URLs)
- Majestic Million (legitimate popular sites)
- DMOZ/Harvard (curated legitimate URLs)
- Custom collected malicious samples

## 🚀 Installation

### Prerequisites
- Python 3.8+
- pip package manager

### Setup

1. **Clone the repository**
```bash
git clone https://github.com/KATHAN-VYAS/malicious_URL_detector.git
cd malicious_URL_detector
```

2. **Install dependencies**
```bash
pip install -r requirements.txt
```

### Required Packages
```
streamlit
tensorflow
numpy
pandas
joblib
tldextract
python-Levenshtein
scikit-learn
matplotlib
seaborn
```

## 💻 Usage

### Running the Web Application

Launch the Streamlit web interface: 
```bash
streamlit run front_end.py
```

The application will open in your browser where you can:
1. Enter a URL to analyze
2. Provide the source of the URL (optional)
3. Get instant classification (Safe ✅ or Malicious 🚨)

### Example Usage

```
URL Input: http://bit.ly/secure-bank-login-verify-account
Source: Email Link

Result:  🚨 This URL is Malicious
```

### Using the Model Programmatically

```python
from tensorflow.keras.models import load_model
import joblib
import numpy as np

# Load model
model = load_model("malicious_url_detector.h5")

# Extract features (use functions from front_end.py)
features = extract_features(url, source)

# Predict
prediction = model.predict(features)[0][0]

if prediction == 1:
    print("🚨 Malicious URL detected!")
else:
    print("✅ URL appears safe")
```

## 📁 Project Structure

```
malicious_URL_detector/
│
├── front_end.py                    # Streamlit web application
├── general_model.ipynb             # Main model training notebook
├── NLP_model1.ipynb                # NLP feature extraction experiments
│
├── malicious_url_detector.h5       # Trained deep learning model
├── tfidf_vectorizer.pkl            # TF-IDF vectorizer for NLP features
│
├── requirements.txt                # Python dependencies
├── tld-list-details.csv            # Top-level domain reference data
│
└── README.md                       # Project documentation
```

## 📈 Performance Metrics

### Classification Report
```
              precision    recall  f1-score   support

           0       0.94      0.99      0.96   1584986
           1       0.94      0.78      0.85    433669

    accuracy                           0.94   2018655
   macro avg       0.94      0.88      0.91   2018655
weighted avg       0.94      0.94      0.94   2018655
```

### Confusion Matrix
```
[[1562203   22783]     True Negatives: 1,562,203
 [  95540  338129]]    False Positives: 22,783
                       False Negatives: 95,540
                       True Positives: 338,129
```

### Key Metrics
- **Accuracy**: 94.07%
- **Precision**: 94% (both classes)
- **AUC-ROC**: 0.9502
- **F1-Score**: 0.96 (benign), 0.85 (malicious)

## 🛠️ Technologies Used

### Machine Learning & Deep Learning
- **TensorFlow/Keras**: Neural network implementation
- **Scikit-learn**: Data preprocessing, feature scaling, metrics

### Web Framework
- **Streamlit**: Interactive web interface

### Data Processing
- **Pandas**: Data manipulation
- **NumPy**: Numerical operations

### Feature Extraction
- **tldextract**: Domain parsing
- **python-Levenshtein**: String distance calculations
- **urllib**:  URL parsing

### Visualization
- **Matplotlib**: Training history plots
- **Seaborn**: Correlation heatmaps

## 🔮 Future Improvements

- [ ] Real-time URL reputation checking via external APIs
- [ ] Ensemble model combining deep learning with Random Forest
- [ ] WHOIS data integration for domain age analysis
- [ ] SSL certificate validation
- [ ] User feedback mechanism for continuous learning
- [ ] Browser extension for real-time protection
- [ ] API endpoint for integration with other security tools
- [ ] Multi-language URL support
- [ ] Historical tracking of URL reputation changes

## 📝 Model Training Notes

The deep learning model was trained with:
- **StandardScaler** for feature normalization
- **Early stopping** to prevent overfitting
- **Dropout layers** for regularization
- **20 epochs** with validation monitoring

Training time: ~4 hours on dataset of 6.7M URLs

## 🤝 Contributing

Contributions are welcome! Feel free to:
- Report bugs
- Suggest new features
- Submit pull requests
- Improve documentation

## 📄 License

This project is open source and available under the MIT License. 

## 👨‍💻 Author

**Kathan Vyas**
- GitHub: [@KATHAN-VYAS](https://github.com/KATHAN-VYAS)

## 🙏 Acknowledgments

- PhishTank for malicious URL data
- Majestic Million for legitimate URL dataset
- AI Lab for project guidance and support

---

**Note**: This model is designed for educational and research purposes.  For production use, consider additional security layers and regular model updates with fresh threat intelligence. 

## 📞 Contact

For questions or collaboration opportunities, please open an issue in this repository.

---

⭐ If you found this project helpful, please consider giving it a star! 
