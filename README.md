# URL CLASSIFICATION

## Overview
This project focuses on detecting phishing URLs using machine learning techniques and WHOIS data. Phishing attacks pose a significant threat to cybersecurity, and detecting malicious URLs is crucial for protecting users from potential harm. By leveraging WHOIS data and various lexical features extracted from URLs, this project aims to develop an effective phishing URL detection system.

## Dataset
- **Original Dataset**: The original dataset contains URLs labeled as phishing or benign, sourced from various sources, the raw datasetcan be downloaded at https://research.aalto.fi/en/datasets/phishstorm-phishing-legitimate-url-dataset
- **Cleaning**: Irrelevant columns are removed, duplicates are eliminated, and the dataset is split into phishing and benign URLs.
- **WHOIS Verification**: WHOIS data is used to verify the legitimacy of URLs, filtering out unreachable or invalid URLs.

## Features Extraction
- **WHOIS Data**: WHOIS information is retrieved for each URL to extract features such as registration date, expiration date, and last updated date.
- **Lexical Features**: Various lexical features such as dot count, URL length, digit count, special character count, hyphen count, and protocol are extracted from the URLs.

## Feature Selection
- **WHOIS Verification**: URLs are verified using WHOIS data, and only verified URLs are included in the analysis.
- **Lexical Features**: Relevant lexical features are selected for training the machine learning models.

## Machine Learning Models
Several machine learning algorithms are trained and evaluated for phishing URL detection:
1. **Decision Tree**
2. **K-Nearest Neighbors (KNN)**
3. **Kernel SVM**
4. **Logistic Regression**
5. **Naive Bayes**
6. **Random Forest**
7. **Support Vector Machine (SVM)**

## Evaluation
- The performance of each model is evaluated using metrics such as accuracy, confusion matrix, precision, recall, and F1-score.
- Cross-validation and hyperparameter tuning techniques are employed to optimize model performance.

## Results
- The results of each model are presented, highlighting their performance in detecting phishing URLs.
- Comparison of different machine learning algorithms helps identify the most effective approach for phishing URL detection.

## Future Work
- Optimization: Continuously optimize machine learning models to improve detection accuracy and reduce false positives.
- Real-time Detection: Implement the detection system in real-time to prevent users from accessing phishing URLs.
- Integration: Integrate the detection system with web browsers and email clients for seamless protection against phishing attacks.


