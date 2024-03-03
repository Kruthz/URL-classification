!pip install python-whois
!pip install tldextract
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import whois
import datetime
from os.path import splitext
import tldextract
from urllib.parse import urlparse
from google.colab import drive
import os
#loading dataset
urldata = pd.read_csv("../Data/RawDataset/urldata.csv",encoding = "ISO-8859-1")
urldata.head()
urldata.shape
#taking only required columns into a new Dataframe
urldata = urldata.filter(['domain','label'],axis=1)
urldata.head()
urldata.tail()
urldata.shape
#Checking for NULL values
urldata.duplicated().sum()
#removing duplicates
urldata = urldata.drop_duplicates()
urldata.shape
urldata.to_csv("../Data/CleanedDataset/preprocessed_urldata.csv",index=False)
drive.mount('/content/drive/')
os.chdir('/content/drive/My Drive/Colab Notebooks')
#loading dataset which contains 5000 phishing URLs and 5000 legitimate URLs
dataset = pd.read_csv("merged_whois_verified_urls.csv")
dataset.head()
dataset.shape
#function to perform whois on given url
def perform_whois(url):
    try:
        whois_result = whois.whois(url)
        return whois_result
    except Exception:
        return False
#function to fetch the website age in days using URL created_date
def get_registered_date_in_days(whois_result):
    if(whois_result!=False):
        created_date = whois_result.creation_date
        if((created_date is not None) and (type(created_date)!=str)):
            if(type(created_date)==list):
                created_date=created_date[0]
            today_date=datetime.datetime.now()
            days = (today_date-created_date).days
            return days
        else:
            return -1
    else:
        return -1
#function to fetch the website expiry date in days using URL expiration_date
def get_expiration_date_in_days(whois_result):
    if(whois_result!=False):
        expiration_date = whois_result.expiration_date
        if((expiration_date is not None) and (type(expiration_date)!=str)):
            if(type(expiration_date)==list):
                expiration_date = expiration_date[0]
            today_date=datetime.datetime.now()
            days = (expiration_date-today_date).days
            return days
        else:
            return -1
    else:
        return -1
  #function to fetch the website's last updated date in days using URL updated_date
def get_updated_date_in_days(whois_result):
    if(whois_result!=False):
        updated_date = whois_result.updated_date
        if((updated_date is not None) and (type(updated_date)!=str)):
            if(type(updated_date)==list):
                updated_date = updated_date[0]
            today_date=datetime.datetime.now()
            days = (today_date-updated_date).days
            return days
        else:
            return -1
    else:
        return -1
def get_dot_count(url):
    return url.count('.')
def get_url_length(url):
    return len(url)
def get_digit_count(url):
    return sum(c.isdigit() for c in url)
def get_special_char_count(url):
    count = 0
    special_characters = [';','+=','_','?','=','&','[',']']
    for each_letter in url:
        if each_letter in special_characters:
            count = count + 1
    return count
def get_hyphen_count(url):
    return url.count('-')
def get_double_slash(url):
    return url.count('//')
def get_single_slash(url):
    return url.count('/')
def get_at_the_rate(url):
    return url.count('@')
def get_protocol(url):
    protocol = urlparse(url)
    if(protocol.scheme == 'http'):
        return 1
    else:
        return 0
def get_protocol_count(url):
    http_count = url.count('http')
    https_count = url.count('https')
    http_count = http_count - https_count #correcting the miscount of https as http
    return (http_count + https_count)
registered_date_in_days = []
expiration_date_in_days = []
updated_date_in_days = []
dotCount = []
urlLength = []
digitCount = []
specialCharCount = []
hyphenCount = []
doubleSlashCount = []
singleSlashCount = []
atTheRateCount = []
protocol = []
protocolCount = []
def extract_all_features():
    counter = 0
    for url in dataset['url']:
        counter = counter + 1
        print(counter)
        whois_result = perform_whois(url)
        #Extracting whois features from URLs
        registered_date_in_days.append(get_registered_date_in_days(whois_result))
        expiration_date_in_days.append(get_expiration_date_in_days(whois_result))
        updated_date_in_days.append(get_updated_date_in_days(whois_result))
        #Extracting lexical features from URLs
        dotCount.append(get_dot_count(url))
        urlLength.append(get_url_length(url))
        digitCount.append(get_digit_count(url))
        specialCharCount.append(get_special_char_count(url))
        hyphenCount.append(get_hyphen_count(url))
        doubleSlashCount.append(get_double_slash(url))
        singleSlashCount.append(get_single_slash(url))
        atTheRateCount.append(get_at_the_rate(url))
        protocol.append(get_protocol(url))
        protocolCount.append(get_protocol_count(url))
extract_all_features()
print(f'Registered Date list length               : {len(registered_date_in_days)}')
print(f'Expiration Date list length               : {len(expiration_date_in_days)}')
print(f'Updation Date list length                 : {len(updated_date_in_days)}')
print(f'Dot Count list length                     : {len(dotCount)}')
print(f'URL Length list length                    : {len(urlLength)}')
print(f'Digit Count list length                   : {len(digitCount)}')
print(f'Special Character Count list length       : {len(specialCharCount)}')
print(f'Hyphen Count list length                  : {len(hyphenCount)}')
print(f'Double Slash Count list length            : {len(doubleSlashCount)}')
print(f'Single Slash Count list length            : {len(singleSlashCount)}')
print(f'At the Rate(@) Count list length          : {len(atTheRateCount)}')
print(f'ProtocolName Count list length            : {len(protocol)}')
print(f'Protocol Count list length                : {len(protocolCount)}')
features_df = pd.DataFrame()
features_df['whois_regDate'] = registered_date_in_days
features_df['whois_expDate'] = expiration_date_in_days
features_df['whois_updatedDate'] = updated_date_in_days
features_df["dot_count"] = dotCount
features_df["url_len"] = urlLength
features_df["digit_count"] = digitCount
features_df["special_count"] = specialCharCount
features_df["hyphen_count"] = hyphenCount
features_df["double_slash"] = doubleSlashCount
features_df["single_slash"] = singleSlashCount
features_df["at_the_rate"] = atTheRateCount
features_df["protocol"] = protocol
features_df["protocol_count"] = protocolCount
features_df.head()
features_df.shape
features_df.to_csv("features.csv",index=False)
urldata = pd.read_csv('../Data/CleanedDataset/preprocessed_urldata.csv',encoding = "ISO-8859-1")
len(urldata)
#this function performs whois and returns true to those urls which are reachable through whois
def performwhois(url):
    try:
        result = whois.whois(url)
        return True #success
    except Exception:
        return False #error
benign_sample = urldata['domain'][48000:95000]
len(benign_sample)
type(benign_sample)
benign_sample.head()
benign_urls = []
counter = 0
for url in benign_sample:
    if performwhois(url):
        counter = counter + 1
        print(counter)
        benign_urls.append(url)
len(benign_urls)
benign_df = pd.DataFrame()
benign_df['url'] = benign_urls
benign_df['label'] = 0
benign_df.head()
benign_df.to_csv("../Data/CleanedDataset/whois_verified_benign_urls.csv",index=False)
import numpy as np
import pandas as pd
import whois
urldata = pd.read_csv('../Data/CleanedDataset/preprocessed_urldata.csv',encoding = "ISO-8859-1")
len(urldata)
#this function performs whois and returns true to those urls which are reachable through whois
def performwhois(url):
    try:
        result = whois.whois(url)
        return True #success
    except Exception:
        return False #error
phishing_sample = urldata['domain'][:40000]
len(phishing_sample)
phishing_sample.head()
phishing_urls = []
counter = 0
for url in phishing_sample:
    if performwhois(url):
        print(counter)
        counter = counter + 1
        phishing_urls.append(url)
len(phishing_urls)
phishing_urls[0]
phishing_df = pd.DataFrame()
phishing_df["url"] = phishing_urls
phishing_df.head()
phishing_df["label"] = 1
phishing_df.head()
phishing_df.to_csv("../Data/CleanedDataset/whois_verified_phishing_urls.csv",index=False)
feature_dataset = pd.read_csv("../Data/FeaturesDataset/features.csv")
label_dataset = pd.read_csv("../Data/CleanedDataset/merged_whois_verified_urls.csv")
feature_dataset.head()
label_dataset.head()
X = feature_dataset.iloc[:,[0,1,2,3,4,5,6,7,8,9,10,12] ].values #not including protocol feature
y = label_dataset.iloc[:, [1]].values
print(f'X shape: {X.shape}')
print(f'y shape: {y.shape}')
from sklearn.model_selection import train_test_split
X_train,X_test,y_train,y_test = train_test_split(X,y,test_size=0.2,random_state=0)
print('X_train', X_train.shape)
print('X_test', X_test.shape)
print('y_train', y_train.shape)
print('y_test', y_test.shape)
from sklearn.preprocessing import StandardScaler
scaler = StandardScaler()
X_train = scaler.fit_transform(X_train)
X_test = scaler.transform(X_test)
def get_dt_results():
    from sklearn.tree import DecisionTreeClassifier
    classifier = DecisionTreeClassifier(criterion='entropy',random_state=0)
    classifier.fit(X_train,y_train)
    y_pred = classifier.predict(X_test)
    from sklearn.metrics import confusion_matrix,accuracy_score
    cm = confusion_matrix(y_test,y_pred)
    accuracy = accuracy_score(y_test,y_pred)
    result_dict = {"accuracy":accuracy,"cm":cm}
    return result_dict
def get_knn_results():
    #Fitting into KNN
    from sklearn.neighbors import KNeighborsClassifier
    classifier = KNeighborsClassifier(n_neighbors=5,metric='minkowski',p=2) #To select which method to use to calculate 
    #distance, we need to define metric first and then p value 1 for manhattan distance, 2 for euclidian distance
    classifier.fit(X_train,y_train)
    y_pred = classifier.predict(X_test)
    from sklearn.metrics import confusion_matrix,accuracy_score
    cm = confusion_matrix(y_test,y_pred)
    accuracy = accuracy_score(y_test,y_pred)
    result_dict = {"accuracy":accuracy,"cm":cm}
    return result_dict
    def get_kernel_SVM_results():
    from sklearn.svm import SVC
    classifier = SVC(kernel="rbf",random_state=0)
    classifier.fit(X_train,y_train)
    y_pred = classifier.predict(X_test)
    from sklearn.metrics import confusion_matrix,accuracy_score
    cm = confusion_matrix(y_test,y_pred)
    accuracy = accuracy_score(y_test,y_pred)
    result_dict = {"accuracy":accuracy,"cm":cm}
    return result_dict
def get_logistic_reg_results():
    from sklearn.linear_model import LogisticRegression
    classifier = LogisticRegression(random_state=0)
    classifier.fit(X_train,y_train)
    y_pred = classifier.predict(X_test)
    from sklearn.metrics import confusion_matrix,accuracy_score
    cm = confusion_matrix(y_test,y_pred)
    accuracy = accuracy_score(y_test,y_pred)
    result_dict = {"accuracy":accuracy,"cm":cm}
    return result_dict
def get_naive_bayes_results():
    from sklearn.naive_bayes import GaussianNB
    classifier = GaussianNB()
    classifier.fit(X_train,y_train)
    y_pred = classifier.predict(X_test)
    from sklearn.metrics import confusion_matrix,accuracy_score
    cm = confusion_matrix(y_test,y_pred)
    accuracy = accuracy_score(y_test,y_pred)
    result_dict = {"accuracy":accuracy,"cm":cm}
    return result_dict
def get_random_forest_results():
    from sklearn.ensemble import RandomForestClassifier
    classifier = RandomForestClassifier(n_estimators=20,criterion='entropy',random_state=0)
    classifier.fit(X_train,y_train)
    y_pred = classifier.predict(X_test)
    from sklearn.metrics import confusion_matrix,accuracy_score
    cm = confusion_matrix(y_test,y_pred)
    accuracy = accuracy_score(y_test,y_pred)
    result_dict = {"accuracy":accuracy,"cm":cm}
    return result_dict
def get_svm_results():
    #Fitting SVM to Training set
    from sklearn.svm import SVC
    classifier = SVC(kernel='linear',random_state=0)
    classifier.fit(X_train,y_train)
    y_pred = classifier.predict(X_test)
    from sklearn.metrics import confusion_matrix,accuracy_score
    cm = confusion_matrix(y_test,y_pred)
    accuracy = accuracy_score(y_test,y_pred)
    result_dict = {"accuracy":accuracy,"cm":cm}
    return result_dict
def get_classification_results():
    results_dict = {}
    dt = get_dt_results()
    knn = get_knn_results()
    kernelsvm = get_kernel_SVM_results()
    logreg = get_logistic_reg_results()
    nb = get_naive_bayes_results()
    rf = get_random_forest_results()
    svm = get_svm_results()
    results_dict = {"Decision Tree":dt,"KNN":knn,"Kernel SVM":kernelsvm,"Log Regression":logreg,"Naive Bayes":nb,"Random Forest":rf,"SVM":svm}
    #results_dict = {"Decision Tree":dt,"Kernel SVM":kernelsvm,"Random Forest":rf}
    return results_dict
classification_results = get_classification_results()
for k,v in classification_results.items():
    print(f"{k}: {v['accuracy'],v['cm']}")
phishing_urls_whois_verified = pd.read_csv("../Data/CleanedDataset/whois_verified_phishing_urls.csv")
benign_urls_whois_verified = pd.read_csv("../Data/CleanedDataset/whois_verified_benign_urls.csv")
phishing_urls_whois_verified.shape
benign_urls_whois_verified.shape
phishing_urls_whois_verified.head()
benign_urls_whois_verified.head()
phishing_urls_whois_verified_reduced = phishing_urls_whois_verified[:5000]
phishing_urls_whois_verified_reduced.shape
benign_urls_whois_verified_reduced = benign_urls_whois_verified[:5000]
benign_urls_whois_verified_reduced.shape
combined = pd.DataFrame()
combined = pd.concat([phishing_urls_whois_verified_reduced,benign_urls_whois_verified_reduced])
combined.shape
combined.to_csv("../Data/CleanedDataset/merged_whois_verified_urls.csv", index=False)
