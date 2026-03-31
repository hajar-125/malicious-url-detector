import pandas as pd
import re
import tldextract
import whois
from urllib.parse import urlparse
from datetime import datetime
import os

class FeatureExtractor:
    def __init__(self):
        #we will initialize state here with loading a list of known shorteners
        self.shortening_services= r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net"

    def extract_lexical(self, url):
        #in this function we will extract all string based features
        features= {}
        try:
            parsed_url= urlparse(url)
            ext= tldextract.extract(url)
            domain= ext.domain

            features['url_length']= len(url)
            features['hostname_length']= len(parsed_url.netloc)
            features['path_length']= len(parsed_url.path)

            features['count_dot']= url.count('.')
            features['count_hyphen']= url.count('-')
            features['count_at']= url.count('@')
            features['count_question']= url.count('?')
            features['count_equals']= url.count('=')
            features['count_digits']= sum(c.isdigit() for c in url)

            features['is_https']= 1 if parsed_url.scheme == 'https' else 0
            features['has_ip']= 1 if re.search(
                r'(([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\/)|'  # IPv4
                r'((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*', url) else 0
            features['is_shortened']= 1 if re.search(self.shortening_services, parsed_url.netloc) else 0

        except Exception as e: 
            features = {k: 0 for k in ['url_length', 'hostname_length', 'path_length', 'count_dot', 'count_hyphen', 'count_at', 'count_question', 'count_equals', 'count_digits', 'is_https', 'has_ip', 'is_shortened']}

        return features
    
    def extract_domain_ages(self, url):
        #this function will help us extract the domain age of the url using WHOIS data
        
        try: 
            domain= tldextract.extract(url).registered_domain
            w = whois.whois(domain)

            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date= creation_date[0]
            
            if isinstance(creation_date, datetime):
                age= (datetime.now() - creation_date).days
                return {'domain_age_days': age}
            else:
                return {'domain_age_days': -1}
        except Exception: 
            return {'domain_age_days': -1}
        
    def process_url(self, url, include_whois=False):
        features= self.extract_lexical(url)

        if include_whois:
            features.update(self.extract_domain_ages(url))

        return features

def build_dataset(input_csv, output_csv, sample_size=None):
    print("we are loading the raw data...")
    df= pd.read_csv(input_csv)

    exctractor= FeatureExtractor()
    feature_list= []

    batch_size = 1000
    batch_buffer = []

    print("doing the work...")
    for index, row in df.iterrows():
        url = row['url']
        label = row['label']

        feats= exctractor.process_url(url, include_whois=False)
        feats['label']=label

        batch_buffer.append(feats)

        if len(batch_buffer) >= batch_size:
            temp_df = pd.DataFrame(batch_buffer)
            write_header = not os.path.isfile(output_csv)
            temp_df.to_csv(output_csv, mode='a', header=write_header, index=False)
            
            print(f"Saved batch. Processed up to row {index + 1}...")

            batch_buffer = []
            
    if batch_buffer:
        temp_df = pd.DataFrame(batch_buffer)
        write_header = not os.path.isfile(output_csv)
        temp_df.to_csv(output_csv, mode='a', header=write_header, index=False)
        print("Saved final batch.")

if __name__ == "__main__":
    build_dataset("phishing_dataset.csv", "dataset_final.csv", sample_size=5000)