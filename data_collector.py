import pandas as pd
import requests
import io
import zipfile
import os

MALICIOUS_URL = "http://data.phishtank.com/data/online-valid.csv" #from phishtank
BENIGN_URL = "https://tranco-list.eu/top-1m.csv.zip" # from tranco list 
DATASET_FILENAME = "phishing_dataset.csv"

def get_phishing_urls():
    print("downloading phishtank data...")

    headers= {'User-Agent': 'Mozilla/5.0 (DataScienceProject)'}
    try:
        response = requests.get(MALICIOUS_URL, headers=headers)
        response.raise_for_status()

        data=pd.read_csv(io.BytesIO(response.content))

        phishing_df = pd.DataFrame({'url': data['url']})
        phishing_df['label']= 1

        print("success loaded {len(phishing_df)} malicious URLs")
        return phishing_df
    
    except Exception as e:
        print("error {e}")
        return phishing_df
    
def get_benign_urls(num_to_fetch=10000):
    print("downloading tranco list data...")

    try:
        response = requests.get(BENIGN_URL, stream=True)
        z = zipfile.ZipFile(io.BytesIO(response.content))

        filename= z.namelist()[0]
        data = pd.read_csv(z.open(filename), header=None, names=['rank', 'domain'], nrows=num_to_fetch)

        legit_df=pd.DataFrame()
        legit_df['url']= 'http://'+ data['domain']
        legit_df['label']=0

        print("success loaded {len(legit_df)} benign URLs")
        return legit_df
    except Exception as e:
        print("error {e}")
        return legit_df
    
def main():
    phishing_df = get_phishing_urls()

    if phishing_df.empty:
        print("Failed to get phishing data. Exiting.")
        return
    
    url_needed = len(phishing_df)
    legit_df = get_benign_urls(url_needed)

    print("merging and shuffling datasets...")

    full_df = pd.concat([phishing_df, legit_df], ignore_index=True)
    full_df = full_df.sample(frac=1, random_state=42).reset_index(drop=True)

    full_df.to_csv(DATASET_FILENAME, index=False)
    print("process complete")

if __name__ == "__main__":
    main()



