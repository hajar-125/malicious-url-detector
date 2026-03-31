from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import xgboost as xgb
import pandas as pd
import numpy as np
from feature_extractor import FeatureExtractor
import os

app = FastAPI(title="PhishGuard API", description="Real-time Phishing Detection")
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "phishing_xgb_model.json")

model = xgb.XGBClassifier()
#model.load_model("phishing_xgb_model.json")
if os.path.exists(MODEL_PATH):
    model.load_model(MODEL_PATH)
    print(f"Model loaded successfully from {MODEL_PATH}")
else:
    raise FileNotFoundError(f"CRITICAL: Model file not found at {MODEL_PATH}. Did you run train_model.py?")


extractor = FeatureExtractor()

class URLRequest(BaseModel):
    url: str

@app.post("/predict") # tells us when we send a post request to the adress /predict, the server runs the function below 
async def predict_url(request: URLRequest): 
    try: 
        features_dict = extractor.process_url(request.url, include_whois=True)
        
        feature_order= ['url_length', 'hostname_length', 'path_length', 
            'count_dot', 'count_hyphen', 'count_at', 'count_question', 
            'count_equals', 'count_digits', 
            'is_https', 'has_ip', 'is_shortened']
        
        input_df= pd.DataFrame([features_dict])
        input_df = input_df[feature_order]

        prediction = model.predict(input_df)[0]
        probability = model.predict_proba(input_df)[0][1]

        return{
            'url': request.url,
            'is_phishing': bool(prediction),
            'confidence_score': float(probability),
            'risk_level': "Critical" if probability>0.8 else "SAFE" 
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
@app.get('/')
def home():
    return {"message": "PhishGuard API is running. Send POST requests to /predict"}
