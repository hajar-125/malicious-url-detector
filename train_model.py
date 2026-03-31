import pandas as pd
import xgboost as xgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import matplotlib.pyplot as plt

input= "dataset_final.csv"
model_file=" phishing_xgb_model.json"

def load_data(filepath):

    df = pd.read_csv(filepath)

    if 'label' not in df.columns:
        cols = [
            'url_length', 'hostname_length', 'path_length', 
            'count_dot', 'count_hyphen', 'count_at', 'count_question', 
            'count_equals', 'count_digits', 
            'is_https', 'has_ip', 'is_shortened', 
            'label'  # The target is always last
        ]

        df = pd.read_csv(filepath, header=None, names=cols)
        print('done')

    return df
def train_phishing_detector():
    print("we load data..")
    df=load_data(input)

    x= df.drop('label', axis=1, errors='ignore')
    y=df['label']
    
    #x = x.select_dtypes(include=['number'])

    x_train, x_test, y_train, y_test= train_test_split( x, y, test_size=0.2, stratify=y, random_state=42)

    model = xgb.XGBClassifier(
        objective= 'binary:logistic', 
        n_estimators= 100,
        max_depth= 5, 
        learning_rate=0.1,
        eval_metrics= 'logloss', 
        use_label_encoder= False
    )

    print('training phase...')
    model.fit(x_train, y_train)

    print('\n-> Model Evaluation')
    y_pred = model.predict(x_test)

    accuracy= accuracy_score(y_test, y_pred)
    print(f'Accuracy: {accuracy: .4f}')

    print('\n-> Classification report')
    print(classification_report(y_test, y_pred))

    print('-> Confusion matrix')
    print(confusion_matrix(y_test, y_pred))

    model.save_model(model_file)
    print('model saved')

    print("\nGenerating Feature Importance Plot...")
    x = xgb.plot_importance(model, max_num_features=10, height=0.5)
    plt.title("Feature Importance (XGBoost)")
    plt.tight_layout()
    plt.savefig("feature_importance.png")
    print("Feature importance plot saved to 'feature_importance.png'")


if __name__ == "__main__":
    train_phishing_detector()