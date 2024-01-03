from flask import Flask, render_template, request
import pandas as pd
from joblib import load
from sklearn.metrics import accuracy_score
from sklearn.model_selection import train_test_split
from email.message import EmailMessage
import smtplib
app = Flask(__name__)

# Load the preprocessed dataset
file_path = 'cleaned_dataset.csv'  
data = pd.read_csv(file_path)
data['Label'] = data['Label'].apply(lambda x: 0 if x == 'BENIGN' else 1)

# Split the dataset
X = data.drop('Label', axis=1)
y = data['Label']
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.1, random_state=42)

# Load the models
rf_model = load('random_forest_model.joblib')
dt_model = load('decision_tree_model.joblib')
svm_model = load('svm_model.joblib')
knn_model = load('knn_model.joblib') 

# Calculate accuracies
rf_accuracy = accuracy_score(y_test, rf_model.predict(X_test))
dt_accuracy = accuracy_score(y_test, dt_model.predict(X_test))
svm_accuracy = accuracy_score(y_test, svm_model.predict(X_test))
knn_accuracy = accuracy_score(y_test, knn_model.predict(X_test))  

# Function to make predictions
def send_email_alert():
    msg = EmailMessage()
    msg['Subject'] = 'Attack Alert'
    msg['From'] = 'emailalertids@gmail.com'
    msg['To'] = 'lanstondrobert@gmail.com'  
    msg.set_content('An attack has been detected!')

    with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
        smtp.login('emailalertids@gmail.com', 'qymr sxpf rcyi hkbr')  # App password
        smtp.send_message(msg)

def make_prediction(input_data):
    input_df = pd.DataFrame([input_data], columns=X.columns)
    rf_prediction = rf_model.predict(input_df)[0]
    dt_prediction = dt_model.predict(input_df)[0]
    svm_prediction = svm_model.predict(input_df)[0]
    knn_prediction = knn_model.predict(input_df)[0] 

    total_weight = rf_accuracy + dt_accuracy + svm_accuracy + knn_accuracy
    weighted_sum = (rf_prediction * rf_accuracy) + (dt_prediction * dt_accuracy) + (svm_prediction * svm_accuracy) + (knn_prediction * knn_accuracy)
    combined_prediction = round(weighted_sum / total_weight)
    if combined_prediction == 1:
        send_email_alert()
    return {
        "rf": {"prediction": rf_prediction, "accuracy": rf_accuracy},
        "dt": {"prediction": dt_prediction, "accuracy": dt_accuracy},
        "svm": {"prediction": svm_prediction, "accuracy": svm_accuracy},
        "knn": {"prediction": knn_prediction, "accuracy": knn_accuracy},
        "combined": combined_prediction,
        "calculation_steps": f"({rf_prediction} * {rf_accuracy}) + ({dt_prediction} * {dt_accuracy}) + ({svm_prediction} * {svm_accuracy}) + ({knn_prediction} * {knn_accuracy}) / {total_weight} = {combined_prediction}",
        "is_attack": combined_prediction == 1
    }

# Flask routes
@app.route('/', methods=['GET', 'POST'])
def index():
    column_names = ['Bwd Packet Length Min', 'Bwd Packet Length Std', 'Flow IAT Max', 'Fwd IAT Std', 'Bwd IAT Total', 'Bwd Packets/s', 'Min Packet Length', 'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count', 'Init_Win_bytes_forward', 'min_seg_size_forward']
    if request.method == 'POST':
        input_data = [request.form.get(column) for column in column_names]
        input_data = [float(i) for i in input_data]
        predictions = make_prediction(input_data)
        return render_template('index.html', predictions=predictions, column_names=column_names, accuracies={'rf': rf_accuracy, 'dt': dt_accuracy, 'svm': svm_accuracy, 'knn': knn_accuracy})
    return render_template('index.html', predictions=None, column_names=column_names, accuracies=None)


if __name__ == '__main__':
    app.run(debug=True)
