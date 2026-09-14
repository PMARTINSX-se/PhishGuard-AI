FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN python train_model.py --dataset data/urls.csv --out models/phishing_rf.pkl
EXPOSE 5000
CMD ["python", "app.py"]
