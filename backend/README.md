# PhishGuard AI Backend

Flask + scikit-learn ML inference API for phishing URL classification.

## Setup
```
cd backend
python -m venv venv && source venv/bin/activate    # Windows: venv\Scripts\activate
pip install -r requirements.txt
python train_model.py              # creates models/phishing_rf.pkl (uses seed dataset if data/urls.csv missing)
python app.py                      # serves on http://localhost:5000
```

## Train on a real dataset
1. Download a CSV with `url,label` columns from Kaggle/PhishTank/UCI.
2. Save to `data/urls.csv`.
3. Re-run `python train_model.py`.

## Endpoints
- `POST /api/scan`     `{url}` → verdict, risk_score, reasons
- `POST /api/report`   `{url}` → log a user report
- `GET  /api/reports`  → recent reports
- `GET  /api/stats`    → aggregate counts
- `GET  /healthz`      → liveness probe

## Docker
```
docker build -t phishguard-api .
docker run -p 5000:5000 phishguard-api
```
