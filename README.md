# PhishGuard Pro

Integrated security platform for URL threat analysis, message spam classification, and authorized web vulnerability assessment.

## Features

| Module | Access |
|--------|--------|
| URL threat analysis | Public |
| Spam / message classification | Public |
| Website vulnerability scanner | Authenticated + verified account |
| Personal scan history, HTML reports, CSV export | Authenticated |
| Admin console | Admin role |

## Stack

- Flask, Flask-Login, SQLAlchemy (SQLite)
- scikit-learn models for URL and message classification
- Gunicorn-ready (`wsgi.py`), Docker support

## Local run

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python scripts/train_models.py   # optional refresh of models
python app.py
```

## Production

```bash
export SECRET_KEY="long-random-value"
export ADMIN_EMAIL="admin@yourdomain.com"
export ADMIN_PASSWORD="strong-password"
export PRODUCTION=1
gunicorn -b 0.0.0.0:$PORT -w 2 --timeout 120 wsgi:app
```

Or: `docker compose up -d --build`

On first boot an admin account is created from `ADMIN_EMAIL` / `ADMIN_PASSWORD` (not shown in the UI).

## Data

- `data/phishing_urls.csv` — labeled URL samples  
- `data/spam_emails.csv` — labeled message samples  
- `models/*.joblib` — trained classifiers  

## Policy

Vulnerability scanning must only target systems you own or are authorized to assess.

## Deploy (Render)

- Build: `pip install -r requirements.txt`
- Start: `gunicorn -b 0.0.0.0:$PORT -w 2 --timeout 120 wsgi:app`
- Env: `SECRET_KEY`, `ADMIN_EMAIL`, `ADMIN_PASSWORD`, `PRODUCTION=1`
