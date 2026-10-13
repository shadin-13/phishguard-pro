FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libxml2-dev libxslt1-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt gunicorn

COPY . .

ENV PRODUCTION=1
ENV PORT=8000
EXPOSE 8000

# Persist SQLite under /app/data (mount volume in production)
CMD gunicorn -b 0.0.0.0:${PORT} -w 2 --timeout 120 wsgi:app
