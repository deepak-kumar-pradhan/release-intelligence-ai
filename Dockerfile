FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt

COPY . .

RUN mkdir -p reports session

EXPOSE 8503

CMD ["streamlit", "run", "ui/app.py", "--server.headless=true", "--server.address=0.0.0.0", "--server.port=8503"]