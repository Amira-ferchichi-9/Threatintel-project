FROM python:3.11-slim
WORKDIR /app

ENV PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --timeout=300 -r requirements.txt

COPY . .

RUN python3 -c "from agents.agent_nlp_bec import run_nlp_bec_agent; print('models pre-loaded')"

CMD ["uvicorn", "api:app", "--host", "0.0.0.0", "--port", "8000"]