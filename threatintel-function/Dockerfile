FROM mcr.microsoft.com/azure-functions/python:4-python3.11

ENV AzureWebJobsScriptRoot=/home/site/wwwroot \
    FUNCTIONS_WORKER_RUNTIME=python \
    PYTHONUNBUFFERED=1

WORKDIR /home/site/wwwroot

COPY threatintel-function/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy only the Function App runtime files.
COPY threatintel-function/function_app.py ./
COPY threatintel-function/host.json ./

# Copy project-root modules used by function_app.py.
# Build context must be the repository root (PFA_2) when building this image.
COPY orchestrator.py ./
COPY cosmos_client.py ./
COPY cache.py ./
COPY report_generator.py ./
COPY agents ./agents
