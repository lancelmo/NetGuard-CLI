# Estágio 1: Build e Instalação de Dependências
FROM python:3.10-slim AS builder
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Estágio 2: Imagem de Execução
FROM python:3.10-slim AS runner
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /opt/venv /opt/venv
COPY . .

ENV PATH="/opt/venv/bin:$PATH"
ENV PYTHONUNBUFFERED=1

EXPOSE 8000

# Sprint 4: sobe a Web Engine (FastAPI/Uvicorn) em vez da CLI do Projeto 1.
# O banco e as tabelas são criados automaticamente no startup do server.py.
CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8000"]