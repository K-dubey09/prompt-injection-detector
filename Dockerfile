FROM python:3.12-slim AS base

LABEL org.opencontainers.image.title="PromptGuard"
LABEL org.opencontainers.image.description="Prompt-injection detection & defense toolkit for LLMs"
LABEL org.opencontainers.image.source="https://github.com/K-dubey09/prompt-injection-detector"
LABEL org.opencontainers.image.licenses="MIT"

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# Install with the api + ml extras: FastAPI server, Pydantic schemas, and the
# trained scikit-learn classifier (the bundled model artifact ships with the
# package via package-data).
COPY pyproject.toml README.md ./
COPY promptguard ./promptguard
COPY web ./web
RUN pip install .[api,ml]

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://localhost:8000/health', timeout=3).status==200 else 1)"

CMD ["uvicorn", "promptguard.server:app", "--host", "0.0.0.0", "--port", "8000"]
