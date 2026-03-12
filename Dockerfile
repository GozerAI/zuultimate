FROM python:3.11-slim

WORKDIR /app

# Copy build metadata first (keeps Docker layer caching useful)
COPY pyproject.toml README.md ./

# Copy source BEFORE installing
COPY src/ src/
COPY alembic.ini .
COPY alembic/ alembic/
COPY config/ config/

RUN pip install --no-cache-dir ".[postgres,redis]"

RUN mkdir -p data

EXPOSE 8000

CMD ["uvicorn", "zuultimate.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
