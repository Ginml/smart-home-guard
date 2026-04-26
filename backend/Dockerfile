FROM python:3.12-slim

# System deps: libgomp1 is required by LightGBM (OpenMP runtime)
RUN apt-get update \
    && apt-get install -y --no-install-recommends libgomp1 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

ENV UV_SYSTEM_PYTHON=1

WORKDIR /app

# Layer caching: install deps before copying source
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev

# Copy backend source and pcap extraction utils
COPY backend/ ./backend/
COPY utils/ ./utils/

# Model artifacts are mounted at runtime via docker-compose volume (notebooks/models)

EXPOSE 8000

CMD ["uv", "run", "uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
