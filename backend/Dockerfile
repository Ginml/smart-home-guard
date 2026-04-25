FROM python:3.12-slim

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

ENV UV_SYSTEM_PYTHON=1

# tcpdump is required by the real-time capture service (POST /api/scan/start).
# At runtime the container additionally needs CAP_NET_RAW, e.g.
#   docker run --cap-add=NET_RAW --network host smart-home-guard-backend
RUN apt-get update \
    && apt-get install -y --no-install-recommends tcpdump \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Layer caching: install deps before copying source
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev

# Copy backend source
COPY backend/ ./backend/

# Copy only the needed model artifacts
COPY notebooks/models/lightgbm.txt notebooks/models/scaler.pkl notebooks/models/label_encoder.pkl ./notebooks/models/

EXPOSE 8000

CMD ["uv", "run", "uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
