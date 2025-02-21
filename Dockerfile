FROM python:3.12-slim AS python-base
COPY --from=ghcr.io/astral-sh/uv:0.4.2 /uv /bin/uv

# version: 0.1

ENV PYTHONUNBUFFERED=1 \
  PYTHONDONTWRITEBYTECODE=1 \
  PIP_NO_CACHE_DIR=off \
  PIP_DISABLE_PIP_VERSION_CHECK=on \
  PIP_DEFAULT_TIMEOUT=100 \
  PYSETUP_PATH="/opt/pysetup" \
  VENV_PATH="/opt/pysetup/.venv"

ENV PATH="$VENV_PATH/bin:$PATH"

# builder-base is used to build dependencies
FROM python-base AS builder-base
RUN apt-get update \
    && apt-get install --no-install-recommends -y \
        build-essential \
        postgresql-client \
        libpq-dev


# We copy our Python requirements here to cache them
# and install only runtime deps using poetry
WORKDIR $PYSETUP_PATH
COPY ./uv.lock ./pyproject.toml ./README.md ./src ./
# RUN uv python install 3.10
RUN uv sync --frozen

# 'production' stage uses the clean 'python-base' stage and copies
# in only our runtime deps that were installed in the 'builder-base'
FROM python-base AS production

COPY --from=builder-base $VENV_PATH $VENV_PATH

# COPY ./extend /app/extend
COPY ./extend/__init__.py /app/extend/__init__.py
COPY ./src /app/src
COPY ./pg_anon /app/pg_anon
WORKDIR /app

COPY . .
RUN uv sync --frozen

RUN apt update && \
    apt install -y postgresql-client

ENTRYPOINT ["/app/pg_anon"]
