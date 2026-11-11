# Bastion core: the Warden orchestrator, its agents and the incident page.
FROM python:3.12-slim

RUN useradd --uid 10001 --create-home bastion \
    && mkdir /data && chown bastion:bastion /data
WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src
COPY rules ./rules
COPY policy ./policy
COPY tests/labeled_events ./tests/labeled_events
RUN pip install --no-cache-dir '.[core,tracing]'

USER bastion
ENV BASTION_DATA_DIR=/data BASTION_POLICY_DIR=/app/policy PYTHONUNBUFFERED=1
VOLUME /data
CMD ["bastion-core", "run"]
