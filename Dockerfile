FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install package and runtime dependencies
COPY pyproject.toml /app/
COPY analyzers /app/analyzers
COPY baselines /app/baselines
COPY cli /app/cli
COPY providers /app/providers
COPY reports /app/reports
COPY schemas /app/schemas
COPY soar /app/soar
COPY cloud_posture_watch_cli.py /app/

RUN pip install --no-cache-dir .

# Runtime directories for mounted outputs/credentials
RUN mkdir -p /app/reports /app/creds

# Environment defaults (override with --env-file or -e)
ENV CPW_WATCH_MODE=false \
    CPW_SCAN_INTERVAL_SECONDS=900 \
    CPW_BASELINE_PROFILE=standard \
    CPW_PROVIDERS=aws,azure,gcp \
    CPW_OUTPUT_FORMAT=both \
    CPW_REPORT_DIR=/app/reports \
    CPW_STORAGE_BACKEND=local

# Entrypoint supports env-based command construction for CI/cloud runners.
# If CPW_WATCH_MODE=true, attempts watch mode; otherwise performs a one-shot scan.
CMD ["sh", "-c", "if [ \"${CPW_WATCH_MODE}\" = \"true\" ]; then python cloud_posture_watch_cli.py watch --interval ${CPW_SCAN_INTERVAL_SECONDS} --providers ${CPW_PROVIDERS} --baseline ${CPW_BASELINE_PROFILE} --output ${CPW_OUTPUT_FORMAT} --report-dir ${CPW_REPORT_DIR}; else python cloud_posture_watch_cli.py scan --providers ${CPW_PROVIDERS} --baseline ${CPW_BASELINE_PROFILE} --output ${CPW_OUTPUT_FORMAT} --report-dir ${CPW_REPORT_DIR}; fi"]
