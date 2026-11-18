FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /opt/rsa-lab
COPY pyproject.toml README.md main.py ./
COPY core/ core/
COPY attacks/ attacks/
COPY cli/ cli/
RUN python -m pip install --no-cache-dir . \
    && useradd --create-home --user-group --uid 10001 lab \
    && install -d -o lab -g lab /data
USER lab
WORKDIR /data
ENTRYPOINT ["rsa-lab"]
CMD ["--help"]
