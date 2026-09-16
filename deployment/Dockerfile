# Controlled network-lab image. Deployments must pin a reviewed base-image digest.
FROM python:3.13-slim
WORKDIR /opt/aisecure
COPY pyproject.toml README.md /opt/aisecure/
COPY aisecure /opt/aisecure/aisecure
COPY tools/network_boundary_lab.py /opt/aisecure/tools/network_boundary_lab.py
RUN python -m pip install --no-cache-dir '.[workbench]' \
 && useradd --uid 10001 --create-home aisecure
USER 10001:10001
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
ENTRYPOINT ["python", "tools/network_boundary_lab.py"]
