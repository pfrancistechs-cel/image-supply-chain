# The "shop" application. Two builds come from this one file:
#   REQS=requirements.txt      (default) urllib3 2.2.3: clean
#   REQS=requirements-bad.txt            urllib3 1.26.4: has known vulnerabilities, so the SBOM policy must refuse it
FROM python:3.12-slim
ARG APP_VERSION=1.0.0
ARG REQS=requirements.txt
ENV APP_VERSION=${APP_VERSION} PYTHONUNBUFFERED=1
WORKDIR /app
COPY ${REQS} /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt && rm /tmp/requirements.txt
COPY app.py .
USER 65534
EXPOSE 8080
CMD ["python", "app.py"]
