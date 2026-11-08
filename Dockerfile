# Everything here runs during `docker build`, before the sandbox exists, so it needs no egress rule.
# @openshell ignore kind=all reason="build-time only: runs before the sandbox starts" scope=file
FROM python:3.12-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# No WORKDIR on purpose: OpenShell rejects an image working directory the (non-root)
# sandbox user cannot use, and without one it uses its own /sandbox workspace.
# The server is started with --app-dir /app, so it does not depend on the cwd.
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY app /app/app
COPY openshell /app/openshell

# Targets for the filesystem rows. Unix permissions are wide open on purpose:
# any denial you see comes from the OpenShell policy (Landlock), not from chmod.
RUN mkdir -p /data /opt/forbidden \
 && echo "top secret" > /opt/forbidden/secret.txt \
 && chmod -R 0777 /data /opt/forbidden

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
EXPOSE 8080
CMD ["/usr/local/bin/python3.12", "-m", "uvicorn", "app.main:app", "--app-dir", "/app", "--host", "0.0.0.0", "--port", "8080"]
