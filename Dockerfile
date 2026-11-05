# Minimal, locked-down runtime for untrusted models/agents.
# The sandbox has no network at run time, so dependencies must be baked into the image.
# pip is removed below; see the comment there for how to add packages.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# Remove pip so a model can't install anything, even if it finds a way to run commands.
# To add dependencies, build a derived image before this step, or install them in a
# separate stage and COPY the site-packages folder in.
RUN rm -rf /usr/local/lib/python3.12/site-packages/pip \
           /usr/local/lib/python3.12/site-packages/pip-*.dist-info \
           /usr/local/lib/python3.12/ensurepip \
           /usr/local/bin/pip /usr/local/bin/pip3 /usr/local/bin/pip3.12

# Run as "nobody" (uid/gid 65534) rather than root.
USER 65534:65534

WORKDIR /out
