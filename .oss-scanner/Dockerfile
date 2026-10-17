# Build environment for Anthropic's OSS Scanner: https://red.anthropic.com/oss-scanner
#
# The scanner builds this image with the repository as the build context and with network access,
# then scans the finished image offline. Anything the agent needs must be installed here.
FROM debian:bookworm

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates git python3 python3-pip python3-venv \
    && rm -rf /var/lib/apt/lists/*

# scanner contract: the checkout lives inside the image, at /src
COPY . /src
WORKDIR /src

# Debian 12 marks its Python installation as externally managed (PEP 668). Install the one runtime
# dependency into it anyway rather than into a virtualenv: a virtualenv only works while its bin
# directory is on PATH, and a login shell rebuilds PATH from /etc/profile and loses it. The image
# is disposable and has no other Python software in it, so there is nothing to break.
RUN pip install --no-cache-dir --break-system-packages -r requirements.txt

# What CI runs on every push: generate the full set offline. The output goes to a scratch directory
# so the checkout at /src stays clean. Worth seeing if it breaks, but it should not fail the build.
RUN python3 malicious-pdf.py https://example.com --output-dir /tmp/smoke \
      && echo "generated $(find /tmp/smoke -type f | wc -l) files" \
      || echo "WARNING: generation reported failures"
