# StegSuite — self-hosted steganography/forensics workbench.
#
# Base toolset is pinned by digest so upstream updates can never break a rebuild.
# The toolset image is AperiSolve (MIT); StegSuite's own code is independent.
FROM ghcr.io/zeecka/aperisolve@sha256:d45e1e129f210dd96aef7b2f046cb79d4ea1727591514c391dcd4d4d580d6ec5

USER root

COPY backend/requirements.txt /opt/stegsuite/requirements.txt
RUN python3 -m venv /opt/stegsuite/venv \
 && /opt/stegsuite/venv/bin/pip install --no-cache-dir -U pip \
 && /opt/stegsuite/venv/bin/pip install --no-cache-dir -r /opt/stegsuite/requirements.txt

COPY backend/ /opt/stegsuite/backend/

WORKDIR /data
EXPOSE 19014
CMD ["/opt/stegsuite/venv/bin/uvicorn", "backend.main:app", \
     "--host", "0.0.0.0", "--port", "19014", "--app-dir", "/opt/stegsuite"]
