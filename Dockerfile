FROM nvidia/cuda:12.8.1-runtime-ubuntu24.04

ARG DEBIAN_FRONTEND=noninteractive
ARG HASHCAT_VERSION=7.1.2
ARG HASHCAT_SHA256=80db0316387794ce9d14ed376da75b8a7742972485b45db790f5f8260307ff98

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl p7zip-full python3 \
 && rm -rf /var/lib/apt/lists/*

RUN curl --fail --show-error --silent --location \
      "https://hashcat.net/files/hashcat-${HASHCAT_VERSION}.7z" \
      --output /tmp/hashcat.7z \
 && echo "${HASHCAT_SHA256}  /tmp/hashcat.7z" | sha256sum --check --strict \
 && mkdir -p /opt/hashcat-release \
 && 7z x /tmp/hashcat.7z -o/opt/hashcat-release >/dev/null \
 && mv "/opt/hashcat-release/hashcat-${HASHCAT_VERSION}" /opt/hashcat \
 && rm -rf /tmp/hashcat.7z /opt/hashcat-release \
 && /opt/hashcat/hashcat.bin --version

COPY app.py /opt/estoc/app.py

WORKDIR /opt/hashcat
ENTRYPOINT ["python3", "/opt/estoc/app.py"]
