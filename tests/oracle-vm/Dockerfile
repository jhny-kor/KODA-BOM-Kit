# Build-host VM tools only. This image is not part of the air-gap delivery.
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends qemu-system-x86 rpm2cpio cpio gzip xz-utils python3 ca-certificates && rm -rf /var/lib/apt/lists/*
