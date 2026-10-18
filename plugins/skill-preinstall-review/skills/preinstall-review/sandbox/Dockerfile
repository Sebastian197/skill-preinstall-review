# Sandbox image for preinstall-review.
#
# The base image is pinned by digest. The apt packages are not pinned to exact
# versions; the image is rebuilt only when this directory changes, and the tag
# carries a hash of its contents.
FROM debian@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587

# Tools a candidate skill is likely to call. They are present so that an
# attempt shows up as a real syscall (connect, open) instead of a
# "command not found" that hides intent.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      strace python3 nodejs bash coreutils findutils curl wget git netcat-openbsd \
      openssh-client ca-certificates procps \
 && rm -rf /var/lib/apt/lists/*

# The reviewed code runs as this unprivileged user. The runner and the
# sinkhole run as root inside the container so the candidate cannot read or
# rewrite the evidence.
RUN useradd -m -u 1001 -s /bin/bash candidate

COPY runner.py sinkhole.py /opt/spr/
ENTRYPOINT ["python3", "/opt/spr/runner.py"]
