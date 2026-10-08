FROM node:24-bookworm-slim@sha256:0e0ff40c39bc087845bfb27465a0df4ea419520094bc35842ff83dd8cbe6f9b6
RUN groupadd --gid 65532 macoperator-task \
    && useradd --uid 65532 --gid 65532 --home-dir /home/agent --no-create-home --shell /usr/sbin/nologin macoperator-task \
    && groupadd --gid 65533 macoperator-pid1 \
    && useradd --uid 65533 --gid 65533 --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin macoperator-pid1
WORKDIR /opt/mac-operator/site
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund && npm cache clean --force
COPY run-site-build.cjs /opt/mac-operator/run-site-build.cjs
WORKDIR /
