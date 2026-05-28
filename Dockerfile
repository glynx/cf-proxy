FROM node:22-alpine

# install necessary packages
RUN apk add --no-cache \
    ca-certificates \
    curl \
    bash \
    jq \
    python3 \
    py3-websockets \
  && update-ca-certificates

# install bun + wrangler
RUN npm install -g bun wrangler \
  && node -v \
  && bun -v \
  && which wrangler \
  && wrangler -v

# copy files for worker
RUN mkdir /cf-proxy
COPY proxy.py /cf-proxy
COPY entrypoint.sh /cf-proxy
ADD worker /cf-proxy/worker

# Environment
ENV XDG_CONFIG_HOME=/workspace/.cf
ENV HOME=/workspace

# Custom entrypoint script
RUN chmod +x /cf-proxy/entrypoint.sh
ENTRYPOINT [ "/cf-proxy/entrypoint.sh" ]
