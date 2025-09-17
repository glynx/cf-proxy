FROM oven/bun:alpine

# get wrangler for cloudflare workes
RUN bun i -g wrangler && apk add --no-cache npm ca-certificates curl bash jq >/dev/null && update-ca-certificates

RUN mkdir /cf-proxy

# copy files for worker
COPY proxy.js /cf-proxy
COPY entrypoint.sh /cf-proxy
ADD worker /cf-proxy/worker

# Environment
ENV XDG_CONFIG_HOME=/workspace/.cf

RUN chmod +x /cf-proxy/entrypoint.sh

ENTRYPOINT [ "/cf-proxy/entrypoint.sh" ]
