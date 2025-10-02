FROM oven/bun:alpine

# get wrangler for cloudflare workes
RUN apk add --no-cache ca-certificates curl bash jq python3 py3-websockets npm >/dev/null && update-ca-certificates 
ENV BUN_INSTALL=/usr/local
RUN bun i -g wrangler && which wrangler && wrangler -v

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
