FROM oven/bun:alpine

# get wrangler for cloudflare workes
RUN apk add --no-cache ca-certificates curl bash jq python3 py3-websockets >/dev/null && bun i -g wrangler && update-ca-certificates 

# copy files for worker
RUN mkdir /cf-proxy
COPY proxy.py /cf-proxy
COPY entrypoint.sh /cf-proxy
ADD worker /cf-proxy/worker

# Environment
ENV XDG_CONFIG_HOME=/workspace/.cf

# Custom entrypoint script
RUN chmod +x /cf-proxy/entrypoint.sh
ENTRYPOINT [ "/cf-proxy/entrypoint.sh" ]
