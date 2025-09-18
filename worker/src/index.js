import { connect } from 'cloudflare:sockets';

export default {
  async fetch(request, env, ctx) {
    const TOKEN = '<YOUR-AUTH-TOKEN>';

    // Auth check
    if (request.headers.get('Authorization') !== TOKEN) {
      return new Response('Unauthorized', { status: 401 });
    }

    // Expect WS upgrade
    const upgrade = request.headers.get('Upgrade') || '';
    if (upgrade.toLowerCase() !== 'websocket') {
      return new Response('Expected Upgrade: websocket', { status: 426 });
    }

    const targetHeader = request.headers.get('X-Proxy-Target');
    if (!targetHeader) {
      return new Response('Missing X-Proxy-Target', { status: 400 });
    }

    // Parse target "host:port"
    let host = '';
    let port = 0;
    try {
      // Support IPv6: "[::1]:443" or "v6-host:port"
      const m = targetHeader.match(/^\[([^\]]+)\]:(\d+)$|^([^:]+):(\d+)$/);
      if (m) {
        host = (m[1] ?? m[3]) || '';
        port = parseInt((m[2] ?? m[4]) || '0', 10);
      }
      if (!host || !port) throw new Error('parse-failed');
    } catch {
      return new Response('Bad X-Proxy-Target', { status: 400 });
    }

    // Establish outbound TCP
    let socket;
    try {
      socket = connect({ hostname: host, port });
    } catch (e) {
      // DNS/resolve/permission errors
      return new Response('Connect failed', { status: 502 });
    }

    const { readable, writable, closed } = socket;
    const writer = writable.getWriter();

    // Create WS pair
    const pair = new WebSocketPair();
    const client = pair[0];
    const server = pair[1];

    // Accept server side
    server.accept();
    // Ensure we get ArrayBuffers for binary frames
    // (Cloudflare supports this property on WebSocket)
    try { server.binaryType = 'arraybuffer'; } catch {}

    // ---- WS -> TCP (message handler) ----
    server.addEventListener('message', (e) => {
      let bytes;
      if (typeof e.data === 'string') {
        // Client sent text: turn into bytes
        bytes = new TextEncoder().encode(e.data);
      } else if (e.data instanceof ArrayBuffer) {
        bytes = new Uint8Array(e.data);
      } else if (e.data?.byteLength !== undefined) {
        // e.g. Uint8Array
        bytes = new Uint8Array(e.data.buffer || e.data, e.data.byteOffset || 0, e.data.byteLength);
      } else {
        // Unknown type; ignore
        return;
      }

      // Fire-and-forget; backpressure is handled by Streams internally
      writer.write(bytes).catch((err) => {
        try { server.close(1011, 'tcp_write_failed'); } catch {}
      });
    });

    // If WS closes -> close TCP writer (half-close -> FIN)
    server.addEventListener('close', async () => {
      try { await writer.close(); } catch {}
      try { await socket.close(); } catch {}
    });

    server.addEventListener('error', async () => {
      try { await writer.abort('ws_error'); } catch {}
      try { await socket.close(); } catch {}
    });

    // ---- TCP -> WS (pipe) ----
    // Stream target.readable to WS frames
    const pipe = readable.pipeTo(new WritableStream({
      write(chunk) {
        // chunk is Uint8Array
        try { server.send(chunk); } catch {
          // If WS send fails, abort the TCP side
          throw new Error('ws_send_failed');
        }
      },
      close() {
        // Remote closed -> close the WS
        try { server.close(1000, 'tcp_closed'); } catch {}
      },
      abort() {
        try { server.close(1011, 'tcp_aborted'); } catch {}
      }
    })).catch((err) => {
      // Suppress "ws_send_failed" -> already closed above
    });

    // Also, when the TCP socket fully closes, ensure WS is done
    closed.then(() => {
      try { server.close(1000, 'tcp_closed'); } catch {}
    }).catch(() => {
      try { server.close(1011, 'tcp_error'); } catch {}
    });

    // Hand control to the client side
    return new Response(null, {
      status: 101,
      webSocket: client,
    });
  }
}
