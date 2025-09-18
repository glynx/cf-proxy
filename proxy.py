#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cloudflare-Worker WebSocket tunneling proxy in Python (asyncio).
- Supports HTTP proxy (CONNECT + plain HTTP forwarding)
- Supports SOCKS5 (CONNECT only)
- Uses 'websockets' client with custom headers
- Binary-safe relay, send-queue until WS is open
- Bi-directional teardown and idle timeouts

Usage examples:
  HTTP proxy on :8080
    python proxy.py http --worker my-instance.workers.dev -p 8080 -a "SECRET" -v

  SOCKS5 proxy on :1080
    python proxy.py socks --worker my-instance.workers.dev -p 1080 -a "SECRET" -v
"""

import argparse
import asyncio
import inspect
import logging
import re
import sys
import time
from typing import Any
from urllib.parse import urlparse

import websockets 

# ----------------------------- Utils ----------------------------------------

def parse_host_header(raw: bytes) -> str:
    """Extract Host header value as-is (may include :port, IPv6)."""
    try:
        text = raw.decode('latin-1', errors='ignore')
        for line in text.split('\n'):
            if line.lower().startswith('host:'):
                return line.split(':', 1)[1].strip()
    except Exception:
        pass
    return ''

def is_http_connect(raw: bytes) -> bool:
    """Detect 'CONNECT host:port HTTP/1.1'."""
    try:
        line0 = raw.split(b'\n', 1)[0].strip().decode('latin-1', errors='ignore')
        return line0.startswith('CONNECT ')
    except Exception:
        return False

def parse_connect_target(raw: bytes) -> str:
    """Parse target from 'CONNECT host:port HTTP/1.1'."""
    try:
        line0 = raw.split(b'\n', 1)[0].strip().decode('latin-1', errors='ignore')
        parts = line0.split()
        if len(parts) >= 2:
            return parts[1].strip()
    except Exception:
        pass
    return ''

def parse_abs_form_target(raw: bytes) -> str:
    """
    Parse absolute-form 'GET http://host[:port]/path HTTP/1.1'.
    Fallback to Host header (default port 80).
    """
    try:
        line0 = raw.split(b'\n', 1)[0].strip().decode('latin-1', errors='ignore')
        parts = line0.split()
        if len(parts) >= 2:
            u = urlparse(parts[1])
            if u.scheme and u.netloc:
                host = u.hostname
                port = u.port or (443 if u.scheme == 'https' else 80)
                return f"{host}:{port}"
    except Exception:
        pass

    host = parse_host_header(raw)
    if host:
        if ':' in host:
            return host
        return f"{host}:80"
    return ''

def human_addr(peer) -> str:
    try:
        host, port, *_ = peer
        return f"{host}:{port}"
    except Exception:
        return str(peer)

# ----------------------------- Tunnel ---------------------------------------

class WSTunnel:
    """
    Manages a WebSocket tunnel to the Cloudflare Worker and bridges to a TCP client.
    - Queues TCP data until WS is open
    - For HTTP CONNECT, sends 200 only after WS is ready
    - Enforces idle timeouts on activity
    """
    def __init__(self, worker_host: str, target: str, auth: str | None, mode: str,
                 idle_ms: int, log: logging.Logger):
        self.worker_host = worker_host
        self.target = target
        self.auth = auth
        self.mode = mode  # 'CONNECT' | 'HTTP_FORWARD' | 'SOCKS5'
        self.idle_ms = idle_ms
        self.log = log

        self.ws: websockets.WebSocketClientProtocol | None = None
        self._queue: list[bytes] = []
        self._ready = asyncio.Event()
        self._last_activity = time.monotonic()
        self._idle_task: asyncio.Task | None = None
        self._closed = asyncio.Event()

    async def open(self):
        headers = {
            "X-Proxy-Target": self.target,
        }
        if self.auth:
            headers["Authorization"] = self.auth

        uri = f"wss://{self.worker_host}"
        self.log.debug(f"WS connecting to {uri} -> {self.target} ({self.mode})")

        connect_kwargs : dict[str, Any] = dict(
            max_size=None,  # don't cap frames
            ping_interval=20,
            ping_timeout=20
        )
        # some versions may require additional_headers and other extra_headers
        connect_kwargs['additional_headers' if 'additional_headers' in inspect.signature(websockets.connect).parameters else 'extra_headers'] = headers
        self.ws = await websockets.connect(uri, **connect_kwargs)

        # Start idle watchdog if requested
        if self.idle_ms > 0:
            self._idle_task = asyncio.create_task(self._idle_watchdog())

        # Mark ready and flush queue
        self._ready.set()
        if self._queue:
            for chunk in self._queue:
                await self._safe_send(chunk)
            self._queue.clear()

    async def _idle_watchdog(self):
        """Close tunnel if no traffic for idle_ms."""
        try:
            while not self._closed.is_set():
                await asyncio.sleep(self.idle_ms / 1000.0 / 2)
                if (time.monotonic() - self._last_activity) * 1000 >= self.idle_ms:
                    self.log.debug("Idle timeout -> closing WS")
                    await self.close(code=1000, reason="idle_timeout")
                    break
        except asyncio.CancelledError:
            pass

    async def _safe_send(self, data: bytes):
        """Send bytes over WS; handles closed/None."""
        if not self.ws:
            return
        try:
            await self.ws.send(data)
        except Exception as e:
            self.log.debug(f"WS send failed: {e!r}")
            await self.close()

    async def pump_ws_to_tcp(self, writer: asyncio.StreamWriter):
        """
        Receive WS frames and write to TCP.
        Stops when WS closes or write fails.
        """
        assert self.ws is not None
        try:
            async for msg in self.ws:
                # 'msg' is bytes for binary frames (default behavior)
                if isinstance(msg, (bytes, bytearray, memoryview)):
                    try:
                        writer.write(bytes(msg))
                        await writer.drain()
                    except Exception:
                        break
                else:
                    # If we receive text, convert to bytes defensively
                    data = msg.encode('utf-8', 'ignore')
                    try:
                        writer.write(data)
                        await writer.drain()
                    except Exception:
                        break
                self._last_activity = time.monotonic()
        except Exception as e:
            self.log.debug(f"WS->TCP pump ended: {e!r}")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            await self.close()

    async def send_tcp_data(self, data: bytes):
        """Called when TCP client sends data; queue until WS is ready."""
        self._last_activity = time.monotonic()
        if self._ready.is_set():
            await self._safe_send(data)
        else:
            self._queue.append(bytes(data))

    async def close(self, code: int = 1000, reason: str = "closing"):
        if self._closed.is_set():
            return
        self._closed.set()
        if self._idle_task:
            self._idle_task.cancel()
        if self.ws:
            try:
                await self.ws.close(code=code, reason=reason)
            except Exception:
                pass

# --------------------------- HTTP Proxy -------------------------------------

class HTTPProxy:
    """
    Minimal HTTP proxy:
      - CONNECT: open tunnel and reply '200 Connection Established' after WS is ready
      - Forwarding: for absolute-form or Host-based requests, just forward bytes
    """

    def __init__(self, worker: str, auth: str | None, idle_ms: int, log: logging.Logger):
        self.worker = worker
        self.auth = auth
        self.idle_ms = idle_ms
        self.log = log

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        peer = human_addr(writer.get_extra_info('peername'))
        try:
            first = await reader.read(65536)
            if not first:
                writer.close()
                await writer.wait_closed()
                return

            if is_http_connect(first):
                target = parse_connect_target(first)
                if not target:
                    writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                    await writer.drain()
                    writer.close()
                    await writer.wait_closed()
                    return

                tun = WSTunnel(self.worker, target, self.auth, "CONNECT", self.idle_ms, self.log)
                await tun.open()

                # Only now tell the client the tunnel is established
                writer.write(b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: py-ws-proxy\r\n\r\n")
                await writer.drain()

                # Start WS->TCP pump
                pump_task = asyncio.create_task(tun.pump_ws_to_tcp(writer))

                # TCP->WS loop
                while not pump_task.done():
                    data = await reader.read(65536)
                    if not data:
                        break
                    await tun.send_tcp_data(data)

                await tun.close()
                await pump_task

            else:
                # Plain HTTP forwarding
                target = parse_abs_form_target(first)
                if not target:
                    writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                    await writer.drain()
                    writer.close()
                    await writer.wait_closed()
                    return

                tun = WSTunnel(self.worker, target, self.auth, "HTTP_FORWARD", self.idle_ms, self.log)
                await tun.open()
                # Send the first request immediately (already read)
                await tun.send_tcp_data(first)

                pump_task = asyncio.create_task(tun.pump_ws_to_tcp(writer))

                while not pump_task.done():
                    data = await reader.read(65536)
                    if not data:
                        break
                    await tun.send_tcp_data(data)

                await tun.close()
                await pump_task

        except Exception as e:
            self.log.debug(f"[HTTP {peer}] error: {e!r}")
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

# --------------------------- SOCKS5 Proxy -----------------------------------

class SOCKS5Proxy:
    """
    Minimal SOCKS5 server supporting CONNECT (0x01) only.
    """

    def __init__(self, worker: str, auth: str | None, idle_ms: int, log: logging.Logger):
        self.worker = worker
        self.auth = auth
        self.idle_ms = idle_ms
        self.log = log

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        peer = human_addr(writer.get_extra_info('peername'))
        try:
            # Greeting: VER | NMETHODS | METHODS...
            greet = await reader.readexactly(2)
            ver = greet[0]
            nmethods = greet[1]
            if ver != 0x05:
                writer.close()
                await writer.wait_closed()
                return
            methods = await reader.readexactly(nmethods)
            if 0x00 not in methods:
                writer.write(bytes([0x05, 0xFF]))  # no acceptable methods
                await writer.drain()
                writer.close()
                await writer.wait_closed()
                return
            # No auth
            writer.write(bytes([0x05, 0x00]))
            await writer.drain()

            # Request: VER | CMD | RSV | ATYP | DST.ADDR | DST.PORT
            head = await reader.readexactly(4)
            ver, cmd, rsv, atyp = head
            if ver != 0x05 or cmd != 0x01:  # CONNECT only
                writer.write(bytes([0x05, 0x07, 0x00, 0x01, 0,0,0,0, 0,0]))
                await writer.drain()
                writer.close()
                await writer.wait_closed()
                return

            if atyp == 0x01:  # IPv4
                addr = await reader.readexactly(4)
                host = ".".join(str(b) for b in addr)
            elif atyp == 0x03:  # Domain
                ln = (await reader.readexactly(1))[0]
                host = (await reader.readexactly(ln)).decode('utf-8', 'ignore')
            elif atyp == 0x04:  # IPv6
                addr = await reader.readexactly(16)
                # Basic hex-concat; not trying to pretty-compress
                host = ":".join(f"{addr[i]:02x}{addr[i+1]:02x}" for i in range(0, 16, 2))
                host = f"[{host}]"
            else:
                writer.close()
                await writer.wait_closed()
                return

            port_bytes = await reader.readexactly(2)
            port = port_bytes[0] * 256 + port_bytes[1]
            target = f"{host}:{port}"

            tun = WSTunnel(self.worker, target, self.auth, "SOCKS5", self.idle_ms, self.log)
            await tun.open()

            # Success response (bind addr set to 0.0.0.0:0)
            writer.write(bytes([0x05, 0x00, 0x00, 0x01, 0,0,0,0, 0,0]))
            await writer.drain()

            pump_task = asyncio.create_task(tun.pump_ws_to_tcp(writer))

            while not pump_task.done():
                data = await reader.read(65536)
                if not data:
                    break
                await tun.send_tcp_data(data)

            await tun.close()
            await pump_task

        except asyncio.IncompleteReadError:
            # Client hung up early
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
        except Exception as e:
            self.log.debug(f"[SOCKS {peer}] error: {e!r}")
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

# --------------------------- Main / CLI -------------------------------------

async def run_server(kind: str, host: str, port: int, worker: str,
                     auth: str | None, idle_ms: int, verbose: bool):
    log = logging.getLogger("cfws")
    log.setLevel(logging.DEBUG if verbose else logging.INFO)
    h = logging.StreamHandler(sys.stdout)
    h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    log.handlers.clear()
    log.addHandler(h)

    handler = HTTPProxy(worker, auth, idle_ms, log) if kind == "http" else SOCKS5Proxy(worker, auth, idle_ms, log)

    async def _client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        if kind == "http":
            await handler.handle_client(reader, writer)
        else:
            await handler.handle_client(reader, writer)

    server = await asyncio.start_server(_client, host=host, port=port)
    addr = ", ".join(str(sock.getsockname()) for sock in server.sockets)
    log.info(f"[+] {kind.upper()} proxy listening on {addr}, worker=wss://{worker}, idle_ms={idle_ms}")

    async with server:
        await server.serve_forever()

def parse_args():
    p = argparse.ArgumentParser(description="Proxy via Cloudflare Worker (WS tunnel)")
    sub = p.add_subparsers(dest="kind", required=True)

    def add_common(sp):
        sp.add_argument("--worker", required=True, help="Worker hostname (e.g. my-instance.workers.dev)")
        sp.add_argument("-a", "--auth", default=None, help="Authorization header value")
        sp.add_argument("--host", default="0.0.0.0", help="Bind address (default 0.0.0.0)")
        sp.add_argument("-p", "--port", type=int, help="Listen port")
        sp.add_argument("--idle-ms", type=int, default=60000, help="Idle timeout for tunnels (ms)")
        sp.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")

    sp_http = sub.add_parser("http", help="HTTP proxy mode")
    add_common(sp_http)
    sp_http.set_defaults(port=8080)

    sp_socks = sub.add_parser("socks", help="SOCKS5 proxy mode")
    add_common(sp_socks)
    sp_socks.set_defaults(port=1080)

    return p.parse_args()

def main():
    args = parse_args()
    try:
        asyncio.run(run_server(args.kind, args.host, args.port, args.worker, args.auth, args.idle_ms, args.verbose))
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()