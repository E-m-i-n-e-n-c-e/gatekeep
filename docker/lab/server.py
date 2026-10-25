"""Tiny lab services: HTTP on 80, HTTPS on 443 and 8443, a banner on 23."""

import http.server
import socketserver
import ssl
import threading


class Hello(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = f"hello from server (host={self.headers.get('Host')})\n".encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        print(f"[web] {self.client_address[0]} {fmt % args}")


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class TLSServer(Server):
    """TLS handshake per connection, in its own thread, with a timeout.

    Wrapping the listening socket instead would run every handshake inside
    accept(): one client whose ClientHello the firewall drops would then
    stall the whole server.
    """

    def __init__(self, port):
        super().__init__(("0.0.0.0", port), Hello)
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain("/tmp/cert.pem", "/tmp/key.pem")

    def finish_request(self, request, client_address):
        request.settimeout(5)
        try:
            tls = self.ctx.wrap_socket(request, server_side=True)
        except (ssl.SSLError, OSError):
            return
        self.RequestHandlerClass(tls, client_address, self)


class Banner(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.sendall(b"lab telnet: you should not be able to see this\r\n")


class BannerServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


servers = [Server(("0.0.0.0", 80), Hello), TLSServer(443), TLSServer(8443), BannerServer(("0.0.0.0", 23), Banner)]
for s in servers[1:]:
    threading.Thread(target=s.serve_forever, daemon=True).start()
servers[0].serve_forever()
