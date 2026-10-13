"""A TCP proxy between two nodes that a test can cut, delay or reset (partition and heal)."""
import socket
import threading
import time


class Proxy:
    """Listens on (host, port) and relays each connection to `target`. `mode` is one of:
    pass   relay (after `delay` seconds per connection, if set)
    cut    accept and close at once, and drop every relayed connection: the peer sees a reset or an empty reply
    A test flips the mode with cut() / heal(); connections open at the time of a cut are closed."""

    def __init__(self, host, port, target):
        self.host, self.port, self.target = host, port, target
        self.mode, self.delay = "pass", 0.0
        self.accepted = 0
        self._lock = threading.Lock()
        self._conns = set()
        self._stop = threading.Event()
        self._srv = socket.socket()
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind((host, port))
        self._srv.listen(64)
        self._srv.settimeout(0.2)
        self._thread = threading.Thread(target=self._accept, daemon=True)
        self._thread.start()

    def cut(self):
        self.mode = "cut"
        with self._lock:
            conns, self._conns = list(self._conns), set()
        for c in conns:
            _close(c)

    def heal(self):
        self.mode = "pass"

    def close(self):
        self._stop.set()
        self.cut()
        self._thread.join(timeout=5)
        _close(self._srv)

    def _accept(self):
        while not self._stop.is_set():
            try:
                client, _ = self._srv.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            self.accepted += 1
            if self.mode == "cut":
                _close(client)
                continue
            threading.Thread(target=self._relay, args=(client,), daemon=True).start()

    def _relay(self, client):
        if self.delay:
            time.sleep(self.delay)
        try:
            upstream = socket.create_connection(self.target, timeout=5)
        except OSError:
            _close(client)
            return
        with self._lock:
            if self.mode == "cut":
                _close(client), _close(upstream)
                return
            self._conns |= {client, upstream}
        for a, b in ((client, upstream), (upstream, client)):
            threading.Thread(target=_pipe, args=(a, b), daemon=True).start()


def _pipe(src, dst):
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def _close(s):
    try:
        s.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    try:
        s.close()
    except OSError:
        pass
