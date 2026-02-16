#!/usr/bin/env python3
"""
capture_tls_quic.py — Capture TLS ClientHello and QUIC Initial

-t : capture TLS ClientHello (default)
-q : capture QUIC Initial
-a : capture both (TLS + QUIC)
"""

from __future__ import annotations
import argparse
import socket
import subprocess
import sys
import threading
import time
import shutil
import platform
import functools
from datetime import datetime
from pathlib import Path
from contextlib import contextmanager
from typing import Iterator, Tuple

IS_WINDOWS = platform.system() == "Windows"

MAX_BUFFER_SIZE = 2048
CAPTURE_TIMEOUT = 1
RETRIES = 3
OUT_DIR = Path.cwd()

CURL_CMD = "curl"
CURL_CMD_ALT = "curl-quiche"
if shutil.which(CURL_CMD_ALT) is not None:
    CURL_CMD = CURL_CMD_ALT

PROTOCOL_INFO = {
    "tls_clienthello": ("tls", "TLS ClientHello"),
    "quic_initial": ("quic", "QUIC Initial"),
}

def timestamp():
    return datetime.now().strftime('%Y%m%dT%H%M%S')

def resolve_host(host: str) -> str:
    """Resolve hostname to IP address with proper error handling"""
    try:
        for res in socket.getaddrinfo(host, 443, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM):
            af, socktype, proto, canonname, sa = res
            return sa[0]
        raise socket.gaierror(f"Could not resolve {host}")
    except socket.gaierror as e:
        raise RuntimeError(f'❌ Could not resolve {host}: {e}')
    except Exception as e:
        raise RuntimeError(f'❌ Unexpected error resolving {host}: {e}')

def safe_bind(sock: socket.socket, addr: tuple[str, int]):
    """Cross-platform bind helper (prevents 'invalid argument' on Windows)"""
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(addr)
    except OSError as e:
        print(f"❗[warn] bind failed on {addr}: {e}")
        if IS_WINDOWS:
            try:
                sock.bind(("127.0.0.1", 0))
            except OSError as e2:
                print(f"❌ [fatal] Fallback bind also failed: {e2}")
                raise

def file_operation_handler(func):
    """Decorator for file operation error handling"""
    @functools.wraps(func)
    def wrapper(path: Path, protocol_prefix: str = "", *args, **kwargs):
        tag = f"[{protocol_prefix}]" if protocol_prefix else ""
        func_name = func.__name__
        try:
            return func(path, protocol_prefix, *args, **kwargs)
        except IOError as e:
            print(f"❌ {tag} [{func_name}] Error processing file {path.name}: {e}")
        except Exception as e:
            print(f"❌ {tag} [{func_name}] Unexpected error: {e}")
    return wrapper

@file_operation_handler
def trim_trailing_zeros(path: Path, protocol_prefix: str = ""):
    """Remove trailing zeros from binary file"""
    with open(path, "rb") as f:
        data = f.read()
    end = len(data)
    while end > 0 and data[end - 1] == 0:
        end -= 1
    if end < len(data):
        with open(path, "wb") as f:
            f.write(data[:end])
        tag = f"[{protocol_prefix}]" if protocol_prefix else ""
        print(f"🔄 {tag} [trim] Removed {len(data) - end} trailing zero bytes from {path.name}")

@file_operation_handler
def hexdump_bin_file(filename: Path, protocol_prefix: str = "", bytes_count=16):
    """Display hexdump of binary file (first line only) similar to 'hexdump -C -n 16'"""
    with open(filename, 'rb') as f:
        data = f.read(bytes_count)

    if not data:
        print(f"[{protocol_prefix}] File {filename.name} is empty")
        return

    hex_groups = []
    for i in range(0, len(data), 8):
        group = data[i:i+8]
        hex_groups.append(' '.join(f'{b:02x}' for b in group))
    hex_line = '  '.join(hex_groups).ljust(47)
    ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in data)
    tag = f"[{protocol_prefix}]" if protocol_prefix else ""
    print(f"✅ {tag} [hexdump] 00000000  {hex_line}  |{ascii_part}|")

class ManagedSocket:
    """Wrapper for socket that ensures proper cleanup"""

    def __init__(self, sock_type: int):
        try:
            self._sock = socket.socket(socket.AF_INET, sock_type)
            self._is_closed = False
        except socket.error as e:
            raise RuntimeError(f"Failed to create socket: {e}")

    @property
    def sock(self) -> socket.socket:
        if self._is_closed:
            raise RuntimeError("Socket is closed")
        return self._sock

    def close(self):
        if not self._is_closed and self._sock:
            try:
                self._sock.close()
            except socket.error as e:
                print(f"⚠️ [warn] Error closing socket: {e}")
            finally:
                self._is_closed = True

    def __del__(self):
        self.close()

@contextmanager
def managed_tcp_connection(addr: Tuple[str, int]) -> Iterator[socket.socket]:
    """Context manager for TCP connection that ensures proper cleanup"""
    sock = None
    try:
        sock = socket.create_connection(addr, timeout=CAPTURE_TIMEOUT)
        yield sock
    except socket.timeout:
        print(f"❌ [tcp] Connection timeout to {addr}")
        raise
    except socket.error as e:
        print(f"❌ [tcp] Connection failed to {addr}: {e}")
        raise
    finally:
        if sock:
            try:
                sock.close()
            except socket.error:
                pass

class BaseProxyCapture:
    """Base class for proxy capture implementations"""

    def __init__(self, domain: str, remote_ip: str, protocol: str):
        self.domain = domain
        self.remote_ip = remote_ip
        self.protocol = protocol
        self.saved_path = OUT_DIR / f"{protocol}_{domain.replace('.', '_')}_{timestamp()}.bin"
        self.captured = None
        self.stop_event = threading.Event()
        self.local_port = None
        self.managed_sockets = []

    @property
    def prefix(self) -> str:
        return PROTOCOL_INFO.get(self.protocol, (self.protocol, ""))[0]

    @property
    def display_name(self) -> str:
        return PROTOCOL_INFO.get(self.protocol, (self.protocol, self.protocol.replace('_', ' ').title()))[1]

    def setup_socket(self, sock_type: int, bind_addr: tuple[str, int] = ("127.0.0.1", 0)) -> ManagedSocket:
        """Create and bind a socket safely, register it for cleanup"""
        sock_mgr = ManagedSocket(sock_type)
        safe_bind(sock_mgr.sock, bind_addr)
        self.managed_sockets.append(sock_mgr)
        return sock_mgr

    def get_curl_command(self) -> list[str]:
        """Get curl command for the specific protocol"""
        base_cmd = [
            CURL_CMD,
            "-ISs",
            "--tlsv1.3",
            "--connect-to", f"{self.domain}:443:127.0.0.1:{self.local_port}",
            "--max-time", str(CAPTURE_TIMEOUT),
            "--curves", "X25519",
            f"https://{self.domain}",
        ]
        if self.protocol == "quic_initial":
            base_cmd.insert(2, "--http3-only")
        return base_cmd

    def save_captured_data(self, data: bytes) -> None:
        """Save captured data to file"""
        try:
            self.captured = bytes(data)
            with open(self.saved_path, "wb") as f:
                f.write(self.captured)
            print(f"✅ [{self.prefix}] Saved {self.display_name} to {self.saved_path.name}")

            if self.protocol == "quic_initial":
                trim_trailing_zeros(self.saved_path, self.prefix)

            hexdump_bin_file(self.saved_path, self.prefix)
        except Exception as e:
            print(f"❌ [{self.prefix}] Error saving data: {e}")

    def run_capture(self) -> Path | None:
        """Main capture execution flow"""
        try:
            self.create_sockets()
            print(f"🔄 [{self.prefix}] Listening on 127.0.0.1:{self.local_port}, forwarding to {self.remote_ip}:443")

            th = threading.Thread(target=self.handle_proxy_loop, daemon=True)
            th.start()

            cmd = self.get_curl_command()
            print(f"🔄 [{self.prefix}] Running:", " ".join(cmd))

            try:
                result = subprocess.run(
                    cmd,
                    check=False,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                    timeout=CAPTURE_TIMEOUT + 1
                )

                if result.returncode not in (0, 28):
                    stderr_text = result.stderr.decode(errors="ignore").strip()
                    msg = f"⚠️ [{self.prefix}] curl exited ({result.returncode})"
                    if stderr_text:
                        msg += f": {stderr_text.splitlines()[-1]}"
                    print(msg)

            except FileNotFoundError:
                print(f"❌ [{self.prefix}] curl not found; please install curl")
                self.stop_event.set()
                return None
            except subprocess.TimeoutExpired:
                print(f"⚠️ [{self.prefix}] curl command timed out")
            except Exception as e:
                print(f"⚠️ [{self.prefix}] curl execution warning: {e}")

            th.join(timeout=2)
            self.stop_event.set()

            if self.saved_path.exists() and self.saved_path.stat().st_size > 0:
                return self.saved_path
            else:
                print(f"❌ [{self.prefix}] No data captured or file is empty")
                return None

        except socket.error as e:
            print(f"❌ [{self.prefix}] Network error: {e}")
            return None
        except IOError as e:
            print(f"❌ [{self.prefix}] I/O error: {e}")
            return None
        except Exception as e:
            print(f"❌ [{self.prefix}] Unexpected error: {e}")
            return None
        finally:
            self.cleanup()

    def cleanup(self) -> None:
        for managed_sock in self.managed_sockets:
            try:
                managed_sock.close()
            except Exception as e:
                print(f"⚠️ [{self.prefix}] Warning during socket cleanup: {e}")
        self.managed_sockets.clear()

class TCPProxyCapture(BaseProxyCapture):
    """TCP proxy for TLS ClientHello capture"""

    def __init__(self, domain: str, remote_ip: str):
        super().__init__(domain, remote_ip, "tls_clienthello")
        self.server_sock_manager = None

    def create_sockets(self) -> None:
        try:
            self.server_sock_manager = self.setup_socket(socket.SOCK_STREAM)
            self.server_sock_manager.sock.listen(1)
            self.local_port = self.server_sock_manager.sock.getsockname()[1]
        except Exception as e:
            print(f"❌ [tcp] Failed to create server socket: {e}")
            raise

    def handle_proxy_loop(self) -> None:
        try:
            server_sock = self.server_sock_manager.sock
            server_sock.settimeout(CAPTURE_TIMEOUT)

            try:
                client_sock, client_addr = server_sock.accept()
            except socket.timeout:
                print("⚠️ [tcp] No client connection received (timeout)")
                return

            with managed_tcp_connection((self.remote_ip, 443)) as remote_sock:
                first_data = client_sock.recv(MAX_BUFFER_SIZE)
                if first_data:
                    self.save_captured_data(first_data)
                    remote_sock.sendall(first_data)

                def forward(src, dst):
                    try:
                        while True:
                            data = src.recv(MAX_BUFFER_SIZE)
                            if not data:
                                break
                            dst.sendall(data)
                    except Exception:
                        pass

                t1 = threading.Thread(target=forward, args=(client_sock, remote_sock), daemon=True)
                t2 = threading.Thread(target=forward, args=(remote_sock, client_sock), daemon=True)
                t1.start()
                t2.start()
                t1.join(timeout=CAPTURE_TIMEOUT)
                t2.join(timeout=CAPTURE_TIMEOUT)

        except Exception as e:
            print(f"❌ [tcp] Proxy error: {e}")
        finally:
            self.stop_event.set()

class UDPProxyCapture(BaseProxyCapture):
    """UDP proxy for QUIC Initial capture"""

    def __init__(self, domain: str, remote_ip: str):
        super().__init__(domain, remote_ip, "quic_initial")
        self.sock_in_manager = None
        self.sock_out_manager = None

    def create_sockets(self) -> None:
        try:
            self.sock_in_manager = self.setup_socket(socket.SOCK_DGRAM)
            self.local_port = self.sock_in_manager.sock.getsockname()[1]
            self.sock_out_manager = self.setup_socket(socket.SOCK_DGRAM, ("0.0.0.0", 0))
        except Exception as e:
            print(f"❌ [udp] Failed to create UDP sockets: {e}")
            raise

    def handle_proxy_loop(self) -> None:
        try:
            sock_in = self.sock_in_manager.sock
            sock_out = self.sock_out_manager.sock
            sock_in.settimeout(CAPTURE_TIMEOUT)

            while not self.stop_event.is_set():
                try:
                    data, _ = sock_in.recvfrom(MAX_BUFFER_SIZE)
                except socket.timeout:
                    break
                if self.captured is None:
                    self.save_captured_data(data)
                try:
                    sock_out.sendto(data, (self.remote_ip, 443))
                except socket.error as e:
                    print(f"⚠️ [udp] Failed to send data: {e}")
        except Exception as e:
            print(f"❌ [udp] Proxy error: {e}")
        finally:
            self.stop_event.set()

def run_tcp_proxy_capture(domain: str, remote_ip: str) -> Path | None:
    """Capture TLS ClientHello using TCP proxy"""
    try:
        proxy = TCPProxyCapture(domain, remote_ip)
        return proxy.run_capture()
    except Exception as e:
        print(f"❌ [tcp] Capture setup failed: {e}")
        return None

def run_udp_proxy_capture(domain: str, remote_ip: str) -> Path | None:
    """Capture QUIC Initial using UDP proxy"""
    try:
        proxy = UDPProxyCapture(domain, remote_ip)
        return proxy.run_capture()
    except Exception as e:
        print(f"❌ [udp] Capture setup failed: {e}")
        return None

def main():
    parser = argparse.ArgumentParser(description="Capture TLS ClientHello / QUIC Initial")
    parser.add_argument("-t", action="store_true", help="Capture TLS ClientHello (default)")
    parser.add_argument("-q", action="store_true", help="Capture QUIC Initial")
    parser.add_argument("-a", action="store_true", help="Capture both TLS and QUIC")
    parser.add_argument("host", help="Target hostname (example.com)")
    args = parser.parse_args()

    if not (args.t or args.q or args.a):
        args.t = True

    host = args.host.strip()
    if not host:
        print("❌ Error: Host cannot be empty")
        return

    try:
        remote_ip = resolve_host(host)
        print(f"🔄 Resolved {host} -> {remote_ip}")
    except Exception as e:
        print(f"❌ {e}")
        return

    if args.a:
        run_tcp_proxy_capture(host, remote_ip)
        run_udp_proxy_capture(host, remote_ip)
        return

    success = False
    for attempt in range(1, RETRIES + 1):
        print(f"🔄 Attempt {attempt}/{RETRIES}")
        result = run_udp_proxy_capture(host, remote_ip) if args.q else run_tcp_proxy_capture(host, remote_ip)
        if result:
            success = True
            break
        if attempt < RETRIES:
            print("⏳ Retrying...")
            time.sleep(1)
    else:
        print("❌ All attempts failed")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n⏹️  Operation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Fatal error: {e}")
        sys.exit(1)
