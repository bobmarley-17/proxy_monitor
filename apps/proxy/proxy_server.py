import socket
import threading
import time
import sys
import os
import django
import select
import ipaddress
from django.db.models import F
from django.db import close_old_connections

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
django.setup()

from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
from apps.dashboard.models import ProxyRequest, DomainStats
from apps.blocklist.models import BlockedDomain, BlockedIP, BlockedPort, BlockRule

BUFFER_SIZE = 65536 * 2

# Performance tuning
MAX_CONNECTIONS = 1000
CLIENT_HEADER_TIMEOUT = 10
IDLE_TUNNEL_TIMEOUT = 120

_active_connections = 0
_conn_lock = threading.Lock()


# =========================================================
# SSRF protection
# =========================================================
def is_private_host(host):
    try:
        ip = ipaddress.ip_address(socket.gethostbyname(host))
        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
        )
    except Exception:
        return False


# =========================================================
# Blocklist checker
# =========================================================
def check_blocklist(hostname, src_ip=None, dest_ip=None, src_port=None, dest_port=None):
    """
    Check all blocklist rules. Returns (is_blocked, block_reason, block_type).
    """
    try:
        close_old_connections()

        # 1. Check domain blocklist
        domain_blocked, domain_rule = BlockedDomain.is_blocked(hostname)
        if domain_blocked:
            reason = f"Domain blocked: {domain_rule.domain}"
            if domain_rule.reason:
                reason += f" ({domain_rule.reason})"
            return True, reason, 'domain'

        # 2. Check source IP blocklist
        if src_ip:
            ip_blocked, ip_rule = BlockedIP.is_blocked(src_ip, 'source')
            if ip_blocked:
                reason = f"Source IP blocked: {ip_rule.ip_address}"
                if ip_rule.reason:
                    reason += f" ({ip_rule.reason})"
                return True, reason, 'source_ip'

        # 3. Check destination IP blocklist
        if dest_ip:
            ip_blocked, ip_rule = BlockedIP.is_blocked(dest_ip, 'destination')
            if ip_blocked:
                reason = f"Destination IP blocked: {ip_rule.ip_address}"
                if ip_rule.reason:
                    reason += f" ({ip_rule.reason})"
                return True, reason, 'dest_ip'

        # 4. Check destination port blocklist
        if dest_port:
            port_blocked, port_rule = BlockedPort.is_blocked(dest_port, 'destination')
            if port_blocked:
                reason = f"Port blocked: {port_rule.port}"
                if port_rule.reason:
                    reason += f" ({port_rule.reason})"
                return True, reason, 'port'

        # 5. Check source port blocklist
        if src_port:
            port_blocked, port_rule = BlockedPort.is_blocked(src_port, 'source')
            if port_blocked:
                reason = f"Source port blocked: {port_rule.port}"
                if port_rule.reason:
                    reason += f" ({port_rule.reason})"
                return True, reason, 'source_port'

        # 6. Check combined firewall rules
        action, rule = BlockRule.check_request(
            hostname=hostname,
            source_ip=src_ip,
            dest_ip=dest_ip,
            source_port=src_port,
            dest_port=dest_port
        )
        if action == 'block':
            reason = f"Rule blocked: {rule.name}"
            if rule.reason:
                reason += f" ({rule.reason})"
            return True, reason, 'rule'

        return False, None, None

    except Exception as e:
        print(f"[BLOCKLIST ERROR] {e}")
        return False, None, None


# =========================================================
# Database logging
# =========================================================
def log_request(method, hostname, url, src_ip, src_port, dest_ip, dest_port,
                status_code, content_length, response_time, blocked,
                block_reason=None, block_type=None):
    """Log request to database and broadcast via WebSocket."""
    try:
        close_old_connections()

        req = ProxyRequest.objects.create(
            method=method,
            hostname=hostname,
            url=url or hostname,
            source_ip=src_ip,
            source_port=src_port,
            destination_ip=dest_ip or '',
            destination_port=dest_port or 0,
            status_code=status_code,
            content_length=content_length or 0,
            response_time=round(response_time, 3),
            blocked=blocked,
            block_reason=block_reason or '',
            block_type=block_type or '',
        )

        # Update domain stats
        DomainStats.objects.update_or_create(
            domain=hostname,
            defaults={}
        )
        stats_update = {'request_count': F('request_count') + 1}
        if blocked:
            stats_update['blocked_count'] = F('blocked_count') + 1
        if content_length:
            stats_update['total_bytes'] = F('total_bytes') + content_length
        DomainStats.objects.filter(domain=hostname).update(**stats_update)

        # Broadcast via WebSocket
        try:
            channel_layer = get_channel_layer()
            async_to_sync(channel_layer.group_send)(
                'proxy_updates',
                {
                    'type': 'proxy_request',
                    'data': {
                        'id': str(req.id),
                        'method': method,
                        'hostname': hostname,
                        'url': url or hostname,
                        'status_code': status_code,
                        'blocked': blocked,
                        'block_reason': block_reason or '',
                        'response_time': round(response_time, 3),
                        'source_ip': src_ip,
                        'timestamp': req.timestamp.isoformat() if req.timestamp else '',
                    }
                }
            )
        except Exception:
            pass

    except Exception as e:
        print(f"[LOG ERROR] {e}")


# =========================================================
# Proxy Server
# =========================================================
class ProxyServer:
    def __init__(self, host='0.0.0.0', port=8088):
        self.host = host
        self.port = int(port)
        self.channel_layer = get_channel_layer()

    def start(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        srv.bind((self.host, self.port))
        srv.listen(500)

        print(f"\n{'='*60}")
        print(f"  PROXY SERVER STARTED")
        print(f"  Listening on: {self.host}:{self.port}")
        print(f"  Blocklist enforcement: ENABLED")
        print(f"  Max connections: {MAX_CONNECTIONS}")
        print(f"{'='*60}\n")

        # Show blocklist stats on startup
        try:
            print(f"  Blocked domains:  {BlockedDomain.objects.filter(is_active=True).count()}")
            print(f"  Blocked IPs:      {BlockedIP.objects.filter(is_active=True).count()}")
            print(f"  Blocked ports:    {BlockedPort.objects.filter(is_active=True).count()}")
            print(f"  Firewall rules:   {BlockRule.objects.filter(is_active=True).count()}")
            print(f"{'='*60}\n")
        except Exception:
            pass

        while True:
            try:
                client, addr = srv.accept()

                if not self._acquire_slot():
                    client.close()
                    continue

                client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

                threading.Thread(
                    target=self.handle_client,
                    args=(client, addr),
                    daemon=True
                ).start()

            except KeyboardInterrupt:
                break

    def _acquire_slot(self):
        global _active_connections
        with _conn_lock:
            if _active_connections >= MAX_CONNECTIONS:
                return False
            _active_connections += 1
            return True

    def _release_slot(self):
        global _active_connections
        with _conn_lock:
            _active_connections -= 1

    # ---------------------------------------------------------
    # CLIENT HANDLER
    # ---------------------------------------------------------
    def handle_client(self, client, addr):
        start = time.time()
        peer_ip, src_port = addr[0], addr[1]

        try:
            client.settimeout(CLIENT_HEADER_TIMEOUT)

            data = client.recv(BUFFER_SIZE)
            if not data:
                return

            first_line = data.split(b'\r\n')[0].decode(errors='ignore')
            parts = first_line.split()
            if len(parts) < 2:
                return

            method = parts[0]
            target = parts[1]

            if method == 'CONNECT':
                self.handle_connect(client, target, peer_ip, src_port, start)
            else:
                self.handle_http(client, data, method, target, peer_ip, src_port, start)

        except socket.timeout:
            pass
        except Exception:
            pass
        finally:
            try:
                client.close()
            except:
                pass
            self._release_slot()

    # ---------------------------------------------------------
    # TUNNEL
    # ---------------------------------------------------------
    def tunnel(self, client, server):
        sockets = [client, server]
        last_activity = time.time()

        try:
            while True:
                readable, _, exceptional = select.select(
                    sockets, [], sockets, 10
                )

                now = time.time()

                if now - last_activity > IDLE_TUNNEL_TIMEOUT:
                    break

                if exceptional:
                    break

                if not readable:
                    continue

                for sock in readable:
                    data = sock.recv(BUFFER_SIZE)
                    if not data:
                        return

                    last_activity = now

                    if sock is client:
                        server.sendall(data)
                    else:
                        client.sendall(data)

        finally:
            try:
                server.close()
            except:
                pass

    # ---------------------------------------------------------
    # CONNECT (HTTPS)
    # ---------------------------------------------------------
    def handle_connect(self, client, target, src_ip, src_port, start):
        server = None
        try:
            if ':' in target:
                host, port = target.split(':')
                port = int(port)
            else:
                host = target
                port = 443

            # --- BLOCKLIST CHECK ---
            is_blocked, block_reason, block_type = check_blocklist(
                hostname=host,
                src_ip=src_ip,
                dest_port=port,
                src_port=src_port,
            )

            if is_blocked:
                client.sendall(b'HTTP/1.1 403 Forbidden\r\n'
                              b'Content-Type: text/plain\r\n'
                              b'Connection: close\r\n\r\n'
                              b'Blocked by proxy policy')
                elapsed = time.time() - start
                log_request(
                    method='CONNECT', hostname=host, url=target,
                    src_ip=src_ip, src_port=src_port,
                    dest_ip=None, dest_port=port,
                    status_code=403, content_length=0,
                    response_time=elapsed, blocked=True,
                    block_reason=block_reason, block_type=block_type,
                )
                print(f"  [BLOCKED] CONNECT {host}:{port} from {src_ip} - {block_reason}")
                return

            # --- SSRF protection ---
            if is_private_host(host):
                client.sendall(b'HTTP/1.1 403 Forbidden\r\n\r\n')
                elapsed = time.time() - start
                log_request(
                    method='CONNECT', hostname=host, url=target,
                    src_ip=src_ip, src_port=src_port,
                    dest_ip=None, dest_port=port,
                    status_code=403, content_length=0,
                    response_time=elapsed, blocked=True,
                    block_reason='Private/internal host blocked (SSRF)',
                    block_type='ssrf',
                )
                return

            # --- CONNECT to remote ---
            server = socket.create_connection((host, port), timeout=10)
            server.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

            # Get resolved destination IP
            dest_ip = server.getpeername()[0] if server else None

            # Check destination IP blocklist after DNS resolution
            if dest_ip:
                ip_blocked, ip_reason, ip_type = check_blocklist(
                    hostname=host,
                    src_ip=src_ip,
                    dest_ip=dest_ip,
                    dest_port=port,
                    src_port=src_port,
                )
                if ip_blocked and ip_type in ('dest_ip',):
                    server.close()
                    client.sendall(b'HTTP/1.1 403 Forbidden\r\n\r\n'
                                  b'Blocked by proxy policy')
                    elapsed = time.time() - start
                    log_request(
                        method='CONNECT', hostname=host, url=target,
                        src_ip=src_ip, src_port=src_port,
                        dest_ip=dest_ip, dest_port=port,
                        status_code=403, content_length=0,
                        response_time=elapsed, blocked=True,
                        block_reason=ip_reason, block_type=ip_type,
                    )
                    print(f"  [BLOCKED] CONNECT {host}:{port} dest_ip={dest_ip} - {ip_reason}")
                    return

            client.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')

            # Log allowed connection
            elapsed = time.time() - start
            log_request(
                method='CONNECT', hostname=host, url=target,
                src_ip=src_ip, src_port=src_port,
                dest_ip=dest_ip, dest_port=port,
                status_code=200, content_length=0,
                response_time=elapsed, blocked=False,
            )

            self.tunnel(client, server)

        except Exception as e:
            try:
                client.sendall(b'HTTP/1.1 502 Bad Gateway\r\n\r\n')
            except:
                pass
            # Log error
            elapsed = time.time() - start
            try:
                host_name = target.split(':')[0] if ':' in target else target
                log_request(
                    method='CONNECT', hostname=host_name, url=target,
                    src_ip=src_ip, src_port=src_port,
                    dest_ip=None, dest_port=443,
                    status_code=502, content_length=0,
                    response_time=elapsed, blocked=False,
                )
            except:
                pass
        finally:
            try:
                if server:
                    server.close()
            except:
                pass

    # ---------------------------------------------------------
    # HTTP (plain)
    # ---------------------------------------------------------
    def handle_http(self, client, data, method, target, src_ip, src_port, start):
        server = None
        try:
            if target.startswith('http://'):
                target_clean = target[7:]
            else:
                target_clean = target

            host = target_clean.split('/')[0]
            path = '/' + '/'.join(target_clean.split('/')[1:]) if '/' in target_clean else '/'
            port = 80

            if ':' in host:
                host, port = host.rsplit(':', 1)
                port = int(port)

            # --- BLOCKLIST CHECK ---
            is_blocked, block_reason, block_type = check_blocklist(
                hostname=host,
                src_ip=src_ip,
                dest_port=port,
                src_port=src_port,
            )

            if is_blocked:
                block_response = (
                    b'HTTP/1.1 403 Forbidden\r\n'
                    b'Content-Type: text/html\r\n'
                    b'Connection: close\r\n\r\n'
                    b'<html><body><h1>403 Forbidden</h1>'
                    b'<p>This site has been blocked by proxy policy.</p>'
                    b'</body></html>'
                )
                client.sendall(block_response)
                elapsed = time.time() - start
                log_request(
                    method=method, hostname=host, url=target,
                    src_ip=src_ip, src_port=src_port,
                    dest_ip=None, dest_port=port,
                    status_code=403, content_length=0,
                    response_time=elapsed, blocked=True,
                    block_reason=block_reason, block_type=block_type,
                )
                print(f"  [BLOCKED] {method} {host}{path} from {src_ip} - {block_reason}")
                return

            # --- SSRF protection ---
            if is_private_host(host):
                client.sendall(b'HTTP/1.1 403 Forbidden\r\n\r\n')
                elapsed = time.time() - start
                log_request(
                    method=method, hostname=host, url=target,
                    src_ip=src_ip, src_port=src_port,
                    dest_ip=None, dest_port=port,
                    status_code=403, content_length=0,
                    response_time=elapsed, blocked=True,
                    block_reason='Private/internal host blocked (SSRF)',
                    block_type='ssrf',
                )
                return

            # --- Forward request ---
            server = socket.create_connection((host, port), timeout=10)
            server.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

            dest_ip = server.getpeername()[0] if server else None

            server.sendall(data)

            response_data = b''
            content_length = 0
            status_code = 0

            while True:
                try:
                    server.settimeout(10)
                    response = server.recv(BUFFER_SIZE)
                    if not response:
                        break
                    if not response_data:
                        # Parse status from first chunk
                        try:
                            status_line = response.split(b'\r\n')[0].decode(errors='ignore')
                            status_parts = status_line.split()
                            if len(status_parts) >= 2:
                                status_code = int(status_parts[1])
                        except:
                            pass
                    response_data += response
                    content_length += len(response)
                    client.sendall(response)
                except socket.timeout:
                    break

            elapsed = time.time() - start
            log_request(
                method=method, hostname=host, url=target,
                src_ip=src_ip, src_port=src_port,
                dest_ip=dest_ip, dest_port=port,
                status_code=status_code or 200, content_length=content_length,
                response_time=elapsed, blocked=False,
            )

        except Exception as e:
            try:
                client.sendall(b'HTTP/1.1 502 Bad Gateway\r\n\r\n')
            except:
                pass
            elapsed = time.time() - start
            try:
                host_name = target.split('/')[0] if '/' in target else target
                if host_name.startswith('http://'):
                    host_name = host_name[7:]
                log_request(
                    method=method, hostname=host_name, url=target,
                    src_ip=src_ip, src_port=src_port,
                    dest_ip=None, dest_port=80,
                    status_code=502, content_length=0,
                    response_time=elapsed, blocked=False,
                )
            except:
                pass
        finally:
            try:
                if server:
                    server.close()
            except:
                pass


def run_proxy(port=8088):
    ProxyServer(port=port).start()


if __name__ == '__main__':
    ProxyServer().start()
