import socket
import threading
import time
import os
import sys
import django
from urllib.parse import urlparse
from django.db.models import F
from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
django.setup()

from apps.dashboard.models import ProxyRequest, DomainStats
from apps.blocklist.models import BlockedDomain

BUFFER_SIZE = 65536 * 2


class ProxyServer:
    def __init__(self, host='0.0.0.0', port=8080):
        self.host = host
        self.port = int(port)
        self.blocked = set()
        self.blocked_domains_map = {}  # domain -> id mapping for hit tracking
        self.channel_layer = get_channel_layer()

    def load_blocklist(self):
        try:
            blocked_entries = BlockedDomain.objects.filter(is_active=True)
            self.blocked = set(blocked_entries.values_list('domain', flat=True))
            self.blocked_domains_map = {b.domain: b.id for b in blocked_entries}
            print(f"📋 Loaded {len(self.blocked)} blocked domains")
        except Exception as e:
            print(f"Error loading blocklist: {e}")
            self.blocked = set()
            self.blocked_domains_map = {}

    def is_blocked(self, h):
        if not h:
            return False, None
        h = h.lower().split(':')[0]
        
        # Exact match
        if h in self.blocked:
            return True, self.blocked_domains_map.get(h)
        
        # Subdomain match
        parts = h.split('.')
        for i in range(len(parts)):
            parent = '.'.join(parts[i:])
            if parent in self.blocked:
                return True, self.blocked_domains_map.get(parent)
        
        return False, None

    def increment_hit_count(self, domain_id):
        """Increment hit count for blocked domain"""
        if domain_id:
            try:
                BlockedDomain.objects.filter(id=domain_id).update(hit_count=F('hit_count') + 1)
            except Exception as e:
                print(f"Error updating hit count: {e}")

    def start(self):
        self.load_blocklist()
        srv = None
        
        try:
            srv = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            srv.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            bind_host = '::' if self.host == '0.0.0.0' else self.host
            srv.bind((bind_host, self.port))
            print(f"\n{'='*60}\n  🌐 PROXY STARTED (Dual Stack)\n  📍 Port: {self.port}\n{'='*60}\n")
        except Exception as e:
            print(f"⚠️ IPv6 failed ({e}), using IPv4...")
            if srv:
                srv.close()
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((self.host, self.port))
            print(f"\n{'='*60}\n  🌐 PROXY STARTED (IPv4)\n  📍 Port: {self.port}\n{'='*60}\n")

        srv.listen(200)
        
        try:
            while True:
                c, a = srv.accept()
                threading.Thread(target=self.handle, args=(c, a), daemon=True).start()
        except KeyboardInterrupt:
            print("\n🛑 Stopped")
        finally:
            srv.close()

    def handle(self, client, addr):
        start = time.time()
        src_ip, src_port = addr[0], addr[1]
        
        try:
            client.settimeout(60)
            data = client.recv(BUFFER_SIZE)
            if not data:
                client.close()
                return
            
            first_line = data.split(b'\n')[0].decode('iso-8859-1').strip()
            parts = first_line.split()
            if len(parts) < 2:
                client.close()
                return
            
            method, url = parts[0], parts[1]
            
            if method == 'CONNECT':
                self.handle_https(client, url, src_ip, src_port, start)
            else:
                self.handle_http(client, data, method, url, src_ip, src_port, start)
        except Exception:
            client.close()

    def handle_http(self, client, data, method, url, src_ip, src_port, start):
        server = None
        try:
            p = urlparse(url)
            host = p.hostname or ''
            port = p.port or 80
            
            is_blocked, blocked_id = self.is_blocked(host)
            if is_blocked:
                self.send_blocked(client, host)
                self.increment_hit_count(blocked_id)
                self.log(method, host, 403, True, start, src_ip, src_port, "0.0.0.0", 0, 0)
                client.close()
                return

            str_data = data.decode('iso-8859-1')
            if 'Connection: keep-alive' in str_data:
                str_data = str_data.replace('Connection: keep-alive', 'Connection: close')
            elif 'Connection: close' not in str_data:
                idx = str_data.find('\r\n\r\n')
                if idx != -1:
                    str_data = str_data[:idx] + '\r\nConnection: close' + str_data[idx:]
            data = str_data.encode('iso-8859-1')

            server = socket.create_connection((host, port), timeout=15)
            
            try:
                dst_info = server.getpeername()
                dst_ip, dst_port = dst_info[0], dst_info[1]
            except:
                dst_ip, dst_port = host, port

            server.sendall(data)
            
            total = 0
            while True:
                chunk = server.recv(BUFFER_SIZE)
                if not chunk:
                    break
                client.sendall(chunk)
                total += len(chunk)
            
            self.log(method, host, 200, False, start, src_ip, src_port, dst_ip, dst_port, total)
            
        except Exception:
            pass
        finally:
            try:
                client.close()
            except:
                pass
            try:
                if server:
                    server.close()
            except:
                pass

    def handle_https(self, client, url, src_ip, src_port, start):
        server = None
        try:
            host = url.split(':')[0]
            port = 443
            if ':' in url:
                try:
                    port = int(url.split(':')[1])
                except:
                    pass

            is_blocked, blocked_id = self.is_blocked(host)
            if is_blocked:
                client.sendall(b'HTTP/1.1 403 Forbidden\r\n\r\n')
                self.increment_hit_count(blocked_id)
                self.log('CONNECT', host, 403, True, start, src_ip, src_port, "0.0.0.0", 0, 0)
                client.close()
                return

            server = socket.create_connection((host, port), timeout=15)
            
            try:
                dst_info = server.getpeername()
                dst_ip, dst_port = dst_info[0], dst_info[1]
            except:
                dst_ip, dst_port = host, port

            client.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
            self.log('CONNECT', host, 200, False, start, src_ip, src_port, dst_ip, dst_port, 0)

            client.settimeout(None)
            server.settimeout(None)

            def forward(source, destination):
                try:
                    while True:
                        data = source.recv(BUFFER_SIZE)
                        if not data:
                            break
                        destination.sendall(data)
                except:
                    pass
                finally:
                    try:
                        source.shutdown(socket.SHUT_RD)
                    except:
                        pass
                    try:
                        destination.shutdown(socket.SHUT_WR)
                    except:
                        pass

            t1 = threading.Thread(target=forward, args=(client, server), daemon=True)
            t2 = threading.Thread(target=forward, args=(server, client), daemon=True)
            t1.start()
            t2.start()
            
        except Exception:
            try:
                client.close()
            except:
                pass
            if server:
                try:
                    server.close()
                except:
                    pass

    def send_blocked(self, client, host):
        body = f'''<!DOCTYPE html>
<html><head><title>Blocked</title>
<style>body{{font-family:system-ui;background:#0f172a;color:#fff;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}}
.c{{text-align:center;padding:40px;background:#1e293b;border-radius:20px;border:1px solid #334155}}
h1{{color:#ef4444;margin-bottom:10px}}
.d{{background:#ef4444;padding:10px 20px;border-radius:10px;display:inline-block;margin-top:15px;font-family:monospace}}</style></head>
<body><div class="c"><h1>🚫 Access Blocked</h1><p>This site has been blocked by your administrator.</p><div class="d">{host}</div></div></body></html>'''
        try:
            client.sendall(f'HTTP/1.1 403 Forbidden\r\nContent-Type:text/html\r\nContent-Length:{len(body)}\r\nConnection:close\r\n\r\n{body}'.encode())
        except:
            pass

    def log(self, method, host, status, blocked, start, src_ip, src_port, dst_ip, dst_port, size):
        threading.Thread(
            target=self._log_db,
            args=(method, host, status, blocked, start, src_ip, src_port, dst_ip, dst_port, size),
            daemon=True
        ).start()

    def _log_db(self, method, host, status, blocked, start, src_ip, src_port, dst_ip, dst_port, size):
        try:
            print(f"{method:8} {host[:30]:30} {src_ip}:{src_port}->{dst_ip}:{dst_port} {'🚫' if blocked else '✓'}")
            
            DomainStats.objects.filter(hostname=host).update(
                request_count=F('request_count') + 1,
                total_bytes=F('total_bytes') + size,
                blocked_count=F('blocked_count') + (1 if blocked else 0)
            )
            if not DomainStats.objects.filter(hostname=host).exists():
                DomainStats.objects.create(
                    hostname=host,
                    request_count=1,
                    total_bytes=size,
                    blocked_count=1 if blocked else 0
                )

            req = ProxyRequest.objects.create(
                method=method,
                url=f"https://{host}" if method == 'CONNECT' else f"http://{host}",
                hostname=host,
                status_code=status,
                blocked=blocked,
                response_time=int((time.time() - start) * 1000),
                content_length=size,
                source_ip=src_ip,
                source_port=int(src_port),
                destination_ip=str(dst_ip),
                destination_port=int(dst_port)
            )
            self.notify(req)
        except Exception as e:
            print(f"Log Error: {e}")

    def notify(self, req):
        try:
            from apps.dashboard.serializers import ProxyRequestListSerializer
            rd = ProxyRequestListSerializer(req).data
            rd['id'] = str(rd['id'])
            async_to_sync(self.channel_layer.group_send)('dashboard', {'type': 'new_request', 'request': rd})
        except:
            pass


def run_proxy(port=8080):
    server = ProxyServer(port=port)
    server.start()


if __name__ == '__main__':
    run_proxy()
