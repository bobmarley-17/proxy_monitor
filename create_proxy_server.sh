##############################
# apps/proxy/proxy_server.py
##############################
cat > apps/proxy/proxy_server.py << 'PROXYEOF'
import socket
import threading
import select
import time
import os
import sys
import django
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
django.setup()

from apps.dashboard.models import ProxyRequest, DomainStats
from apps.blocklist.models import BlockedDomain
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync

class ProxyServer:
    def __init__(self, host='0.0.0.0', port=8080):
        self.host, self.port = host, port
        self.blocked = set()
        self.channel_layer = get_channel_layer()
    
    def load_blocklist(self):
        try:
            self.blocked = set(BlockedDomain.objects.filter(is_active=True).values_list('domain', flat=True))
            print(f"📋 Loaded {len(self.blocked)} blocked domains")
        except: self.blocked = set()
    
    def is_blocked(self, h):
        if not h: return False
        h = h.lower()
        if h in self.blocked: return True
        parts = h.split('.')
        for i in range(len(parts)):
            if '.'.join(parts[i:]) in self.blocked: return True
        return False
    
    def start(self):
        self.load_blocklist()
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.host, self.port))
        srv.listen(100)
        print(f"\n{'='*60}\n  🌐 PROXY SERVER STARTED\n  📍 Port: {self.port}\n  🔧 Configure browser: localhost:{self.port}\n{'='*60}\n")
        try:
            while True:
                c, a = srv.accept()
                threading.Thread(target=self.handle, args=(c, a), daemon=True).start()
        except KeyboardInterrupt: print("\n🛑 Stopped")
        finally: srv.close()
    
    def handle(self, client, addr):
        start = time.time()
        try:
            client.settimeout(30)
            data = client.recv(8192)
            if not data: client.close(); return
            parts = data.decode('utf-8', errors='ignore').split('\n')[0].split()
            if len(parts) < 2: client.close(); return
            method, url = parts[0], parts[1]
            if method == 'CONNECT': self.handle_https(client, url, addr, start)
            else: self.handle_http(client, data, method, url, addr, start)
        except: pass
        finally:
            try: client.close()
            except: pass
    
    def handle_http(self, client, data, method, url, addr, start):
        try:
            p = urlparse(url)
            host, port, path = p.hostname or '', p.port or 80, (p.path or '/') + ('?'+p.query if p.query else '')
            if self.is_blocked(host):
                self.send_blocked(client, host)
                self.log(method=method, url=url, hostname=host, path=path, status_code=403, blocked=True, response_time=int((time.time()-start)*1000), source_ip=addr[0])
                return
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.settimeout(10); srv.connect((host, port))
            req = data.decode('utf-8', errors='ignore')
            srv.sendall((f"{method} {path} HTTP/1.1" + req[req.find('\r\n'):]).encode())
            resp = b''
            while True:
                try:
                    chunk = srv.recv(8192)
                    if not chunk: break
                    resp += chunk; client.sendall(chunk)
                except: break
            srv.close()
            status = 0
            try: status = int(resp.split(b'\r\n')[0].decode().split()[1])
            except: pass
            self.log(method=method, url=url, hostname=host, path=path, status_code=status, content_length=len(resp), response_time=int((time.time()-start)*1000), blocked=False, source_ip=addr[0])
        except: pass
    
    def handle_https(self, client, url, addr, start):
        try:
            host, port = (url.split(':') + ['443'])[:2]; port = int(port)
            if self.is_blocked(host):
                client.sendall(b'HTTP/1.1 403 Forbidden\r\n\r\n')
                self.log(method='CONNECT', url=f"https://{url}", hostname=host, path='/', status_code=403, blocked=True, response_time=int((time.time()-start)*1000), source_ip=addr[0])
                return
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.settimeout(10); srv.connect((host, port))
            client.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
            self.log(method='CONNECT', url=f"https://{url}", hostname=host, path='/', status_code=200, blocked=False, response_time=int((time.time()-start)*1000), source_ip=addr[0])
            client.setblocking(False); srv.setblocking(False)
            socks = [client, srv]
            while socks:
                r, _, _ = select.select(socks, [], socks, 60)
                if not r: break
                for s in r:
                    try:
                        d = s.recv(8192)
                        if not d: socks = []; break
                        (srv if s is client else client).sendall(d)
                    except: socks = []; break
            srv.close()
        except: pass
    
    def send_blocked(self, client, host):
        body = f'<!DOCTYPE html><html><head><title>Blocked</title><style>body{{font-family:sans-serif;background:#1a1a2e;color:#fff;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}}.c{{text-align:center;padding:40px;background:rgba(255,255,255,.05);border-radius:20px}}h1{{color:#e94560}}.d{{background:#e94560;padding:8px 20px;border-radius:20px;display:inline-block}}</style></head><body><div class="c"><h1>🛡️ Blocked</h1><p>Access denied</p><div class="d">{host}</div></div></body></html>'
        client.sendall(f'HTTP/1.1 403 Forbidden\r\nContent-Type:text/html\r\nContent-Length:{len(body)}\r\n\r\n{body}'.encode())
    
    def log(self, **kw):
        try:
            req = ProxyRequest.objects.create(**kw)
            host = kw.get('hostname', '')
            stats, _ = DomainStats.objects.get_or_create(hostname=host)
            stats.request_count += 1
            if kw.get('blocked'): stats.blocked_count += 1
            stats.total_bytes += kw.get('content_length', 0)
            stats.save()
            if kw.get('blocked'):
                try: BlockedDomain.objects.filter(domain=host).update(hit_count=models.F('hit_count')+1)
                except: pass
            self.notify(req, stats)
            print(f"{kw.get('method',''):8} {host:40} {'🚫 BLOCKED' if kw.get('blocked') else '✓ '+str(kw.get('status_code','-'))}")
        except Exception as e: print(f"Log error: {e}")
    
    def notify(self, req, stats):
        try:
            from apps.dashboard.serializers import ProxyRequestListSerializer, DomainStatsSerializer
            rd = ProxyRequestListSerializer(req).data; rd['id'] = str(rd['id'])
            sd = DomainStatsSerializer(stats).data
            async_to_sync(self.channel_layer.group_send)('dashboard', {'type': 'new_request', 'request': rd})
            async_to_sync(self.channel_layer.group_send)('dashboard', {'type': 'stats_update', 'stats': sd})
        except: pass

def run_proxy(port=8080):
    ProxyServer(port=port).start()

if __name__ == '__main__':
    run_proxy()
PROXYEOF

##############################
# apps/proxy/management/commands/runproxy.py
##############################
cat > apps/proxy/management/commands/runproxy.py << 'EOF'
from django.core.management.base import BaseCommand
from django.conf import settings

class Command(BaseCommand):
    help = 'Run proxy server'
    
    def add_arguments(self, parser):
        parser.add_argument('--port', type=int, default=getattr(settings, 'PROXY_PORT', 8080))
    
    def handle(self, *args, **options):
        from apps.proxy.proxy_server import run_proxy
        self.stdout.write(self.style.SUCCESS(f"Starting proxy on port {options['port']}..."))
        run_proxy(options['port'])
EOF

echo "✅ Proxy server created!"
