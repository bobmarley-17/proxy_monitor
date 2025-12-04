import socket
import threading
import time
import sys
import os
import django
from django.db.models import F

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
django.setup()

from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
from apps.dashboard.models import ProxyRequest, DomainStats
from apps.blocklist.models import BlockedDomain

BUFFER_SIZE = 65536 * 2


class ProxyServer:
    def __init__(self, host='0.0.0.0', port=8088):
        self.host = host
        self.port = int(port)
        self.blocked = set()
        self.blocked_domains_map = {}
        self.channel_layer = get_channel_layer()

    def load_blocklist(self):
        """Load blocked domains from database"""
        try:
            blocked_entries = BlockedDomain.objects.filter(is_active=True)
            self.blocked = set(blocked_entries.values_list('domain', flat=True))
            self.blocked_domains_map = {b.domain: b.id for b in blocked_entries}
            print(f"📋 Loaded {len(self.blocked)} blocked patterns:")
            for domain in self.blocked:
                print(f"   - {domain}")
        except Exception as e:
            print(f"Error loading blocklist: {e}")
            self.blocked = set()
            self.blocked_domains_map = {}

    def reload_blocklist(self):
        """Reload blocklist from database"""
        self.load_blocklist()

    def is_blocked(self, h):
        """Check if hostname should be blocked
        
        Supports patterns:
        - Exact match: youtube.com
        - Subdomain wildcard: *.youtube.com (blocks youtube.com and all subdomains)
        - Contains wildcard: *cric* (blocks anything containing 'cric')
        - Starts with: cric* (blocks anything starting with 'cric')
        - Ends with: *cric (blocks anything ending with 'cric')
        """
        if not h:
            return False, None

        # Clean hostname - remove port and convert to lowercase
        h = h.lower().split(':')[0].strip()

        for domain in self.blocked:
            pattern = domain.lower().strip()

            # Skip empty patterns
            if not pattern:
                continue

            # Pattern: *cric* (contains)
            if pattern.startswith('*') and pattern.endswith('*') and len(pattern) > 2:
                search_term = pattern[1:-1]  # Remove * from both ends
                if search_term in h:
                    print(f"🚫 BLOCKED: {h} contains '{search_term}' (pattern: {pattern})")
                    return True, self.blocked_domains_map.get(domain)
            
            # Pattern: *.youtube.com (subdomain wildcard)
            elif pattern.startswith('*.') and not pattern.endswith('*'):
                base_domain = pattern[2:]  # Remove *. prefix
                
                # Match exact base domain
                if h == base_domain:
                    print(f"🚫 BLOCKED: {h} matches {pattern} (exact base)")
                    return True, self.blocked_domains_map.get(domain)
                
                # Match subdomains
                if h.endswith('.' + base_domain):
                    print(f"🚫 BLOCKED: {h} matches {pattern} (subdomain)")
                    return True, self.blocked_domains_map.get(domain)
            
            # Pattern: cric* (starts with)
            elif pattern.endswith('*') and not pattern.startswith('*'):
                prefix = pattern[:-1]  # Remove * from end
                if h.startswith(prefix):
                    print(f"🚫 BLOCKED: {h} starts with '{prefix}' (pattern: {pattern})")
                    return True, self.blocked_domains_map.get(domain)
            
            # Pattern: *cric (ends with)
            elif pattern.startswith('*') and not pattern.endswith('*') and not pattern.startswith('*.'):
                suffix = pattern[1:]  # Remove * from start
                if h.endswith(suffix):
                    print(f"🚫 BLOCKED: {h} ends with '{suffix}' (pattern: {pattern})")
                    return True, self.blocked_domains_map.get(domain)
            
            # Exact match: youtube.com
            elif h == pattern:
                print(f"🚫 BLOCKED: {h} matches {pattern} (exact)")
                return True, self.blocked_domains_map.get(domain)
            
            # Parent domain match: youtube.com also blocks www.youtube.com
            elif h.endswith('.' + pattern):
                print(f"🚫 BLOCKED: {h} matches {pattern} (parent domain)")
                return True, self.blocked_domains_map.get(domain)

        return False, None

    def increment_hit_count(self, domain_id):
        """Increment hit count for blocked domain"""
        if domain_id:
            try:
                BlockedDomain.objects.filter(id=domain_id).update(hit_count=F('hit_count') + 1)
            except Exception as e:
                print(f"Error updating hit count: {e}")

    def start(self):
        """Start the proxy server"""
        self.load_blocklist()
        srv = None

        # Try IPv6 dual-stack first, fall back to IPv4
        try:
            srv = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            srv.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            bind_host = '::' if self.host == '0.0.0.0' else self.host
            srv.bind((bind_host, self.port))
            print(f"\n{'='*60}")
            print(f"  🌐 PROXY SERVER STARTED (Dual Stack IPv4/IPv6)")
            print(f"  📍 Listening on: {self.host}:{self.port}")
            print(f"  🚫 Blocked patterns: {len(self.blocked)}")
            print(f"{'='*60}\n")
        except Exception as e:
            print(f"⚠️ IPv6 dual-stack failed ({e}), using IPv4...")
            if srv:
                srv.close()
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((self.host, self.port))
            print(f"\n{'='*60}")
            print(f"  🌐 PROXY SERVER STARTED (IPv4 Only)")
            print(f"  📍 Listening on: {self.host}:{self.port}")
            print(f"  🚫 Blocked patterns: {len(self.blocked)}")
            print(f"{'='*60}\n")

        srv.listen(200)

        while True:
            try:
                client, addr = srv.accept()
                threading.Thread(target=self.handle_client, args=(client, addr), daemon=True).start()
            except KeyboardInterrupt:
                print("\n🛑 Proxy server shutting down...")
                break
            except Exception as e:
                print(f"Accept error: {e}")

    def handle_client(self, client, addr):
        """Handle incoming client connection"""
        start = time.time()

        # Extract source IP and port
        if len(addr) == 2:
            src_ip, src_port = addr
        else:
            src_ip, src_port = addr[0], addr[1]

        # Normalize IPv6-mapped IPv4 addresses
        if isinstance(src_ip, str) and src_ip.startswith('::ffff:'):
            src_ip = src_ip[7:]

        try:
            client.settimeout(30)
            data = client.recv(BUFFER_SIZE)
            if not data:
                client.close()
                return

            # Parse the request
            try:
                first_line = data.split(b'\r\n')[0].decode('utf-8', errors='ignore')
                parts = first_line.split()
                if len(parts) < 2:
                    client.close()
                    return
                method = parts[0]
                target = parts[1]
            except Exception as e:
                print(f"Parse error: {e}")
                client.close()
                return

            if method == 'CONNECT':
                self.handle_connect(client, target, src_ip, src_port, start)
            else:
                self.handle_http(client, data, method, target, src_ip, src_port, start)

        except socket.timeout:
            pass
        except Exception as e:
            print(f"Client handler error: {e}")
        finally:
            try:
                client.close()
            except:
                pass

    def handle_connect(self, client, target, src_ip, src_port, start):
        """Handle HTTPS CONNECT requests"""
        try:
            if ':' in target:
                host, port = target.split(':')
                port = int(port)
            else:
                host = target
                port = 443

            # Check if blocked
            is_blocked, blocked_id = self.is_blocked(host)
            if is_blocked:
                self.send_blocked(client, host)
                self.increment_hit_count(blocked_id)
                self.log('CONNECT', host, 403, True, start, src_ip, src_port, "0.0.0.0", 0, 0)
                client.close()
                return

            # Connect to target server
            server = socket.create_connection((host, port), timeout=15)

            try:
                dst_info = server.getpeername()
                dst_ip, dst_port = dst_info[0], dst_info[1]
            except:
                dst_ip, dst_port = host, port

            # Send connection established
            client.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
            self.log('CONNECT', host, 200, False, start, src_ip, src_port, dst_ip, dst_port, 0)

            client.settimeout(None)
            server.settimeout(None)

            # Tunnel data between client and server
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
                        source.close()
                    except:
                        pass
                    try:
                        destination.close()
                    except:
                        pass

            t1 = threading.Thread(target=forward, args=(client, server), daemon=True)
            t2 = threading.Thread(target=forward, args=(server, client), daemon=True)
            t1.start()
            t2.start()
            t1.join()
            t2.join()

        except Exception as e:
            print(f"CONNECT error for {target}: {e}")
            try:
                client.sendall(b'HTTP/1.1 502 Bad Gateway\r\n\r\n')
            except:
                pass

    def handle_http(self, client, data, method, target, src_ip, src_port, start):
        """Handle HTTP requests"""
        try:
            # Parse URL
            if target.startswith('http://'):
                target = target[7:]
            
            if '/' in target:
                host_part, path = target.split('/', 1)
                path = '/' + path
            else:
                host_part = target
                path = '/'

            if ':' in host_part:
                host, port = host_part.split(':')
                port = int(port)
            else:
                host = host_part
                port = 80

            # Check if blocked
            is_blocked, blocked_id = self.is_blocked(host)
            if is_blocked:
                self.send_blocked(client, host)
                self.increment_hit_count(blocked_id)
                self.log(method, host, 403, True, start, src_ip, src_port, "0.0.0.0", 0, 0)
                client.close()
                return

            # Modify request - change Connection header
            str_data = data.decode('iso-8859-1')
            if 'Connection: keep-alive' in str_data:
                str_data = str_data.replace('Connection: keep-alive', 'Connection: close')
            elif 'Connection: close' not in str_data:
                idx = str_data.find('\r\n\r\n')
                if idx != -1:
                    str_data = str_data[:idx] + '\r\nConnection: close' + str_data[idx:]
            data = str_data.encode('iso-8859-1')

            # Connect to target server
            server = socket.create_connection((host, port), timeout=15)

            try:
                dst_info = server.getpeername()
                dst_ip, dst_port = dst_info[0], dst_info[1]
            except:
                dst_ip, dst_port = host, port

            # Send request to server
            server.sendall(data)

            # Receive and forward response
            total_size = 0
            while True:
                response = server.recv(BUFFER_SIZE)
                if not response:
                    break
                total_size += len(response)
                client.sendall(response)

            server.close()
            self.log(method, host, 200, False, start, src_ip, src_port, dst_ip, dst_port, total_size)

        except Exception as e:
            print(f"HTTP error for {target}: {e}")
            try:
                client.sendall(b'HTTP/1.1 502 Bad Gateway\r\n\r\n')
            except:
                pass

    def send_blocked(self, client, host):
        """Send blocked page to client"""
        body = f'''<!DOCTYPE html>
<html>
<head>
    <title>Access Blocked</title>
    <style>
        body {{
            font-family: system-ui, -apple-system, sans-serif;
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
            color: #fff;
            display: flex;
            align-items: center;
            justify-content: center;
            height: 100vh;
            margin: 0;
        }}
        .container {{
            text-align: center;
            padding: 60px;
            background: rgba(30, 41, 59, 0.8);
            border-radius: 24px;
            border: 1px solid #334155;
            box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
            max-width: 500px;
        }}
        .icon {{
            font-size: 80px;
            margin-bottom: 20px;
        }}
        h1 {{
            color: #ef4444;
            margin-bottom: 10px;
            font-size: 32px;
        }}
        p {{
            color: #94a3b8;
            font-size: 18px;
            margin-bottom: 30px;
        }}
        .domain {{
            background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%);
            padding: 15px 30px;
            border-radius: 12px;
            display: inline-block;
            font-family: monospace;
            font-size: 18px;
            font-weight: bold;
        }}
        .footer {{
            margin-top: 30px;
            color: #64748b;
            font-size: 14px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">🚫</div>
        <h1>Access Blocked</h1>
        <p>This website has been blocked by your network administrator.</p>
        <div class="domain">{host}</div>
        <div class="footer">
            If you believe this is an error, please contact your administrator.
        </div>
    </div>
</body>
</html>'''
        try:
            response = f'HTTP/1.1 403 Forbidden\r\n'
            response += f'Content-Type: text/html; charset=utf-8\r\n'
            response += f'Content-Length: {len(body)}\r\n'
            response += f'Connection: close\r\n'
            response += f'\r\n'
            response += body
            client.sendall(response.encode('utf-8'))
        except:
            pass

    def log(self, method, host, status, blocked, start, src_ip, src_port, dst_ip, dst_port, size):
        """Log request asynchronously"""
        threading.Thread(
            target=self._log_db,
            args=(method, host, status, blocked, start, src_ip, src_port, dst_ip, dst_port, size),
            daemon=True
        ).start()

    def _log_db(self, method, host, status, blocked, start, src_ip, src_port, dst_ip, dst_port, size):
        """Save request to database"""
        try:
            # Console log
            icon = '🚫' if blocked else '✅'
            print(f"{icon} {method:8} {host[:40]:40} {src_ip}:{src_port} -> {dst_ip}:{dst_port}")

            # Update domain stats
            updated = DomainStats.objects.filter(hostname=host).update(
                request_count=F('request_count') + 1,
                total_bytes=F('total_bytes') + size,
                blocked_count=F('blocked_count') + (1 if blocked else 0)
            )
            
            if not updated:
                DomainStats.objects.create(
                    hostname=host,
                    request_count=1,
                    total_bytes=size,
                    blocked_count=1 if blocked else 0
                )

            # Create request log
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

            # Send WebSocket notification
            self.notify(req)

        except Exception as e:
            print(f"Log Error: {e}")

    def notify(self, req):
        """Send WebSocket notification for new request"""
        try:
            from apps.dashboard.serializers import ProxyRequestListSerializer
            data = ProxyRequestListSerializer(req).data
            data['id'] = str(data['id'])
            async_to_sync(self.channel_layer.group_send)(
                'dashboard',
                {
                    'type': 'new_request',
                    'request': data
                }
            )
        except Exception as e:
            pass


def run_proxy(port=8088):
    """Start the proxy server"""
    server = ProxyServer(port=port)
    server.start()


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Proxy Server')
    parser.add_argument('--port', type=int, default=8088, help='Port to listen on')
    args = parser.parse_args()
    run_proxy(args.port)
