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
from apps.blocklist.models import BlockedDomain, BlockedIP, BlockedPort, BlockRule

BUFFER_SIZE = 65536 * 2


class ProxyServer:
    def __init__(self, host='0.0.0.0', port=8088):
        self.host = host
        self.port = int(port)
        self.channel_layer = get_channel_layer()

    def load_blocklist(self):
        """Load and display blocklist stats"""
        try:
            domain_count = BlockedDomain.objects.filter(is_active=True).count()
            ip_count = BlockedIP.objects.filter(is_active=True).count()
            port_count = BlockedPort.objects.filter(is_active=True).count()
            rule_count = BlockRule.objects.filter(is_active=True).count()

            print(f"\n📋 Blocklist Loaded:")
            print(f"   🌐 Blocked Domains: {domain_count}")
            print(f"   🔢 Blocked IPs: {ip_count}")
            print(f"   🚪 Blocked Ports: {port_count}")
            print(f"   📜 Custom Rules: {rule_count}")

            # Show blocked domains
            domains = BlockedDomain.objects.filter(is_active=True)[:5]
            if domains:
                print(f"\n   Blocked Domains (top 5):")
                for d in domains:
                    print(f"      - {d.domain} [{d.category}]")

            # Show blocked IPs
            ips = BlockedIP.objects.filter(is_active=True)[:5]
            if ips:
                print(f"\n   Blocked IPs (top 5):")
                for ip in ips:
                    cidr = f"/{ip.cidr_prefix}" if ip.cidr_prefix else ""
                    print(f"      - {ip.ip_address}{cidr} ({ip.ip_type})")

            # Show blocked ports
            ports = BlockedPort.objects.filter(is_active=True)[:5]
            if ports:
                print(f"\n   Blocked Ports (top 5):")
                for p in ports:
                    port_range = f"{p.port}-{p.port_end}" if p.port_end else str(p.port)
                    print(f"      - {port_range} ({p.port_type}, {p.protocol})")

            # Show custom rules
            rules = BlockRule.objects.filter(is_active=True).order_by('priority')[:5]
            if rules:
                print(f"\n   Custom Rules (top 5):")
                print(f"   {'Pri':<5} {'Name':<30} {'Action':<8}")
                print(f"   {'-'*50}")
                for r in rules:
                    print(f"   {r.priority:<5} {r.name[:29]:<30} {r.action.upper():<8}")

        except Exception as e:
            print(f"Error loading blocklist: {e}")

    def check_blocked(self, hostname, src_ip, dst_ip, src_port, dst_port):
        """
        Check all blocking rules in order:
        1. Custom Rules (priority-based, can allow or block)
        2. Blocked Domains
        3. Blocked IPs (source and destination)
        4. Blocked Ports (source and destination)
        
        Returns: (is_blocked, block_type, reason, rule)
        """
        try:
            # 1. Check Custom Rules first (priority-based)
            action, rule = BlockRule.check_request(
                hostname=hostname,
                source_ip=src_ip,
                dest_ip=dst_ip,
                source_port=src_port,
                dest_port=dst_port
            )

            if action == 'allow':
                # Explicit allow - skip all other checks
                print(f"✅ ALLOWED by rule: {rule.name}")
                return False, None, None, None
            elif action == 'block':
                reason = rule.reason or f"Blocked by rule: {rule.name}"
                return True, 'rule', reason, rule
            elif action == 'log':
                # Log only - don't block but record
                print(f"📝 LOGGED by rule: {rule.name}")

            # 2. Check Domain blocking
            if hostname:
                is_blocked, domain_rule = BlockedDomain.is_blocked(hostname)
                if is_blocked:
                    reason = domain_rule.reason or f"Domain blocked: {hostname}"
                    return True, 'domain', reason, domain_rule

            # 3. Check Source IP blocking
            if src_ip:
                is_blocked, ip_rule = BlockedIP.is_blocked(src_ip, 'source')
                if is_blocked:
                    reason = ip_rule.reason or f"Source IP blocked: {src_ip}"
                    return True, 'src_ip', reason, ip_rule

            # 4. Check Destination IP blocking
            if dst_ip:
                is_blocked, ip_rule = BlockedIP.is_blocked(dst_ip, 'destination')
                if is_blocked:
                    reason = ip_rule.reason or f"Destination IP blocked: {dst_ip}"
                    return True, 'dst_ip', reason, ip_rule

            # 5. Check Source Port blocking
            if src_port:
                try:
                    is_blocked, port_rule = BlockedPort.is_blocked(int(src_port), 'source')
                    if is_blocked:
                        reason = port_rule.reason or f"Source port blocked: {src_port}"
                        return True, 'src_port', reason, port_rule
                except (ValueError, TypeError):
                    pass

            # 6. Check Destination Port blocking
            if dst_port:
                try:
                    is_blocked, port_rule = BlockedPort.is_blocked(int(dst_port), 'destination')
                    if is_blocked:
                        reason = port_rule.reason or f"Destination port blocked: {dst_port}"
                        return True, 'dst_port', reason, port_rule
                except (ValueError, TypeError):
                    pass

        except Exception as e:
            print(f"Error checking blocklist: {e}")

        return False, None, None, None

    def start(self):
        """Start the proxy server"""
        self.load_blocklist()
        srv = None

        try:
            srv = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            srv.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            bind_host = '::' if self.host == '0.0.0.0' else self.host
            srv.bind((bind_host, self.port))
            print(f"\n{'='*60}")
            print(f"  🌐 PROXY SERVER STARTED (Dual Stack IPv4/IPv6)")
            print(f"  📍 Listening on: {self.host}:{self.port}")
            print(f"{'='*60}\n")
        except Exception as e:
            print(f"⚠️ IPv6 dual-stack failed ({e}), using IPv4...")
            if srv:
                srv.close()
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((self.host, self.port))
            print(f"\n{'='*60}")
            print(f"  🌐 PROXY SERVER STARTED (IPv4)")
            print(f"  📍 Listening on: {self.host}:{self.port}")
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

        if len(addr) == 2:
            src_ip, src_port = addr
        else:
            src_ip, src_port = addr[0], addr[1]

        # Normalize IPv6-mapped IPv4
        if isinstance(src_ip, str) and src_ip.startswith('::ffff:'):
            src_ip = src_ip[7:]

        try:
            client.settimeout(30)
            data = client.recv(BUFFER_SIZE)
            if not data:
                client.close()
                return

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
            print(f"Client error: {e}")
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

            # Resolve destination IP
            try:
                dst_ip = socket.gethostbyname(host)
            except:
                dst_ip = "0.0.0.0"

            # Check blocking rules
            is_blocked, block_type, reason, rule = self.check_blocked(
                hostname=host,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=port
            )

            if is_blocked:
                print(f"🚫 BLOCKED [{block_type}]: {src_ip}:{src_port} → {dst_ip}:{port} ({host})")
                print(f"   Reason: {reason}")
                self.send_blocked(client, host, reason)
                self.log('CONNECT', host, 403, True, start, src_ip, src_port, dst_ip, port, 0, block_type)
                client.close()
                return

            # Connect to target
            server = socket.create_connection((host, port), timeout=15)

            try:
                dst_info = server.getpeername()
                dst_ip, dst_port = dst_info[0], dst_info[1]
            except:
                dst_ip, dst_port = host, port

            client.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
            self.log('CONNECT', host, 200, False, start, src_ip, src_port, dst_ip, dst_port, 0, None)

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
            print(f"CONNECT error: {e}")
            try:
                client.sendall(b'HTTP/1.1 502 Bad Gateway\r\n\r\n')
            except:
                pass

    def handle_http(self, client, data, method, target, src_ip, src_port, start):
        """Handle HTTP requests"""
        try:
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

            # Resolve destination IP
            try:
                dst_ip = socket.gethostbyname(host)
            except:
                dst_ip = "0.0.0.0"

            # Check blocking rules
            is_blocked, block_type, reason, rule = self.check_blocked(
                hostname=host,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=port
            )

            if is_blocked:
                print(f"🚫 BLOCKED [{block_type}]: {src_ip}:{src_port} → {dst_ip}:{port} ({host})")
                print(f"   Reason: {reason}")
                self.send_blocked(client, host, reason)
                self.log(method, host, 403, True, start, src_ip, src_port, dst_ip, port, 0, block_type)
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

            # Send request
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
            self.log(method, host, 200, False, start, src_ip, src_port, dst_ip, dst_port, total_size, None)

        except Exception as e:
            print(f"HTTP error: {e}")
            try:
                client.sendall(b'HTTP/1.1 502 Bad Gateway\r\n\r\n')
            except:
                pass

    def send_blocked(self, client, host, reason=""):
        """Send blocked page to client"""
        body = f'''<!DOCTYPE html>
<html>
<head>
    <title>Access Blocked</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
            color: #fff;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
        }}
        .container {{
            text-align: center;
            padding: 50px;
            background: rgba(30, 41, 59, 0.95);
            border-radius: 24px;
            border: 1px solid #334155;
            box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
            max-width: 500px;
            margin: 20px;
        }}
        .icon {{ 
            font-size: 80px; 
            margin-bottom: 20px;
            animation: pulse 2s infinite;
        }}
        @keyframes pulse {{
            0%, 100% {{ transform: scale(1); }}
            50% {{ transform: scale(1.1); }}
        }}
        h1 {{ 
            color: #ef4444; 
            margin-bottom: 10px; 
            font-size: 32px;
            font-weight: 700;
        }}
        p {{ 
            color: #94a3b8; 
            font-size: 16px; 
            margin-bottom: 25px;
            line-height: 1.6;
        }}
        .domain {{
            background: linear-gradient(135deg, #ef4444, #dc2626);
            padding: 15px 30px;
            border-radius: 12px;
            display: inline-block;
            font-family: 'SF Mono', Monaco, monospace;
            font-size: 18px;
            font-weight: 600;
            margin-bottom: 20px;
            box-shadow: 0 4px 15px rgba(239, 68, 68, 0.3);
        }}
        .reason {{
            padding: 15px 20px;
            background: rgba(239, 68, 68, 0.1);
            border: 1px solid rgba(239, 68, 68, 0.2);
            border-radius: 10px;
            color: #fca5a5;
            font-size: 14px;
            margin-bottom: 20px;
        }}
        .reason strong {{
            color: #f87171;
        }}
        .footer {{ 
            color: #64748b; 
            font-size: 12px;
            border-top: 1px solid #334155;
            padding-top: 20px;
            margin-top: 10px;
        }}
        .info {{
            display: flex;
            justify-content: center;
            gap: 20px;
            margin-top: 15px;
            font-size: 11px;
            color: #475569;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">🚫</div>
        <h1>Access Blocked</h1>
        <p>This website has been blocked by your network administrator.</p>
        <div class="domain">{host}</div>
        <div class="reason">
            <strong>Reason:</strong> {reason or 'Policy violation'}
        </div>
        <div class="footer">
            If you believe this is an error, please contact your network administrator.
            <div class="info">
                <span>ProxyMonitor</span>
                <span>•</span>
                <span>{time.strftime('%Y-%m-%d %H:%M:%S')}</span>
            </div>
        </div>
    </div>
</body>
</html>'''
        try:
            response = f'HTTP/1.1 403 Forbidden\r\n'
            response += f'Content-Type: text/html; charset=utf-8\r\n'
            response += f'Content-Length: {len(body.encode("utf-8"))}\r\n'
            response += f'Connection: close\r\n'
            response += f'X-Blocked-By: ProxyMonitor\r\n'
            response += f'\r\n'
            response += body
            client.sendall(response.encode('utf-8'))
        except:
            pass

    def log(self, method, host, status, blocked, start, src_ip, src_port, dst_ip, dst_port, size, block_type):
        """Log request asynchronously"""
        threading.Thread(
            target=self._log_db,
            args=(method, host, status, blocked, start, src_ip, src_port, dst_ip, dst_port, size, block_type),
            daemon=True
        ).start()

    def _log_db(self, method, host, status, blocked, start, src_ip, src_port, dst_ip, dst_port, size, block_type):
        """Save request to database"""
        try:
            # Console log
            icon = '🚫' if blocked else '✅'
            block_info = f" [{block_type}]" if block_type else ""
            elapsed = int((time.time() - start) * 1000)
            print(f"{icon} {method:8} {host[:40]:40} {src_ip}:{src_port} → {dst_ip}:{dst_port} {elapsed}ms{block_info}")

            # Update domain stats
            stats, created = DomainStats.objects.get_or_create(
                hostname=host,
                defaults={
                    'request_count': 0,
                    'total_bytes': 0,
                    'blocked_count': 0
                }
            )
            DomainStats.objects.filter(hostname=host).update(
                request_count=F('request_count') + 1,
                total_bytes=F('total_bytes') + size,
                blocked_count=F('blocked_count') + (1 if blocked else 0)
            )

            # Create request log
            req = ProxyRequest.objects.create(
                method=method,
                url=f"https://{host}" if method == 'CONNECT' else f"http://{host}",
                hostname=host,
                status_code=status,
                blocked=blocked,
                response_time=elapsed,
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
        """Send WebSocket notification for real-time updates"""
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
    parser = argparse.ArgumentParser(description='ProxyMonitor - Proxy Server')
    parser.add_argument('--host', type=str, default='0.0.0.0', help='Host to bind')
    parser.add_argument('--port', type=int, default=8088, help='Port to bind')
    args = parser.parse_args()
    
    server = ProxyServer(host=args.host, port=args.port)
    server.start()
