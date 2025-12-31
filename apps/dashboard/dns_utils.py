import socket
import time
from django.conf import settings

DNS_SERVERS = getattr(settings, 'DNS_SERVERS', ['8.8.8.8'])
DNS_TIMEOUT = getattr(settings, 'DNS_TIMEOUT', 5)


def resolve_ip_with_custom_dns(ip_address, dns_server=None):
    """Resolve IP to hostname using custom DNS server"""
    if dns_server is None:
        dns_server = DNS_SERVERS[0] if DNS_SERVERS else '8.8.8.8'
    
    try:
        import dns.resolver
        import dns.reversename
        
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [dns_server]
        resolver.timeout = DNS_TIMEOUT
        resolver.lifetime = DNS_TIMEOUT
        
        rev_name = dns.reversename.from_address(ip_address)
        start_time = time.time()
        answers = resolver.resolve(rev_name, 'PTR')
        elapsed_ms = int((time.time() - start_time) * 1000)
        
        if answers:
            hostname = str(answers[0]).rstrip('.')
            return {
                'ip': ip_address,
                'hostname': hostname,
                'dns_server': dns_server,
                'resolution_time_ms': elapsed_ms,
                'success': True
            }
        
        return {'ip': ip_address, 'hostname': None, 'dns_server': dns_server, 'error': 'No PTR record', 'success': False}
        
    except ImportError:
        return resolve_ip_with_socket(ip_address, dns_server)
    except Exception as e:
        return {'ip': ip_address, 'hostname': None, 'dns_server': dns_server, 'error': str(e), 'success': False}


def resolve_ip_with_socket(ip_address, dns_server=None):
    """Fallback using socket"""
    try:
        start_time = time.time()
        hostname = socket.gethostbyaddr(ip_address)[0]
        elapsed_ms = int((time.time() - start_time) * 1000)
        return {
            'ip': ip_address,
            'hostname': hostname,
            'dns_server': dns_server or 'system',
            'resolution_time_ms': elapsed_ms,
            'success': True
        }
    except Exception as e:
        return {'ip': ip_address, 'hostname': None, 'dns_server': dns_server or 'system', 'error': str(e), 'success': False}
