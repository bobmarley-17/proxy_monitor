import socket
import time
import threading
from django.conf import settings
from django.utils import timezone

# Optional DB cache
try:
    from apps.dashboard.models import IPHostnameCache
    DB_CACHE_AVAILABLE = True
except Exception:
    DB_CACHE_AVAILABLE = False


DNS_SERVERS = getattr(settings, 'DNS_SERVERS', ['8.8.8.8'])
DNS_TIMEOUT = getattr(settings, 'DNS_TIMEOUT', 5)

# 🔥 Cache settings (tunable)
DNS_CACHE_TTL = getattr(settings, 'DNS_CACHE_TTL', 3600)  # 1 hour default
DNS_CACHE_MAX = getattr(settings, 'DNS_CACHE_MAX', 10000)

# 🔥 In-memory cache
_dns_cache = {}
_dns_lock = threading.Lock()


# =========================================================
# 🧠 Cache helpers
# =========================================================
def _cache_get(ip):
    with _dns_lock:
        entry = _dns_cache.get(ip)
        if not entry:
            return None

        hostname, expires = entry
        if expires < time.time():
            _dns_cache.pop(ip, None)
            return None

        return hostname


def _cache_set(ip, hostname):
    with _dns_lock:
        if len(_dns_cache) >= DNS_CACHE_MAX:
            # simple eviction (oldest random pop)
            _dns_cache.pop(next(iter(_dns_cache)))

        _dns_cache[ip] = (
            hostname,
            time.time() + DNS_CACHE_TTL
        )


# =========================================================
# 🔍 Main resolver
# =========================================================
def resolve_ip_with_custom_dns(ip_address, dns_server=None):
    """
    High-performance resolver with:
    1. memory cache
    2. DB cache
    3. DNS lookup fallback
    """

    # -----------------------------------------------------
    # 1️⃣ Memory cache (fast path)
    # -----------------------------------------------------
    cached = _cache_get(ip_address)
    if cached is not None:
        return {
            'ip': ip_address,
            'hostname': cached,
            'dns_server': 'cache',
            'resolution_time_ms': 0,
            'success': True
        }

    # -----------------------------------------------------
    # 2️⃣ DB cache (medium path)
    # -----------------------------------------------------
    if DB_CACHE_AVAILABLE:
        try:
            obj = IPHostnameCache.objects.filter(ip_address=ip_address).first()
            if obj:
                _cache_set(ip_address, obj.hostname)
                return {
                    'ip': ip_address,
                    'hostname': obj.hostname,
                    'dns_server': 'db-cache',
                    'resolution_time_ms': 0,
                    'success': True
                }
        except Exception:
            pass

    # -----------------------------------------------------
    # 3️⃣ Real DNS lookup (slow path)
    # -----------------------------------------------------
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

            # 🔥 update caches
            _cache_set(ip_address, hostname)
            _update_db_cache(ip_address, hostname)

            return {
                'ip': ip_address,
                'hostname': hostname,
                'dns_server': dns_server,
                'resolution_time_ms': elapsed_ms,
                'success': True
            }

        return _dns_fail(ip_address, dns_server, 'No PTR record')

    except ImportError:
        return resolve_ip_with_socket(ip_address, dns_server)

    except Exception as e:
        return _dns_fail(ip_address, dns_server, str(e))


# =========================================================
# 🔁 Socket fallback
# =========================================================
def resolve_ip_with_socket(ip_address, dns_server=None):
    try:
        start_time = time.time()

        original_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(DNS_TIMEOUT)

        try:
            hostname = socket.gethostbyaddr(ip_address)[0]
        finally:
            socket.setdefaulttimeout(original_timeout)

        elapsed_ms = int((time.time() - start_time) * 1000)

        _cache_set(ip_address, hostname)
        _update_db_cache(ip_address, hostname)

        return {
            'ip': ip_address,
            'hostname': hostname,
            'dns_server': dns_server or 'system',
            'resolution_time_ms': elapsed_ms,
            'success': True
        }

    except Exception as e:
        return _dns_fail(ip_address, dns_server or 'system', str(e))


# =========================================================
# 🗄️ DB cache updater
# =========================================================
def _update_db_cache(ip, hostname):
    if not DB_CACHE_AVAILABLE:
        return

    try:
        IPHostnameCache.objects.update_or_create(
            ip_address=ip,
            defaults={
                'hostname': hostname,
                'last_updated': timezone.now()
            }
        )
    except Exception:
        pass


# =========================================================
# ❌ Failure helper
# =========================================================
def _dns_fail(ip, dns_server, error):
    return {
        'ip': ip,
        'hostname': None,
        'dns_server': dns_server,
        'error': error,
        'success': False
    }