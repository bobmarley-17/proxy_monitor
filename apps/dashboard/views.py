# apps/dashboard/views.py

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.contrib import messages
from django.db.models import Sum, Count, Avg, Q, F
from django.db.models.functions import TruncHour
from django.utils import timezone
from django.conf import settings
from datetime import timedelta, datetime
from rest_framework.decorators import api_view
from rest_framework.response import Response
from django.core.cache import cache
import json
import time
import psutil
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET

from .models import ProxyRequest, DomainStats, IPHostnameCache, UserProfile, AuditLog
from .dns_utils import resolve_ip_with_custom_dns
from .rbac import admin_required, operator_required, is_admin, is_operator, log_action

DNS_SERVERS = getattr(settings, 'DNS_SERVERS', ['8.8.8.8'])


# ============ HELPERS ============

def format_bytes(bytes_val):
    """Format bytes into human readable string."""
    if not bytes_val:
        return "0 B"
    if bytes_val < 1024:
        return f"{bytes_val} B"
    elif bytes_val < 1024 * 1024:
        return f"{bytes_val / 1024:.1f} KB"
    elif bytes_val < 1024 * 1024 * 1024:
        return f"{bytes_val / (1024 * 1024):.1f} MB"
    else:
        return f"{bytes_val / (1024 * 1024 * 1024):.2f} GB"


def get_client_ip(request):
    """Get real client IP from request."""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR')


def get_cached_hostname(ip_address):
    """Two-tier hostname lookup: in-memory cache → database."""
    cache_key = f'hostname:{ip_address}'
    hostname = cache.get(cache_key)
    if hostname is not None:
        return hostname if hostname != '__NONE__' else None

    try:
        cached = IPHostnameCache.objects.filter(
            ip_address=ip_address
        ).values_list('hostname', flat=True).first()
        if cached:
            cache.set(cache_key, cached, 3600)
            return cached
        cache.set(cache_key, '__NONE__', 600)
    except Exception:
        pass
    return None


def save_hostname_cache(ip_address, hostname):
    """Save hostname to both DB and in-memory cache."""
    try:
        IPHostnameCache.objects.update_or_create(
            ip_address=ip_address,
            defaults={'hostname': hostname}
        )
        cache.set(f'hostname:{ip_address}', hostname, 3600)
    except Exception:
        pass


def get_current_time():
    """Get current time respecting USE_TZ setting."""
    if settings.USE_TZ:
        return timezone.now()
    else:
        return datetime.now()


# ============ AUTH VIEWS ============

def login_view(request):
    """Login page."""
    if request.user.is_authenticated:
        return redirect('dashboard:index')

    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)

        if user is not None:
            login(request, user)
            log_action(user, 'login', ip_address=get_client_ip(request))
            messages.success(request, f'Welcome back, {user.username}!')
            return redirect(request.GET.get('next', 'dashboard:index'))
        else:
            messages.error(request, 'Invalid username or password')

    return render(request, 'dashboard/login.html')


def logout_view(request):
    """Logout and redirect to login."""
    if request.user.is_authenticated:
        log_action(request.user, 'logout', ip_address=get_client_ip(request))
    logout(request)
    messages.info(request, 'You have been logged out.')
    return redirect('dashboard:login')


# ============ DASHBOARD VIEWS ============

@login_required
def index(request):
    """Main dashboard - optimized + working charts"""

    CACHE_TTL = 600

    cached = cache.get('dashboard:index_context')
    if cached:
        return render(request, 'dashboard/index.html', cached)

    now = get_current_time()
    last_24h = now - timedelta(hours=24)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)

    # ✅ Use DomainStats for all-time totals (much faster than scanning ProxyRequest)
    domain_totals = cache.get_or_set(
        'dashboard:domain_totals',
        lambda: DomainStats.objects.aggregate(total_bytes=Sum('total_bytes'), total_requests=Sum('request_count'), blocked_requests=Sum('blocked_count')),
        300
    )

    # ✅ Base queryset (last 24h only)
    base_qs = ProxyRequest.objects.filter(timestamp__gte=last_24h)

    stats_24h = base_qs.aggregate(
        count=Count('id'),
        blocked=Count('id', filter=Q(blocked=True)),
        bytes=Sum('content_length'),
        avg_response=Avg('response_time'),
        unique_clients=Count('source_ip', distinct=True),
    )

    stats_today = ProxyRequest.objects.filter(
        timestamp__gte=today_start
    ).aggregate(
        count=Count('id'),
        blocked=Count('id', filter=Q(blocked=True)),
        bytes=Sum('content_length'),
    )

    # ✅ Recent requests
    recent_requests = base_qs.order_by('-timestamp').values(
        'id', 'method', 'hostname', 'url',
        'status_code', 'blocked',
        'response_time', 'source_ip', 'timestamp'
    )[:20]

    # =============================
    # 🔥 TRAFFIC OVERVIEW (FIXED)
    # =============================
    # Ensure we use the same timezone-aware range for the graph as the stats
    #graph_qs = ProxyRequest.objects.filter(timestamp__gte=last_24h)
    
    hourly_qs = (
        base_qs.annotate(hour=TruncHour('timestamp')).values('hour').annotate(
            total=Count('id'),
            blocked=Count('id', filter=Q(blocked=True)),
        )
        .order_by('hour')
    )

    # Convert hours to strings to avoid Aware vs Naive mismatch
    hourly_map = {}
    for row in hourly_qs:
        hour_val = row['hour']
        if hour_val:
            hour_str = hour_val.strftime('%Y-%m-%d %H:00')
            hourly_map[hour_str] = row

    hourly_data = []
    for i in range(23, -1, -1):
        hour_key = (now - timedelta(hours=i)).replace(
            minute=0, second=0, microsecond=0
        )
        
        # Match using the string format
        hour_str = hour_key.strftime('%Y-%m-%d %H:00')
        row = hourly_map.get(hour_str, {'total': 0, 'blocked': 0})

        hourly_data.append({
            'hour': hour_key.strftime('%H:00'),
            'total': row['total'],
            'blocked': row['blocked'],
        })

    # =============================
    # 🔥 METHODS (FIXED)
    # =============================
    methods_data = list(
        base_qs.values('method')
        .annotate(count=Count('id'))
        .order_by('-count')
    ) or [{'method': 'GET', 'count': 0}]

    # =============================
    # FINAL CONTEXT
    # =============================
    context = {
        'page': 'dashboard',
        'total_requests': domain_totals['total_requests'] or 0,
        'blocked_requests': domain_totals['blocked_requests'] or 0,
        'total_bytes': domain_totals['total_bytes'] or 0,
        'total_bytes_formatted': format_bytes(domain_totals['total_bytes'] or 0),  # ADD
        'today_bytes_formatted': format_bytes(stats_today['bytes'] or 0),          # ADD
        'requests_24h': stats_24h['count'] or 0,
        'blocked_24h': stats_24h['blocked'] or 0,
        'today_requests': stats_today['count'] or 0,
        'today_blocked': stats_today['blocked'] or 0,
        'active_clients': stats_24h['unique_clients'] or 0,

        # data
        'recent_requests': list(recent_requests),
        'hourly_data': json.dumps(hourly_data),   # ✅ matches your frontend
        'methods': json.dumps(methods_data),      # ✅ matches your frontend
    }

    cache.set('dashboard:index_context', context, CACHE_TTL)
    return render(request, 'dashboard/index.html', context)


@login_required
def requests_view(request):
    """Optimized request listing"""

    filter_hostname = request.GET.get('hostname', '').strip()
    filter_source_ip = request.GET.get('source_ip', '').strip()
    filter_method = request.GET.get('method', '').strip()
    filter_status = request.GET.get('status', '').strip()
    page_num = int(request.GET.get('page', 1))

    per_page = 50

    # 🚀 LIMIT DATA
    last_24h = timezone.now() - timedelta(hours=24)
    qs = ProxyRequest.objects.filter(timestamp__gte=last_24h)

    if filter_hostname:
        qs = qs.filter(hostname__icontains=filter_hostname)
    if filter_source_ip:
        qs = qs.filter(source_ip__icontains=filter_source_ip)
    if filter_method:
        qs = qs.filter(method=filter_method)
    if filter_status:
        if filter_status == 'blocked':
            qs = qs.filter(blocked=True)
        elif filter_status == 'success':
            qs = qs.filter(blocked=False, status_code__lt=400)
        elif filter_status == 'error':
            qs = qs.filter(status_code__gte=400)

    # 🚀 SAFE COUNT

    count_cache_key = f'requests:count:{filter_hostname}:{filter_source_ip}:{filter_method}:{filter_status}'
    total_count = cache.get(count_cache_key)
    if total_count is None:
        total_count = min(qs.count(), 10000)
        cache.set(count_cache_key, total_count, 60)  # cache 60s

    total_pages = max(1, (total_count + per_page - 1) // per_page)
    page_num = max(1, min(page_num, total_pages))

    start = (page_num - 1) * per_page

    qs = qs.order_by('-timestamp')

    requests_list = list(
        qs.values(
            'id', 'method', 'hostname', 'url', 'status_code',
            'blocked', 'source_ip', 'timestamp'
        )[start:start + per_page]
    )

    return render(request, 'dashboard/requests.html', {
        'requests': requests_list,
        'total_count': total_count,
        'page': page_num,
        'total_pages': total_pages,
    })


@login_required
def analytics_view(request):
    """Optimized analytics"""

    CACHE_TTL = 600

    cached = cache.get('dashboard:analytics_context')
    if cached:
        return render(request, 'dashboard/analytics.html', cached)

    now = get_current_time()
    last_24h = now - timedelta(hours=24)
    dns_server = DNS_SERVERS[0] if DNS_SERVERS else '8.8.8.8'

    base_qs = ProxyRequest.objects.filter(timestamp__gte=last_24h)

    totals = base_qs.aggregate(
        total_requests=Count('id'),
        total_bytes=Sum('content_length'),
        avg_response_time=Avg('response_time'),
    )

    top_clients = list(
        base_qs.values('source_ip')
        .annotate(count=Count('id'))
        .order_by('-count')[:10]
    )
    
    top_domains = list(
        DomainStats.objects.order_by('-request_count')[:15]
    )

    top_blocked = list(
        DomainStats.objects.filter(blocked_count__gt=0)
        .order_by('-blocked_count')[:10]
    )

    methods = list(
        base_qs.values('method')
        .annotate(count=Count('id'))
    
    )
    status_codes = list(
        base_qs.exclude(status_code=0)
        .values('status_code')
        .annotate(count=Count('id'))
        .order_by('-count')[:20]
    )
    max_status_count = max((row['count'] for row in status_codes), default=1) or 1
    #max_status_count = max((row['count'] for row in status_codes), default=1)

    context = {
        'page': 'analytics',
        'dns_server': dns_server,
        'total_requests': totals['total_requests'] or 0,
        'total_bytes': totals['total_bytes'] or 0,
        'avg_response_time': round(totals['avg_response_time'] or 0, 2),

        'top_clients': top_clients,

        # 🔥 ADD THESE
        'top_domains': top_domains,
        'top_blocked': top_blocked,

        'methods': json.dumps(methods),
        'status_codes': status_codes,          # plain list for template loop
        'status_codes_json': json.dumps(status_codes),  # keep JSON if needed elsewhere
        'max_status_count': max_status_count,
    }
    #context = {
    #    'total_requests': totals['total_requests'] or 0,
    #    'total_bytes': totals['total_bytes'] or 0,
    #    'avg_response_time': totals['avg_response_time'] or 0,
    #    'top_clients': top_clients,
    #    'methods': json.dumps(methods),
    #}

    cache.set('dashboard:analytics_context', context, CACHE_TTL)
    return render(request, 'dashboard/analytics.html', context)


@login_required
@operator_required
def blocklist_view(request):
    """Blocklist management - cached counts."""
    from apps.blocklist.models import BlockedDomain, BlockedIP, BlockedPort, BlockRule

    show_disabled = request.GET.get('show_disabled', 'true') == 'true'

    if show_disabled:
        blocked_domains = BlockedDomain.objects.all().order_by(
            '-is_active', '-created_at'
        )[:100]
        blocked_ips = BlockedIP.objects.all().order_by(
            '-is_active', '-created_at'
        )[:100]
        blocked_ports = BlockedPort.objects.all().order_by(
            '-is_active', '-created_at'
        )[:100]
        block_rules = BlockRule.objects.all().order_by(
            '-is_active', 'priority', '-created_at'
        )[:100]
    else:
        blocked_domains = BlockedDomain.objects.filter(
            is_active=True
        ).order_by('-created_at')[:100]
        blocked_ips = BlockedIP.objects.filter(
            is_active=True
        ).order_by('-created_at')[:100]
        blocked_ports = BlockedPort.objects.filter(
            is_active=True
        ).order_by('-created_at')[:100]
        block_rules = BlockRule.objects.filter(
            is_active=True
        ).order_by('priority', '-created_at')[:100]

    # Cache counts for 2 minutes
    counts = cache.get('blocklist:counts')
    if counts is None:
        counts = {
            'domain_active': BlockedDomain.objects.filter(is_active=True).count(),
            'domain_total': BlockedDomain.objects.count(),
            'ip_active': BlockedIP.objects.filter(is_active=True).count(),
            'ip_total': BlockedIP.objects.count(),
            'port_active': BlockedPort.objects.filter(is_active=True).count(),
            'port_total': BlockedPort.objects.count(),
            'rule_active': BlockRule.objects.filter(is_active=True).count(),
            'rule_total': BlockRule.objects.count(),
        }
        cache.set('blocklist:counts', counts, 120)

    context = {
        'page': 'blocklist',
        'blocked_domains': blocked_domains,
        'blocked_ips': blocked_ips,
        'blocked_ports': blocked_ports,
        'block_rules': block_rules,
        'domain_count': counts['domain_active'],
        'domain_total': counts['domain_total'],
        'ip_count': counts['ip_active'],
        'ip_total': counts['ip_total'],
        'port_count': counts['port_active'],
        'port_total': counts['port_total'],
        'rule_count': counts['rule_active'],
        'rule_total': counts['rule_total'],
        'show_disabled': show_disabled,
    }

    return render(request, 'dashboard/blocklist.html', context)


# ============ USER MANAGEMENT ============

@login_required
@admin_required
def users_view(request):
    """User management page."""
    users = User.objects.select_related('profile').all().order_by('-date_joined')

    context = {
        'page': 'users',
        'users': users,
        'role_choices': UserProfile.ROLE_CHOICES,
    }

    return render(request, 'dashboard/users.html', context)


@login_required
@admin_required
def user_create(request):
    """Create a new user."""
    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        email = request.POST.get('email', '').strip()
        password = request.POST.get('password', '')
        role = request.POST.get('role', 'viewer')
        department = request.POST.get('department', '')

        if not username or not password:
            messages.error(request, 'Username and password are required')
            return redirect('dashboard:users')

        if User.objects.filter(username=username).exists():
            messages.error(request, 'Username already exists')
            return redirect('dashboard:users')

        try:
            user = User.objects.create_user(
                username=username, email=email, password=password
            )
            user.profile.role = role
            user.profile.department = department
            user.profile.save()

            log_action(
                request.user, 'create', 'user', user.id, username,
                f'Role: {role}', get_client_ip(request)
            )
            messages.success(request, f'User {username} created successfully')
        except Exception as e:
            messages.error(request, f'Error creating user: {e}')

    return redirect('dashboard:users')


@login_required
@admin_required
def user_edit(request, user_id):
    """Edit an existing user."""
    user = get_object_or_404(User, id=user_id)

    if request.method == 'POST':
        user.email = request.POST.get('email', '').strip()
        user.is_active = request.POST.get('is_active') == 'on'
        new_password = request.POST.get('new_password', '')
        if new_password:
            user.set_password(new_password)
        user.save()

        role = request.POST.get('role', 'viewer')
        user.profile.role = role
        user.profile.department = request.POST.get('department', '')
        user.profile.save()

        log_action(
            request.user, 'update', 'user', user.id, user.username,
            f'Role: {role}', get_client_ip(request)
        )
        messages.success(request, f'User {user.username} updated successfully')
        return redirect('dashboard:users')

    context = {
        'page': 'users',
        'edit_user': user,
        'role_choices': UserProfile.ROLE_CHOICES,
    }

    return render(request, 'dashboard/user_edit.html', context)


@login_required
@admin_required
def user_delete(request, user_id):
    """Delete a user."""
    user = get_object_or_404(User, id=user_id)

    if user == request.user:
        messages.error(request, 'You cannot delete yourself')
        return redirect('dashboard:users')

    username = user.username
    log_action(
        request.user, 'delete', 'user', user.id, username,
        ip_address=get_client_ip(request)
    )
    user.delete()
    messages.success(request, f'User {username} deleted')

    return redirect('dashboard:users')


# ============ AUDIT LOGS ============

@login_required
@admin_required
def audit_logs_view(request):
    """Audit log viewer."""
    logs = AuditLog.objects.select_related('user').all()[:500]

    context = {
        'page': 'audit_logs',
        'logs': logs,
    }

    return render(request, 'dashboard/audit_logs.html', context)


# ============ SETTINGS ============

@login_required
def settings_view(request):
    """User settings / profile page."""
    if request.method == 'POST':
        action = request.POST.get('action')

        if action == 'change_password':
            current = request.POST.get('current_password')
            new_pass = request.POST.get('new_password')
            confirm = request.POST.get('confirm_password')

            if not request.user.check_password(current):
                messages.error(request, 'Current password is incorrect')
            elif new_pass != confirm:
                messages.error(request, 'New passwords do not match')
            elif len(new_pass) < 6:
                messages.error(request, 'Password must be at least 6 characters')
            else:
                request.user.set_password(new_pass)
                request.user.save()
                messages.success(request, 'Password changed. Please login again.')
                return redirect('dashboard:login')

        elif action == 'update_profile':
            request.user.email = request.POST.get('email', '')
            request.user.save()
            request.user.profile.department = request.POST.get('department', '')
            request.user.profile.phone = request.POST.get('phone', '')
            request.user.profile.save()
            messages.success(request, 'Profile updated successfully')

    context = {'page': 'settings'}
    return render(request, 'dashboard/settings.html', context)


# ============ API VIEWS ============

@api_view(['GET'])
def api_stats(request):
    """API: Overall statistics."""
    cached = cache.get('api:stats')
    if cached:
        return Response(cached)

    # ---- OPTIMIZED: Aggregation for all-time totals using DomainStats ----
    domain_totals = DomainStats.objects.aggregate(
        total_bytes=Sum('total_bytes'),
        total_requests=Sum('request_count'),
        blocked_requests=Sum('blocked_count')
    )
    total_bytes = domain_totals['total_bytes'] or 0
    total_requests = domain_totals['total_requests'] or 0
    blocked_requests = domain_totals['blocked_requests'] or 0

    data = {
        'total_requests': total_requests,
        'blocked_requests': blocked_requests,
        'total_bytes': total_bytes,
        'total_bytes_formatted': format_bytes(total_bytes),
        'block_rate': round(
            (blocked_requests / total_requests * 100)
            if total_requests > 0 else 0, 1
        ),
    }
    cache.set('api:stats', data, 15)
    return Response(data)


@api_view(['GET'])
def api_requests(request):
    """API: Recent requests list."""
    limit = min(int(request.GET.get('limit', 50)), 500)
    qs = ProxyRequest.objects.order_by('-timestamp').values(
        'id', 'method', 'hostname', 'url', 'status_code', 'blocked',
        'response_time', 'source_ip', 'source_port', 'timestamp',
        'destination_ip', 'destination_port', 'content_length',
        'block_reason', 'block_type',
    )[:limit]

    data = []
    for r in qs:
        data.append({
            'id': str(r['id']),
            'method': r['method'],
            'hostname': r['hostname'],
            'url': r['url'],
            'status_code': r['status_code'],
            'blocked': r['blocked'],
            'response_time': r['response_time'],
            'source_ip': r['source_ip'],
            'source_port': r['source_port'],
            'destination_ip': r['destination_ip'],
            'destination_port': r['destination_port'],
            'content_length': r['content_length'],
            'block_reason': r['block_reason'],
            'block_type': r['block_type'],
            'timestamp': r['timestamp'].isoformat() if r['timestamp'] else None,
        })

    return Response(data)


@api_view(['GET'])
def api_hourly(request):
    """API: Hourly traffic data."""
    now = get_current_time()
    hours = min(int(request.GET.get('hours', 24)), 72)

    cache_key = f'api:hourly:{hours}'
    cached = cache.get(cache_key)
    if cached:
        return Response(cached)

    since = now - timedelta(hours=hours)

    # Single query with TruncHour
    hourly_qs = (
        ProxyRequest.objects
        .filter(timestamp__gte=since)
        .annotate(hour=TruncHour('timestamp'))
        .values('hour')
        .annotate(
            total=Count('id'),
            blocked=Count('id', filter=Q(blocked=True)),
        )
        .order_by('hour')
    )
    hourly_map = {row['hour']: row for row in hourly_qs}

    data = []
    for i in range(hours - 1, -1, -1):
        hour_key = (now - timedelta(hours=i)).replace(
            minute=0, second=0, microsecond=0
        )
        row = hourly_map.get(hour_key, {'total': 0, 'blocked': 0})
        data.append({
            'hour': hour_key.strftime('%H:00'),
            'total': row['total'],
            'blocked': row['blocked'],
        })

    cache.set(cache_key, data, 60)
    return Response(data)


@api_view(['GET'])
def api_resolve(request):
    """API: Resolve IP to hostname using custom DNS."""
    ip = request.GET.get('ip', '')
    if not ip:
        return Response({'error': 'IP address required'}, status=400)

    dns_server = DNS_SERVERS[0] if DNS_SERVERS else '8.8.8.8'
    result = resolve_ip_with_custom_dns(ip, dns_server)

    if result.get('success') and result.get('hostname'):
        save_hostname_cache(ip, result['hostname'])

    return Response(result)


@api_view(['DELETE'])
def api_dns_cache(request):
    """API: Clear DNS hostname cache."""
    IPHostnameCache.objects.all().delete()
    return Response({'message': 'DNS cache cleared'})


@csrf_exempt
@require_GET
def health_check(request):
    """
    GET /api/health/
    Non-blocking health check for load balancer.
    """
    try:
        # interval=0 = non-blocking (returns cached CPU value)
        cpu = psutil.cpu_percent(interval=0)
        mem = psutil.virtual_memory()

        # Cache proxy process check for 30 seconds
        proxy_alive = cache.get('health:proxy_alive')
        if proxy_alive is None:
            proxy_alive = False
            for proc in psutil.process_iter(['cmdline']):
                try:
                    cmdline = ' '.join(proc.info.get('cmdline') or [])
                    if 'runproxy' in cmdline or 'proxy_server' in cmdline:
                        proxy_alive = True
                        break
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            cache.set('health:proxy_alive', proxy_alive, 30)

        payload = {
            'status': 'healthy' if proxy_alive else 'degraded',
            'timestamp': time.time(),
            'proxy_running': proxy_alive,
            'system': {
                'cpu_percent': cpu,
                'memory_percent': mem.percent,
                'memory_available_mb': round(
                    mem.available / 1024 / 1024, 2
                ),
            },
        }
        return JsonResponse(payload, status=200 if proxy_alive else 503)

    except Exception as exc:
        return JsonResponse(
            {'status': 'error', 'error': str(exc)}, status=500
        )