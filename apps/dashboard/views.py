from django.shortcuts import render, redirect
from django.http import JsonResponse
from django.utils import timezone
from django.db.models import Count, Avg, Sum, Q
from django.db.models.functions import TruncHour
from django.contrib.auth.decorators import login_required
from datetime import timedelta
import json

from .models import ProxyRequest, DomainStats, TrafficStats, Alert, IPHostnameCache


@login_required(login_url='dashboard:login')
def index(request):
    """Dashboard home page"""
    now = timezone.now()
    last_24h = now - timedelta(hours=24)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)

    total_stats = ProxyRequest.objects.aggregate(
        total_requests=Count('id'),
        blocked_requests=Count('id', filter=Q(blocked=True)),
        total_bytes=Sum('content_length')
    )

    stats_24h = ProxyRequest.objects.filter(
        timestamp__gte=last_24h
    ).aggregate(
        requests_24h=Count('id'),
        blocked_24h=Count('id', filter=Q(blocked=True)),
        bytes_24h=Sum('content_length'),
        avg_response_time=Avg('response_time')
    )

    unique_ips = ProxyRequest.objects.filter(
        timestamp__gte=today_start
    ).values('source_ip').distinct().count()

    hourly_data = ProxyRequest.objects.filter(
        timestamp__gte=last_24h
    ).annotate(
        hour=TruncHour('timestamp')
    ).values('hour').annotate(
        count=Count('id'),
        blocked=Count('id', filter=Q(blocked=True)),
    ).order_by('hour')

    hourly_data_list = []
    for item in hourly_data:
        hourly_data_list.append({
            'hour': item['hour'].isoformat() if item['hour'] else '',
            'count': item['count'] or 0,
            'blocked': item['blocked'] or 0,
        })

    methods_data = ProxyRequest.objects.filter(
        timestamp__gte=last_24h
    ).values('method').annotate(
        count=Count('id')
    ).order_by('-count')

    methods_list = []
    for item in methods_data:
        if item['method']:
            methods_list.append({
                'method': item['method'],
                'count': item['count']
            })

    recent_requests = ProxyRequest.objects.all().order_by('-timestamp')[:20]

    try:
        recent_alerts = Alert.objects.filter(is_read=False)[:5]
    except Exception:
        recent_alerts = []

    has_chart_data = len(hourly_data_list) > 0
    has_methods_data = len(methods_list) > 0

    context = {
        'total_requests': total_stats['total_requests'] or 0,
        'blocked_requests': total_stats['blocked_requests'] or 0,
        'total_bytes': total_stats['total_bytes'] or 0,
        'requests_24h': stats_24h['requests_24h'] or 0,
        'blocked_24h': stats_24h['blocked_24h'] or 0,
        'bytes_24h': stats_24h['bytes_24h'] or 0,
        'unique_ips': unique_ips,
        'hourly_data_json': json.dumps(hourly_data_list),
        'methods_json': json.dumps(methods_list),
        'has_chart_data': has_chart_data,
        'has_methods_data': has_methods_data,
        'recent_requests': recent_requests,
        'recent_alerts': recent_alerts,
        'page': 'dashboard',
    }

    return render(request, 'dashboard/index.html', context)


@login_required(login_url='dashboard:login')
def analytics(request):
    """Analytics page with traffic data"""
    from django.conf import settings

    hours = int(request.GET.get('hours', 24))
    now = timezone.now()
    time_boundary = now - timedelta(hours=hours)

    dns_server = getattr(settings, 'DNS_SERVERS', ['8.8.8.8'])[0]

    total_stats = ProxyRequest.objects.filter(
        timestamp__gte=time_boundary
    ).aggregate(
        total_requests=Count('id'),
        total_bytes=Sum('content_length'),
        avg_response_time=Avg('response_time')
    )

    top_clients_qs = ProxyRequest.objects.filter(
        timestamp__gte=time_boundary
    ).values('source_ip').annotate(
        count=Count('id'),
        blocked=Count('id', filter=Q(blocked=True)),
        bytes=Sum('content_length')
    ).order_by('-count')[:20]

    top_clients = []
    for client in top_clients_qs:
        client_data = dict(client)
        try:
            cache = IPHostnameCache.objects.get(ip_address=client['source_ip'])
            client_data['hostname'] = cache.hostname
            client_data['resolution_time'] = cache.resolution_time_ms
            client_data['dns_server'] = cache.dns_server
        except IPHostnameCache.DoesNotExist:
            client_data['hostname'] = None
            client_data['resolution_time'] = None
            client_data['dns_server'] = None
        top_clients.append(client_data)

    top_domains = ProxyRequest.objects.filter(
        timestamp__gte=time_boundary
    ).values('hostname').annotate(
        request_count=Count('id'),
        blocked_count=Count('id', filter=Q(blocked=True)),
        total_bytes=Sum('content_length')
    ).order_by('-request_count')[:20]

    top_blocked = ProxyRequest.objects.filter(
        timestamp__gte=time_boundary
    ).values('hostname').annotate(
        request_count=Count('id'),
        blocked_count=Count('id', filter=Q(blocked=True))
    ).filter(
        blocked_count__gt=0
    ).order_by('-blocked_count')[:10]

    methods_data = ProxyRequest.objects.filter(
        timestamp__gte=time_boundary
    ).values('method').annotate(
        count=Count('id')
    ).order_by('-count')

    methods_list = [{'method': m['method'], 'count': m['count']} for m in methods_data if m['method']]

    status_codes = ProxyRequest.objects.filter(
        timestamp__gte=time_boundary,
        status_code__isnull=False
    ).values('status_code').annotate(
        count=Count('id')
    ).order_by('-count')[:10]

    context = {
        'dns_server': dns_server,
        'total_requests': total_stats['total_requests'] or 0,
        'total_bytes': total_stats['total_bytes'] or 0,
        'avg_response_time': total_stats['avg_response_time'] or 0,
        'top_clients': top_clients,
        'top_domains': list(top_domains),
        'top_blocked': list(top_blocked),
        'methods': json.dumps(methods_list),
        'status_codes': list(status_codes),
        'selected_hours': hours,
        'page': 'analytics',
    }

    return render(request, 'dashboard/analytics.html', context)


@login_required(login_url='dashboard:login')
def requests_view(request):
    """View recent requests"""
    page = int(request.GET.get('page', 1))
    per_page = int(request.GET.get('per_page', 50))

    method_filter = request.GET.get('method', '')
    status_filter = request.GET.get('status', '')
    hostname_filter = request.GET.get('hostname', '')
    source_ip_filter = request.GET.get('source_ip', '')

    queryset = ProxyRequest.objects.all()

    if method_filter:
        queryset = queryset.filter(method=method_filter)

    if status_filter == 'success':
        queryset = queryset.filter(status_code__gte=200, status_code__lt=400, blocked=False)
    elif status_filter == 'blocked':
        queryset = queryset.filter(blocked=True)
    elif status_filter == 'error':
        queryset = queryset.filter(status_code__gte=400)

    if hostname_filter:
        queryset = queryset.filter(hostname__icontains=hostname_filter)

    if source_ip_filter:
        queryset = queryset.filter(source_ip__icontains=source_ip_filter)

    offset = (page - 1) * per_page
    requests_list = queryset.order_by('-timestamp')[offset:offset + per_page]
    total_count = queryset.count()

    methods = ProxyRequest.objects.values_list('method', flat=True).distinct()

    context = {
        'requests': requests_list,
        'page': page,
        'per_page': per_page,
        'total_count': total_count,
        'total_pages': (total_count + per_page - 1) // per_page if total_count > 0 else 1,
        'filter_method': method_filter,
        'filter_status': status_filter,
        'filter_hostname': hostname_filter,
        'filter_source_ip': source_ip_filter,
        'methods': list(methods),
        'page': 'requests',
    }

    return render(request, 'dashboard/requests.html', context)


@login_required(login_url='dashboard:login')
def blocklist_view(request):
    """Blocklist management page"""
    try:
        from apps.blocklist.models import BlockedDomain, BlockedIP, BlockedPort, BlockRule

        blocked_domains = BlockedDomain.objects.all().order_by('-created_at')[:100]
        blocked_ips = BlockedIP.objects.all().order_by('-created_at')[:100]
        blocked_ports = BlockedPort.objects.all().order_by('-created_at')[:100]
        block_rules = BlockRule.objects.all().order_by('priority', '-created_at')[:100]

        domain_count = BlockedDomain.objects.filter(is_active=True).count()
        ip_count = BlockedIP.objects.filter(is_active=True).count()
        port_count = BlockedPort.objects.filter(is_active=True).count()
        rule_count = BlockRule.objects.filter(is_active=True).count()

        total_hits = (
            (BlockedDomain.objects.aggregate(Sum('hit_count'))['hit_count__sum'] or 0) +
            (BlockedIP.objects.aggregate(Sum('hit_count'))['hit_count__sum'] or 0) +
            (BlockedPort.objects.aggregate(Sum('hit_count'))['hit_count__sum'] or 0) +
            (BlockRule.objects.aggregate(Sum('hit_count'))['hit_count__sum'] or 0)
        )

    except Exception as e:
        print(f"Blocklist error: {e}")
        blocked_domains = []
        blocked_ips = []
        blocked_ports = []
        block_rules = []
        domain_count = ip_count = port_count = rule_count = total_hits = 0

    context = {
        'blocked_domains': blocked_domains,
        'blocked_ips': blocked_ips,
        'blocked_ports': blocked_ports,
        'block_rules': block_rules,
        'domain_count': domain_count,
        'ip_count': ip_count,
        'port_count': port_count,
        'rule_count': rule_count,
        'total_hits': total_hits,
        'page': 'blocklist',
    }

    return render(request, 'dashboard/blocklist.html', context)


# ============ API Endpoints ============

@login_required(login_url='dashboard:login')
def api_traffic_stats(request):
    """API endpoint for real-time traffic statistics"""
    hours = int(request.GET.get('hours', 24))
    now = timezone.now()
    time_boundary = now - timedelta(hours=hours)

    hourly_data = ProxyRequest.objects.filter(
        timestamp__gte=time_boundary
    ).annotate(
        hour=TruncHour('timestamp')
    ).values('hour').annotate(
        total=Count('id'),
        successful=Count('id', filter=Q(status_code__gte=200, status_code__lt=400) & Q(blocked=False)),
        failed=Count('id', filter=Q(status_code__gte=400)),
        blocked=Count('id', filter=Q(blocked=True)),
    ).order_by('hour')

    method_data = ProxyRequest.objects.filter(
        timestamp__gte=time_boundary
    ).values('method').annotate(
        count=Count('id')
    ).order_by('-count')

    request_methods = {item['method']: item['count'] for item in method_data if item['method']}

    totals = ProxyRequest.objects.filter(
        timestamp__gte=time_boundary
    ).aggregate(
        total=Count('id'),
        blocked=Count('id', filter=Q(blocked=True)),
        avg_response=Avg('response_time'),
    )

    data = {
        'hourly_data': [
            {
                'hour': item['hour'].strftime('%Y-%m-%d %H:00:00') if item['hour'] else '',
                'total': item['total'],
                'successful': item['successful'],
                'failed': item['failed'],
                'blocked': item['blocked'],
            }
            for item in hourly_data
        ],
        'request_methods': request_methods,
        'totals': {
            'total': totals['total'] or 0,
            'blocked': totals['blocked'] or 0,
            'avg_response': round(totals['avg_response'] or 0, 2),
        }
    }

    return JsonResponse(data)


@login_required(login_url='dashboard:login')
def api_recent_requests(request):
    """API endpoint for recent requests"""
    limit = int(request.GET.get('limit', 10))

    logs = ProxyRequest.objects.all().order_by('-timestamp')[:limit]

    data = {
        'requests': [
            {
                'id': log.id,
                'timestamp': log.timestamp.isoformat(),
                'method': log.method,
                'hostname': log.hostname,
                'path': log.path or '/',
                'status_code': log.status_code,
                'response_time': log.response_time,
                'blocked': log.blocked,
                'block_reason': log.block_reason,
                'source_ip': log.source_ip,
                'source_port': log.source_port,
                'content_length': log.content_length,
            }
            for log in logs
        ]
    }

    return JsonResponse(data)


@login_required(login_url='dashboard:login')
def api_domain_stats(request):
    """API endpoint for domain statistics"""
    limit = int(request.GET.get('limit', 20))
    hours = int(request.GET.get('hours', 24))

    time_boundary = timezone.now() - timedelta(hours=hours)

    domains = ProxyRequest.objects.filter(
        timestamp__gte=time_boundary
    ).values('hostname').annotate(
        total=Count('id'),
        blocked=Count('id', filter=Q(blocked=True)),
        errors=Count('id', filter=Q(status_code__gte=400)),
        avg_response=Avg('response_time'),
        total_bytes=Sum('content_length'),
    ).order_by('-total')[:limit]

    return JsonResponse({'domains': list(domains)})


@login_required(login_url='dashboard:login')
def api_ip_stats(request):
    """API endpoint for IP statistics"""
    limit = int(request.GET.get('limit', 20))
    hours = int(request.GET.get('hours', 24))

    time_boundary = timezone.now() - timedelta(hours=hours)

    ips = ProxyRequest.objects.filter(
        timestamp__gte=time_boundary
    ).values('source_ip').annotate(
        total=Count('id'),
        blocked=Count('id', filter=Q(blocked=True)),
        unique_domains=Count('hostname', distinct=True),
    ).order_by('-total')[:limit]

    results = []
    for item in ips:
        item_dict = dict(item)
        try:
            cached = IPHostnameCache.objects.get(ip_address=item['source_ip'])
            item_dict['hostname'] = cached.hostname
        except IPHostnameCache.DoesNotExist:
            item_dict['hostname'] = None
        results.append(item_dict)

    return JsonResponse({'ips': results})


@login_required(login_url='dashboard:login')
def api_alerts(request):
    """API endpoint for alerts"""
    limit = int(request.GET.get('limit', 20))
    unread_only = request.GET.get('unread', 'false').lower() == 'true'

    try:
        queryset = Alert.objects.all()

        if unread_only:
            queryset = queryset.filter(is_read=False)

        alerts = queryset.order_by('-timestamp')[:limit]

        data = {
            'alerts': [
                {
                    'id': alert.id,
                    'timestamp': alert.timestamp.isoformat(),
                    'severity': alert.severity,
                    'alert_type': alert.alert_type,
                    'title': alert.title,
                    'message': alert.message,
                    'source_ip': alert.source_ip,
                    'hostname': alert.hostname,
                    'is_read': alert.is_read,
                }
                for alert in alerts
            ],
            'unread_count': Alert.objects.filter(is_read=False).count(),
        }
    except Exception:
        data = {
            'alerts': [],
            'unread_count': 0,
        }

    return JsonResponse(data)


@login_required(login_url='dashboard:login')
def api_resolve_ip(request):
    """API endpoint to resolve IP to hostname"""
    from django.conf import settings

    ip = request.GET.get('ip', '')
    dns_server = request.GET.get('dns_server') or getattr(settings, 'DNS_SERVERS', ['8.8.8.8'])[0]

    if not ip:
        return JsonResponse({'error': 'IP address required'}, status=400)

    try:
        hostname = IPHostnameCache.resolve_with_custom_dns(ip, dns_server)

        try:
            cache = IPHostnameCache.objects.get(ip_address=ip)
            resolution_time_ms = cache.resolution_time_ms
        except IPHostnameCache.DoesNotExist:
            resolution_time_ms = 0

    except Exception:
        hostname = None
        resolution_time_ms = 0

    return JsonResponse({
        'ip': ip,
        'hostname': hostname,
        'dns_server': dns_server,
        'resolution_time_ms': resolution_time_ms,
    })


@login_required(login_url='dashboard:login')
def api_dns_cache(request):
    """API endpoint to manage DNS cache"""
    if request.method == 'DELETE':
        IPHostnameCache.objects.all().delete()
        return JsonResponse({'status': 'ok', 'message': 'DNS cache cleared'})

    entries = IPHostnameCache.objects.all()[:100]
    data = {
        'entries': [
            {
                'ip': e.ip_address,
                'hostname': e.hostname,
                'dns_server': e.dns_server,
                'resolution_time_ms': e.resolution_time_ms,
                'resolved_at': e.resolved_at.isoformat(),
            }
            for e in entries
        ]
    }
    return JsonResponse(data)
