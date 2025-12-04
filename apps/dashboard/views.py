from django.shortcuts import render
from django.db.models import Sum, Count, Avg, Q
from django.db.models.functions import TruncHour
from django.utils import timezone
from datetime import timedelta
from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.views import APIView
from .models import ProxyRequest, DomainStats, TrafficStats, Alert
from .serializers import (
    ProxyRequestSerializer, ProxyRequestListSerializer,
    DomainStatsSerializer, TrafficStatsSerializer, AlertSerializer
)
from apps.blocklist.models import BlockedDomain


def get_base_context():
    """Common context for all pages"""
    return {
        'alert_count': Alert.objects.filter(is_read=False).count(),
        'total_requests': ProxyRequest.objects.count(),
        'blocked_domains_count': BlockedDomain.objects.filter(is_active=True).count(),
    }


def dashboard_view(request):
    """Main dashboard with overview"""
    now = timezone.now()
    last_24h = now - timedelta(hours=24)
    
    context = get_base_context()
    context.update({
        'page': 'dashboard',
        'recent_requests': ProxyRequest.objects.all().order_by('-timestamp')[:50],
        'blocked_requests': ProxyRequest.objects.filter(blocked=True).count(),
        'requests_24h': ProxyRequest.objects.filter(timestamp__gte=last_24h).count(),
        'blocked_24h': ProxyRequest.objects.filter(timestamp__gte=last_24h, blocked=True).count(),
        'total_bytes': DomainStats.objects.aggregate(Sum('total_bytes'))['total_bytes__sum'] or 0,
        'bytes_24h': ProxyRequest.objects.filter(timestamp__gte=last_24h).aggregate(Sum('content_length'))['content_length__sum'] or 0,
        'unique_ips': ProxyRequest.objects.filter(timestamp__gte=last_24h).values('source_ip').distinct().count(),
        'top_domains': DomainStats.objects.order_by('-request_count')[:10],
        'hourly_data': list(ProxyRequest.objects.filter(timestamp__gte=last_24h).annotate(
            hour=TruncHour('timestamp')
        ).values('hour').annotate(
            count=Count('id'),
            blocked=Count('id', filter=Q(blocked=True))
        ).order_by('hour')),
        'methods': list(ProxyRequest.objects.filter(timestamp__gte=last_24h).values('method').annotate(count=Count('id')).order_by('-count')),
    })
    return render(request, 'dashboard/index.html', context)


def requests_view(request):
    """All requests page with filtering"""
    context = get_base_context()
    
    # Get filter parameters
    hostname = request.GET.get('hostname', '')
    method = request.GET.get('method', '')
    status = request.GET.get('status', '')
    source_ip = request.GET.get('source_ip', '')
    
    # Build query
    qs = ProxyRequest.objects.all().order_by('-timestamp')
    
    if hostname:
        qs = qs.filter(hostname__icontains=hostname)
    if method:
        qs = qs.filter(method=method)
    if status == 'blocked':
        qs = qs.filter(blocked=True)
    elif status == 'success':
        qs = qs.filter(blocked=False, status_code__lt=400)
    elif status == 'error':
        qs = qs.filter(status_code__gte=400)
    if source_ip:
        qs = qs.filter(source_ip__icontains=source_ip)
    
    context.update({
        'page': 'requests',
        'requests': qs[:500],
        'filter_hostname': hostname,
        'filter_method': method,
        'filter_status': status,
        'filter_source_ip': source_ip,
        'methods': ['GET', 'POST', 'CONNECT', 'PUT', 'DELETE', 'HEAD', 'OPTIONS'],
    })
    return render(request, 'dashboard/requests.html', context)


def analytics_view(request):
    """Analytics and statistics page"""
    now = timezone.now()
    last_24h = now - timedelta(hours=24)
    last_7d = now - timedelta(days=7)
    
    context = get_base_context()
    
    # Top clients
    top_clients = ProxyRequest.objects.filter(
        timestamp__gte=last_24h
    ).values('source_ip').annotate(
        count=Count('id'),
        blocked=Count('id', filter=Q(blocked=True)),
        bytes=Sum('content_length'),
    ).order_by('-count')[:20]
    
    # Top domains
    top_domains = DomainStats.objects.order_by('-request_count')[:20]
    
    # Top blocked
    top_blocked = DomainStats.objects.filter(blocked_count__gt=0).order_by('-blocked_count')[:20]
    
    # Hourly data
    hourly_data = ProxyRequest.objects.filter(
        timestamp__gte=last_24h
    ).annotate(
        hour=TruncHour('timestamp')
    ).values('hour').annotate(
        count=Count('id'),
        blocked=Count('id', filter=Q(blocked=True)),
        bytes=Sum('content_length'),
    ).order_by('hour')
    
    # Methods breakdown
    methods = ProxyRequest.objects.values('method').annotate(count=Count('id')).order_by('-count')
    
    # Status codes
    status_codes = ProxyRequest.objects.exclude(status_code=0).values('status_code').annotate(
        count=Count('id')
    ).order_by('-count')[:10]
    
    context.update({
        'page': 'analytics',
        'top_clients': top_clients,
        'top_domains': top_domains,
        'top_blocked': top_blocked,
        'hourly_data': list(hourly_data),
        'methods': list(methods),
        'status_codes': list(status_codes),
        'total_bytes': DomainStats.objects.aggregate(Sum('total_bytes'))['total_bytes__sum'] or 0,
        'avg_response_time': ProxyRequest.objects.aggregate(Avg('response_time'))['response_time__avg'] or 0,
    })
    return render(request, 'dashboard/analytics.html', context)


def blocklist_view(request):
    """Blocklist management page"""
    context = get_base_context()
    context.update({
        'page': 'blocklist',
        'blocked_domains': BlockedDomain.objects.all().order_by('-created_at'),
        'categories': BlockedDomain.objects.values('category').annotate(count=Count('id')).order_by('-count'),
    })
    return render(request, 'dashboard/blocklist.html', context)


def settings_view(request):
    """Settings page"""
    context = get_base_context()
    context.update({
        'page': 'settings',
    })
    return render(request, 'dashboard/settings.html', context)


# ============ API VIEWSETS ============

class ProxyRequestViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = ProxyRequest.objects.all().order_by('-timestamp')
    serializer_class = ProxyRequestListSerializer
    
    def get_queryset(self):
        qs = super().get_queryset()
        if hostname := self.request.query_params.get('hostname'):
            qs = qs.filter(hostname__icontains=hostname)
        if method := self.request.query_params.get('method'):
            qs = qs.filter(method=method.upper())
        if blocked := self.request.query_params.get('blocked'):
            qs = qs.filter(blocked=blocked.lower() == 'true')
        if source_ip := self.request.query_params.get('source_ip'):
            qs = qs.filter(source_ip__icontains=source_ip)
        return qs
    
    @action(detail=False, methods=['delete'])
    def clear_all(self, request):
        count = ProxyRequest.objects.count()
        ProxyRequest.objects.all().delete()
        DomainStats.objects.all().delete()
        return Response({'message': f'Cleared {count} requests'})


class DomainStatsViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = DomainStats.objects.all().order_by('-request_count')
    serializer_class = DomainStatsSerializer


class AlertViewSet(viewsets.ModelViewSet):
    queryset = Alert.objects.all().order_by('-timestamp')
    serializer_class = AlertSerializer
    
    @action(detail=False, methods=['post'])
    def mark_all_read(self, request):
        Alert.objects.filter(is_read=False).update(is_read=True)
        return Response({'status': 'ok'})


class AnalyticsAPIView(APIView):
    def get(self, request):
        period = request.query_params.get('period', '24h')
        if period == '24h':
            since = timezone.now() - timedelta(hours=24)
        elif period == '7d':
            since = timezone.now() - timedelta(days=7)
        else:
            since = timezone.now() - timedelta(hours=24)
        
        requests = ProxyRequest.objects.filter(timestamp__gte=since)
        stats = requests.aggregate(
            total=Count('id'),
            blocked=Count('id', filter=Q(blocked=True)),
            total_bytes=Sum('content_length'),
            avg_response_time=Avg('response_time'),
        )
        return Response(stats)


class StatsAPIView(APIView):
    def get(self, request):
        return Response({
            'total_requests': ProxyRequest.objects.count(),
            'blocked_requests': ProxyRequest.objects.filter(blocked=True).count(),
            'total_bytes': DomainStats.objects.aggregate(Sum('total_bytes'))['total_bytes__sum'] or 0,
            'unique_domains': DomainStats.objects.count(),
            'blocked_domains': BlockedDomain.objects.filter(is_active=True).count(),
        })
