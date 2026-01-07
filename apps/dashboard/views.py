from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.contrib import messages
from django.db.models import Sum, Count, Avg, Q
from django.utils import timezone
from django.conf import settings
from datetime import timedelta, datetime
from rest_framework.decorators import api_view
from rest_framework.response import Response
import json

from .models import ProxyRequest, DomainStats, IPHostnameCache, UserProfile, AuditLog
from .dns_utils import resolve_ip_with_custom_dns
from .rbac import admin_required, operator_required, is_admin, is_operator, log_action

DNS_SERVERS = getattr(settings, 'DNS_SERVERS', ['8.8.8.8'])


def format_bytes(bytes_val):
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
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0]
    return request.META.get('REMOTE_ADDR')


def get_cached_hostname(ip_address):
    try:
        cached = IPHostnameCache.objects.filter(ip_address=ip_address).first()
        if cached:
            return cached.hostname
    except:
        pass
    return None


def save_hostname_cache(ip_address, hostname):
    try:
        IPHostnameCache.objects.update_or_create(ip_address=ip_address, defaults={'hostname': hostname})
    except:
        pass


def get_current_time():
    if settings.USE_TZ:
        return timezone.now()
    else:
        return datetime.now()


# ============ AUTH VIEWS ============

def login_view(request):
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
    if request.user.is_authenticated:
        log_action(request.user, 'logout', ip_address=get_client_ip(request))
    logout(request)
    messages.info(request, 'You have been logged out.')
    return redirect('dashboard:login')


# ============ DASHBOARD VIEWS ============

@login_required
def index(request):
    now = get_current_time()
    last_24h = now - timedelta(hours=24)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    
    total_requests = ProxyRequest.objects.count()
    blocked_requests = ProxyRequest.objects.filter(blocked=True).count()
    total_bytes = ProxyRequest.objects.aggregate(total=Sum('content_length'))['total'] or 0
    
    requests_24h = ProxyRequest.objects.filter(timestamp__gte=last_24h).count()
    blocked_24h = ProxyRequest.objects.filter(timestamp__gte=last_24h, blocked=True).count()
    bytes_24h = ProxyRequest.objects.filter(timestamp__gte=last_24h).aggregate(total=Sum('content_length'))['total'] or 0
    avg_response = ProxyRequest.objects.filter(timestamp__gte=last_24h).aggregate(avg=Avg('response_time'))['avg'] or 0
    
    today_requests = ProxyRequest.objects.filter(timestamp__gte=today_start).count()
    today_blocked = ProxyRequest.objects.filter(timestamp__gte=today_start, blocked=True).count()
    today_bytes = ProxyRequest.objects.filter(timestamp__gte=today_start).aggregate(total=Sum('content_length'))['total'] or 0
    
    unique_clients = ProxyRequest.objects.filter(timestamp__gte=last_24h).values('source_ip').distinct().count()
    recent_requests = list(ProxyRequest.objects.order_by('-timestamp')[:20])
    top_domains = DomainStats.objects.order_by('-request_count')[:10]
    
    hourly_data = []
    for i in range(23, -1, -1):
        hour_start = now - timedelta(hours=i+1)
        hour_end = now - timedelta(hours=i)
        count = ProxyRequest.objects.filter(timestamp__gte=hour_start, timestamp__lt=hour_end).count()
        blocked = ProxyRequest.objects.filter(timestamp__gte=hour_start, timestamp__lt=hour_end, blocked=True).count()
        hourly_data.append({'hour': hour_end.strftime('%H:00'), 'total': count, 'blocked': blocked, 'allowed': count - blocked})
    
    method_stats = list(ProxyRequest.objects.filter(timestamp__gte=last_24h).values('method').annotate(count=Count('id')).order_by('-count'))
    if not method_stats:
        method_stats = list(ProxyRequest.objects.values('method').annotate(count=Count('id')).order_by('-count'))
    
    status_stats = list(ProxyRequest.objects.filter(timestamp__gte=last_24h).values('status_code').annotate(count=Count('id')).order_by('-count'))
    
    context = {
        'page': 'dashboard',
        'total_requests': total_requests,
        'blocked_requests': blocked_requests,
        'total_bytes': total_bytes,
        'total_bytes_formatted': format_bytes(total_bytes),
        'requests_24h': requests_24h,
        'blocked_24h': blocked_24h,
        'bytes_24h': bytes_24h,
        'bytes_24h_formatted': format_bytes(bytes_24h),
        'today_requests': today_requests,
        'today_blocked': today_blocked,
        'today_bytes': today_bytes,
        'today_bytes_formatted': format_bytes(today_bytes),
        'avg_response_time': round(avg_response, 2),
        'unique_clients': unique_clients,
        'recent_requests': recent_requests,
        'top_domains': top_domains,
        'hourly_data': json.dumps(hourly_data),
        'method_stats': json.dumps(method_stats),
        'status_stats': json.dumps(status_stats),
        'block_rate': round((blocked_requests / total_requests * 100) if total_requests > 0 else 0, 1),
    }
    
    return render(request, 'dashboard/index.html', context)


@login_required
def requests_view(request):
    """Request log with filtering and pagination"""
    
    # Get filter parameters
    filter_hostname = request.GET.get('hostname', '').strip()
    filter_source_ip = request.GET.get('source_ip', '').strip()
    filter_method = request.GET.get('method', '').strip()
    filter_status = request.GET.get('status', '').strip()
    page = int(request.GET.get('page', 1))
    per_page = 100
    
    # Build queryset with filters
    requests_qs = ProxyRequest.objects.all()
    
    if filter_hostname:
        requests_qs = requests_qs.filter(hostname__icontains=filter_hostname)
    
    if filter_source_ip:
        requests_qs = requests_qs.filter(source_ip__icontains=filter_source_ip)
    
    if filter_method:
        requests_qs = requests_qs.filter(method=filter_method)
    
    if filter_status:
        if filter_status == 'blocked':
            requests_qs = requests_qs.filter(blocked=True)
        elif filter_status == 'success':
            requests_qs = requests_qs.filter(blocked=False, status_code__gte=200, status_code__lt=400)
        elif filter_status == 'error':
            requests_qs = requests_qs.filter(blocked=False, status_code__gte=400)
    
    # Get total count before pagination
    total_count = requests_qs.count()
    total_pages = (total_count + per_page - 1) // per_page  # Ceiling division
    
    # Ensure page is within bounds
    page = max(1, min(page, total_pages)) if total_pages > 0 else 1
    
    # Apply pagination
    start = (page - 1) * per_page
    end = start + per_page
    requests_list = requests_qs.order_by('-timestamp')[start:end]
    
    # Get unique methods for filter dropdown
    methods = ProxyRequest.objects.values_list('method', flat=True).distinct()
    
    context = {
        'page': 'requests',
        'requests': requests_list,
        'total_count': total_count,
        'total_pages': total_pages,
        'page': page,
        'per_page': per_page,
        'filter_hostname': filter_hostname,
        'filter_source_ip': filter_source_ip,
        'filter_method': filter_method,
        'filter_status': filter_status,
        'methods': list(methods),
    }
    
    return render(request, 'dashboard/requests.html', context)

@login_required
def analytics_view(request):
    now = get_current_time()
    last_24h = now - timedelta(hours=24)
    dns_server = DNS_SERVERS[0] if DNS_SERVERS else '8.8.8.8'
    
    total_requests = ProxyRequest.objects.count()
    total_bytes = ProxyRequest.objects.aggregate(total=Sum('content_length'))['total'] or 0
    avg_response_time = ProxyRequest.objects.aggregate(avg=Avg('response_time'))['avg'] or 0
    
    top_clients = list(ProxyRequest.objects.filter(timestamp__gte=last_24h).values('source_ip').annotate(
        count=Count('id'), blocked=Count('id', filter=Q(blocked=True)), bytes=Sum('content_length')
    ).order_by('-count')[:15])
    
    if not top_clients:
        top_clients = list(ProxyRequest.objects.values('source_ip').annotate(
            count=Count('id'), blocked=Count('id', filter=Q(blocked=True)), bytes=Sum('content_length')
        ).order_by('-count')[:15])
    
    for client in top_clients:
        client['hostname'] = get_cached_hostname(client['source_ip'])
        client['dns_server'] = dns_server
    
    top_domains = DomainStats.objects.order_by('-request_count')[:15]
    top_blocked = DomainStats.objects.filter(blocked_count__gt=0).order_by('-blocked_count')[:10]
    
    methods = list(ProxyRequest.objects.values('method').annotate(count=Count('id')).order_by('-count'))
    status_codes = list(ProxyRequest.objects.values('status_code').annotate(count=Count('id')).order_by('-count'))
    
    context = {
        'page': 'analytics',
        'dns_server': dns_server,
        'total_requests': total_requests,
        'total_bytes': total_bytes,
        'avg_response_time': round(avg_response_time, 2),
        'top_clients': top_clients,
        'top_domains': top_domains,
        'top_blocked': top_blocked,
        'methods': json.dumps(methods),
        'status_codes': status_codes,
    }
    
    return render(request, 'dashboard/analytics.html', context)


@login_required
@operator_required
def blocklist_view(request):
    """Blocklist management page - Shows ALL rules including disabled ones"""
    from apps.blocklist.models import BlockedDomain, BlockedIP, BlockedPort, BlockRule
    
    # Get filter from query params
    show_disabled = request.GET.get('show_disabled', 'true') == 'true'
    
    if show_disabled:
        # Show ALL rules (active and inactive)
        blocked_domains = BlockedDomain.objects.all().order_by('-is_active', '-created_at')[:100]
        blocked_ips = BlockedIP.objects.all().order_by('-is_active', '-created_at')[:100]
        blocked_ports = BlockedPort.objects.all().order_by('-is_active', '-created_at')[:100]
        block_rules = BlockRule.objects.all().order_by('-is_active', 'priority', '-created_at')[:100]
    else:
        # Show only active rules
        blocked_domains = BlockedDomain.objects.filter(is_active=True).order_by('-created_at')[:100]
        blocked_ips = BlockedIP.objects.filter(is_active=True).order_by('-created_at')[:100]
        blocked_ports = BlockedPort.objects.filter(is_active=True).order_by('-created_at')[:100]
        block_rules = BlockRule.objects.filter(is_active=True).order_by('priority', '-created_at')[:100]
    
    context = {
        'page': 'blocklist',
        'blocked_domains': blocked_domains,
        'blocked_ips': blocked_ips,
        'blocked_ports': blocked_ports,
        'block_rules': block_rules,
        'domain_count': BlockedDomain.objects.filter(is_active=True).count(),
        'domain_total': BlockedDomain.objects.count(),
        'ip_count': BlockedIP.objects.filter(is_active=True).count(),
        'ip_total': BlockedIP.objects.count(),
        'port_count': BlockedPort.objects.filter(is_active=True).count(),
        'port_total': BlockedPort.objects.count(),
        'rule_count': BlockRule.objects.filter(is_active=True).count(),
        'rule_total': BlockRule.objects.count(),
        'show_disabled': show_disabled,
    }
    
    return render(request, 'dashboard/blocklist.html', context)


# ============ USER MANAGEMENT ============

@login_required
@admin_required
def users_view(request):
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
            user = User.objects.create_user(username=username, email=email, password=password)
            user.profile.role = role
            user.profile.department = department
            user.profile.save()
            
            log_action(request.user, 'create', 'user', user.id, username, f'Role: {role}', get_client_ip(request))
            messages.success(request, f'User {username} created successfully')
        except Exception as e:
            messages.error(request, f'Error creating user: {e}')
    
    return redirect('dashboard:users')


@login_required
@admin_required
def user_edit(request, user_id):
    user = get_object_or_404(User, id=user_id)
    
    if request.method == 'POST':
        email = request.POST.get('email', '').strip()
        role = request.POST.get('role', 'viewer')
        department = request.POST.get('department', '')
        is_active = request.POST.get('is_active') == 'on'
        new_password = request.POST.get('new_password', '')
        
        user.email = email
        user.is_active = is_active
        if new_password:
            user.set_password(new_password)
        user.save()
        
        user.profile.role = role
        user.profile.department = department
        user.profile.save()
        
        log_action(request.user, 'update', 'user', user.id, user.username, f'Role: {role}', get_client_ip(request))
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
    user = get_object_or_404(User, id=user_id)
    
    if user == request.user:
        messages.error(request, 'You cannot delete yourself')
        return redirect('dashboard:users')
    
    username = user.username
    log_action(request.user, 'delete', 'user', user.id, username, ip_address=get_client_ip(request))
    user.delete()
    messages.success(request, f'User {username} deleted')
    
    return redirect('dashboard:users')


# ============ AUDIT LOGS ============

@login_required
@admin_required
def audit_logs_view(request):
    logs = AuditLog.objects.select_related('user').all()[:500]
    
    context = {
        'page': 'audit_logs',
        'logs': logs,
    }
    
    return render(request, 'dashboard/audit_logs.html', context)


# ============ SETTINGS ============

@login_required
def settings_view(request):
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
                messages.success(request, 'Password changed successfully. Please login again.')
                return redirect('dashboard:login')
        
        elif action == 'update_profile':
            email = request.POST.get('email', '')
            department = request.POST.get('department', '')
            phone = request.POST.get('phone', '')
            
            request.user.email = email
            request.user.save()
            
            request.user.profile.department = department
            request.user.profile.phone = phone
            request.user.profile.save()
            
            messages.success(request, 'Profile updated successfully')
    
    context = {'page': 'settings'}
    return render(request, 'dashboard/settings.html', context)


# ============ API VIEWS ============

@api_view(['GET'])
def api_stats(request):
    now = get_current_time()
    last_24h = now - timedelta(hours=24)
    
    total_requests = ProxyRequest.objects.count()
    blocked_requests = ProxyRequest.objects.filter(blocked=True).count()
    total_bytes = ProxyRequest.objects.aggregate(total=Sum('content_length'))['total'] or 0
    
    return Response({
        'total_requests': total_requests,
        'blocked_requests': blocked_requests,
        'total_bytes': total_bytes,
        'total_bytes_formatted': format_bytes(total_bytes),
        'block_rate': round((blocked_requests / total_requests * 100) if total_requests > 0 else 0, 1),
    })


@api_view(['GET'])
def api_requests(request):
    limit = min(int(request.GET.get('limit', 50)), 500)
    qs = ProxyRequest.objects.order_by('-timestamp')[:limit]
    
    data = [{
        'id': str(r.id),
        'method': r.method,
        'hostname': r.hostname,
        'status_code': r.status_code,
        'blocked': r.blocked,
        'response_time': r.response_time,
        'source_ip': r.source_ip,
        'source_port': r.source_port,
        'timestamp': r.timestamp.isoformat() if r.timestamp else None,
    } for r in qs]
    
    return Response(data)


@api_view(['GET'])
def api_hourly(request):
    now = get_current_time()
    hours = min(int(request.GET.get('hours', 24)), 72)
    
    data = []
    for i in range(hours - 1, -1, -1):
        hour_start = now - timedelta(hours=i+1)
        hour_end = now - timedelta(hours=i)
        total = ProxyRequest.objects.filter(timestamp__gte=hour_start, timestamp__lt=hour_end).count()
        blocked = ProxyRequest.objects.filter(timestamp__gte=hour_start, timestamp__lt=hour_end, blocked=True).count()
        data.append({'hour': hour_end.strftime('%H:00'), 'total': total, 'blocked': blocked})
    
    return Response(data)


@api_view(['GET'])
def api_resolve(request):
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
    IPHostnameCache.objects.all().delete()
    return Response({'message': 'DNS cache cleared'})
