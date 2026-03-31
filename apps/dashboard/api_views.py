# apps/dashboard/api_views.py

from rest_framework import viewsets, generics, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.models import User
from django.db.models import Count, Avg, Sum, Q
from django.db.models.functions import TruncHour, TruncDay
from django.utils import timezone
from datetime import timedelta
import django_filters
from drf_spectacular.utils import extend_schema, OpenApiParameter

from .models import UserProfile, ProxyRequest, DomainStats, AuditLog
from .api_serializers import (
    ProfileSerializer, ChangePasswordSerializer,
    UserListSerializer, UserDetailSerializer, UserCreateSerializer,
    ProxyRequestSerializer, ProxyRequestListSerializer,
    DomainStatsSerializer, AuditLogSerializer,
)
from apps.api.permissions import IsAdmin, IsOperatorOrAdmin, ReadOnlyOrOperator
from apps.api.pagination import StandardPagination, LargePagination
from apps.api.mixins import AuditMixin, ExportMixin, BulkDeleteMixin
from apps.api.throttles import LoginRateThrottle


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# AUTH
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class LoginView(TokenObtainPairView):
    """POST /api/v1/auth/login/"""
    throttle_classes = [LoginRateThrottle]

    def post(self, request, *args, **kwargs):
        response = super().post(request, *args, **kwargs)
        if response.status_code == 200:
            try:
                user = User.objects.get(username=request.data.get('username'))
                xff = request.META.get('HTTP_X_FORWARDED_FOR')
                ip = xff.split(',')[0].strip() if xff else request.META.get('REMOTE_ADDR', '')
                AuditLog.objects.create(
                    user=user,
                    action='login',
                    target_type='user',
                    target_name=user.username,
                    details='API login',
                    ip_address=ip,
                )
            except Exception:
                pass
        return response


class LogoutView(APIView):
    """POST /api/v1/auth/logout/"""
    permission_classes = [IsAuthenticated]

    @extend_schema(responses={200: dict})
    def post(self, request):
        try:
            refresh_token = request.data.get('refresh')
            if not refresh_token:
                return Response(
                    {'error': 'refresh token is required'},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            token = RefreshToken(refresh_token)
            token.blacklist()
            AuditLog.objects.create(
                user=request.user,
                action='logout',
                target_type='user',
                target_name=request.user.username,
                details='API logout',
            )
            return Response({'detail': 'Successfully logged out.'})
        except Exception:
            return Response(
                {'error': 'Invalid or expired token.'},
                status=status.HTTP_400_BAD_REQUEST,
            )


class ProfileView(generics.RetrieveUpdateAPIView):
    """GET/PUT /api/v1/auth/profile/"""
    serializer_class = ProfileSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        return self.request.user


class ChangePasswordView(APIView):
    """POST /api/v1/auth/change-password/"""
    permission_classes = [IsAuthenticated]

    @extend_schema(request=ChangePasswordSerializer, responses={200: dict})
    def post(self, request):
        serializer = ChangePasswordSerializer(
            data=request.data, context={'request': request},
        )
        serializer.is_valid(raise_exception=True)
        request.user.set_password(serializer.validated_data['new_password'])
        request.user.save()
        return Response({'detail': 'Password updated successfully.'})


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# USER MANAGEMENT
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class UserFilter(django_filters.FilterSet):
    role = django_filters.CharFilter(field_name='profile__role')
    is_active = django_filters.BooleanFilter()
    search = django_filters.CharFilter(method='filter_search')

    class Meta:
        model = User
        fields = ['is_active']

    def filter_search(self, queryset, name, value):
        return queryset.filter(
            Q(username__icontains=value)
            | Q(email__icontains=value)
            | Q(first_name__icontains=value)
            | Q(last_name__icontains=value)
        )


class UserViewSet(AuditMixin, viewsets.ModelViewSet):
    """/api/v1/users/"""
    queryset = User.objects.select_related('profile').order_by('-date_joined')
    permission_classes = [IsAuthenticated, IsAdmin]
    pagination_class = StandardPagination
    filterset_class = UserFilter
    search_fields = ['username', 'email', 'first_name', 'last_name']
    ordering_fields = ['username', 'date_joined', 'last_login']
    audit_target_type = 'user'

    def get_serializer_class(self):
        if self.action == 'create':
            return UserCreateSerializer
        if self.action == 'list':
            return UserListSerializer
        return UserDetailSerializer

    @extend_schema(responses={200: dict})
    @action(detail=True, methods=['post'], url_path='toggle-active')
    def toggle_active(self, request, pk=None):
        user = self.get_object()
        if user == request.user:
            return Response(
                {'error': 'Cannot deactivate yourself.'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        user.is_active = not user.is_active
        user.save(update_fields=['is_active'])
        AuditLog.objects.create(
            user=request.user,
            action='update',
            target_type='user',
            target_id=str(user.pk),
            target_name=user.username,
            details='{} user'.format('Activated' if user.is_active else 'Deactivated'),
            ip_address=self._client_ip(),
        )
        return Response({
            'id': user.id,
            'username': user.username,
            'is_active': user.is_active,
        })

    @extend_schema(responses={200: dict})
    @action(detail=True, methods=['post'], url_path='reset-password')
    def reset_password(self, request, pk=None):
        user = self.get_object()
        new_password = request.data.get('new_password', '')
        if len(new_password) < 8:
            return Response(
                {'error': 'Password must be at least 8 characters.'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        user.set_password(new_password)
        user.save()
        AuditLog.objects.create(
            user=request.user,
            action='update',
            target_type='user',
            target_id=str(user.pk),
            target_name=user.username,
            details='Password reset via API',
            ip_address=self._client_ip(),
        )
        return Response({'detail': 'Password reset for {}.'.format(user.username)})

    @extend_schema(responses={200: dict})
    @action(detail=True, methods=['post'], url_path='change-role')
    def change_role(self, request, pk=None):
        user = self.get_object()
        new_role = request.data.get('role', '')
        valid_roles = [r[0] for r in UserProfile.ROLE_CHOICES]
        if new_role not in valid_roles:
            return Response(
                {'error': 'Invalid role. Choices: {}'.format(valid_roles)},
                status=status.HTTP_400_BAD_REQUEST,
            )
        profile = user.profile
        old_role = profile.role
        profile.role = new_role
        profile.save(update_fields=['role'])
        AuditLog.objects.create(
            user=request.user,
            action='update',
            target_type='user',
            target_id=str(user.pk),
            target_name=user.username,
            details='Role changed: {} -> {}'.format(old_role, new_role),
            ip_address=self._client_ip(),
        )
        return Response({
            'id': user.id,
            'username': user.username,
            'role': new_role,
        })


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# PROXY REQUEST LOGS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class ProxyRequestFilter(django_filters.FilterSet):
    hostname = django_filters.CharFilter(lookup_expr='icontains')
    source_ip = django_filters.CharFilter(lookup_expr='exact')
    destination_ip = django_filters.CharFilter(lookup_expr='exact')
    method = django_filters.CharFilter(lookup_expr='iexact')
    blocked = django_filters.BooleanFilter()
    block_type = django_filters.CharFilter(lookup_expr='iexact')
    status_code = django_filters.NumberFilter()
    status_code_min = django_filters.NumberFilter(field_name='status_code', lookup_expr='gte')
    status_code_max = django_filters.NumberFilter(field_name='status_code', lookup_expr='lte')
    start_time = django_filters.DateTimeFilter(field_name='timestamp', lookup_expr='gte')
    end_time = django_filters.DateTimeFilter(field_name='timestamp', lookup_expr='lte')

    class Meta:
        model = ProxyRequest
        fields = ['hostname', 'source_ip', 'destination_ip', 'method', 'blocked', 'block_type', 'status_code']


class ProxyRequestViewSet(ExportMixin, viewsets.ReadOnlyModelViewSet):
    """/api/v1/requests/"""
    queryset = ProxyRequest.objects.all()
    permission_classes = [IsAuthenticated]
    pagination_class = LargePagination
    filterset_class = ProxyRequestFilter
    search_fields = ['hostname', 'url', 'source_ip', 'block_reason']
    ordering_fields = ['timestamp', 'hostname', 'response_time', 'status_code']
    export_filename = 'proxy_requests'

    def get_serializer_class(self):
        if self.action == 'list':
            return ProxyRequestListSerializer
        return ProxyRequestSerializer

    @extend_schema(responses={200: dict}, parameters=[
        OpenApiParameter(name='period', type=str, enum=['1h', '6h', '24h', '7d', '30d']),
    ])
    @action(detail=False, methods=['get'])
    def summary(self, request):
        qs = self._filtered_by_period(request)
        total = qs.count()
        blocked = qs.filter(blocked=True).count()
        return Response({
            'total_requests': total,
            'blocked_requests': blocked,
            'allowed_requests': total - blocked,
            'block_rate': round((blocked / total * 100) if total else 0, 2),
            'unique_clients': qs.values('source_ip').distinct().count(),
            'unique_domains': qs.values('hostname').distinct().count(),
            'avg_response_time': round(qs.aggregate(avg=Avg('response_time'))['avg'] or 0, 2),
            'total_bytes': qs.aggregate(total=Sum('content_length'))['total'] or 0,
            'top_domains': list(qs.values('hostname').annotate(count=Count('id')).order_by('-count')[:10]),
            'top_blocked': list(qs.filter(blocked=True).values('hostname').annotate(count=Count('id')).order_by('-count')[:10]),
            'top_clients': list(qs.values('source_ip').annotate(count=Count('id')).order_by('-count')[:10]),
        })

    @extend_schema(responses={200: dict}, parameters=[
        OpenApiParameter(name='period', type=str, enum=['1h', '6h', '24h', '7d', '30d']),
    ])
    @action(detail=False, methods=['get'])
    def timeline(self, request):
        qs = self._filtered_by_period(request)
        period = request.query_params.get('period', '24h')
        trunc = TruncHour('timestamp') if period in ('1h', '6h', '24h') else TruncDay('timestamp')
        data = list(qs.annotate(bucket=trunc).values('bucket').annotate(
            total=Count('id'),
            blocked=Count('id', filter=Q(blocked=True)),
            allowed=Count('id', filter=Q(blocked=False)),
        ).order_by('bucket'))
        return Response(data)

    @extend_schema(responses={200: ProxyRequestListSerializer(many=True)})
    @action(detail=False, methods=['get'])
    def live(self, request):
        since = request.query_params.get('since')
        qs = self.get_queryset()
        if since:
            from django.utils.dateparse import parse_datetime
            since_dt = parse_datetime(since)
            if since_dt:
                qs = qs.filter(timestamp__gt=since_dt)
        serializer = ProxyRequestListSerializer(qs[:50], many=True)
        return Response(serializer.data)

    @action(detail=False, methods=['get'], url_path='export')
    def export_requests(self, request):
        return self.export_data(request)

    @extend_schema(responses={200: dict})
    @action(detail=False, methods=['delete'], url_path='purge')
    def purge(self, request):
        if not request.user.is_superuser:
            try:
                if request.user.profile.role != 'admin':
                    return Response({'error': 'Admin access required.'}, status=status.HTTP_403_FORBIDDEN)
            except Exception:
                return Response({'error': 'Admin access required.'}, status=status.HTTP_403_FORBIDDEN)
        older_than = request.query_params.get('older_than', '30d')
        days_map = {'7d': 7, '14d': 14, '30d': 30, '60d': 60, '90d': 90}
        days = days_map.get(older_than, 30)
        cutoff = timezone.now() - timedelta(days=days)
        count, _ = ProxyRequest.objects.filter(timestamp__lt=cutoff).delete()
        AuditLog.objects.create(user=request.user, action='delete', target_type='settings',
                                details='Purged {} proxy logs older than {} days'.format(count, days))
        return Response({'deleted': count, 'older_than': '{}d'.format(days)})

    def _filtered_by_period(self, request):
        period = request.query_params.get('period', '24h')
        time_map = {'1h': timedelta(hours=1), '6h': timedelta(hours=6), '24h': timedelta(days=1),
                    '7d': timedelta(days=7), '30d': timedelta(days=30)}
        since = timezone.now() - time_map.get(period, timedelta(days=1))
        return self.get_queryset().filter(timestamp__gte=since)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# DOMAIN STATS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class DomainStatsFilter(django_filters.FilterSet):
    hostname = django_filters.CharFilter(lookup_expr='icontains')
    min_requests = django_filters.NumberFilter(field_name='request_count', lookup_expr='gte')
    has_blocks = django_filters.BooleanFilter(method='filter_has_blocks')

    class Meta:
        model = DomainStats
        fields = ['hostname']

    def filter_has_blocks(self, queryset, name, value):
        return queryset.filter(blocked_count__gt=0) if value else queryset.filter(blocked_count=0)


class DomainStatsViewSet(viewsets.ReadOnlyModelViewSet):
    """/api/v1/domains/"""
    queryset = DomainStats.objects.all()
    serializer_class = DomainStatsSerializer
    permission_classes = [IsAuthenticated]
    pagination_class = StandardPagination
    filterset_class = DomainStatsFilter
    search_fields = ['hostname']
    ordering_fields = ['request_count', 'blocked_count', 'total_bytes', 'last_seen']

    @action(detail=False, methods=['get'], url_path='top-requested')
    def top_requested(self, request):
        limit = min(int(request.query_params.get('limit', 20)), 100)
        serializer = self.get_serializer(self.get_queryset().order_by('-request_count')[:limit], many=True)
        return Response(serializer.data)

    @action(detail=False, methods=['get'], url_path='top-blocked')
    def top_blocked(self, request):
        limit = min(int(request.query_params.get('limit', 20)), 100)
        serializer = self.get_serializer(self.get_queryset().filter(blocked_count__gt=0).order_by('-blocked_count')[:limit], many=True)
        return Response(serializer.data)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# AUDIT LOGS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class AuditLogFilter(django_filters.FilterSet):
    user = django_filters.NumberFilter(field_name='user__id')
    username = django_filters.CharFilter(field_name='user__username', lookup_expr='icontains')
    action = django_filters.ChoiceFilter(choices=AuditLog.ACTION_CHOICES)
    target_type = django_filters.CharFilter(lookup_expr='iexact')
    start_time = django_filters.DateTimeFilter(field_name='timestamp', lookup_expr='gte')
    end_time = django_filters.DateTimeFilter(field_name='timestamp', lookup_expr='lte')

    class Meta:
        model = AuditLog
        fields = ['action', 'target_type']


class AuditLogViewSet(ExportMixin, viewsets.ReadOnlyModelViewSet):
    """/api/v1/audit-logs/"""
    queryset = AuditLog.objects.select_related('user').all()
    serializer_class = AuditLogSerializer
    permission_classes = [IsAuthenticated, IsAdmin]
    pagination_class = StandardPagination
    filterset_class = AuditLogFilter
    search_fields = ['details', 'target_name', 'user__username']
    ordering_fields = ['timestamp', 'action']
    export_filename = 'audit_logs'

    @action(detail=False, methods=['get'], url_path='export')
    def export_logs(self, request):
        return self.export_data(request)

    @extend_schema(responses={200: dict})
    @action(detail=False, methods=['get'])
    def summary(self, request):
        period = request.query_params.get('period', '7d')
        time_map = {'24h': timedelta(days=1), '7d': timedelta(days=7), '30d': timedelta(days=30)}
        since = timezone.now() - time_map.get(period, timedelta(days=7))
        qs = self.get_queryset().filter(timestamp__gte=since)
        return Response({
            'total': qs.count(),
            'by_action': list(qs.values('action').annotate(count=Count('id')).order_by('-count')),
            'by_target_type': list(qs.values('target_type').annotate(count=Count('id')).order_by('-count')),
            'by_user': list(qs.values('user__username').annotate(count=Count('id')).order_by('-count')[:10]),
        })


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# DASHBOARD / ANALYTICS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class DashboardStatsView(APIView):
    """GET /api/v1/dashboard/stats/"""
    permission_classes = [IsAuthenticated]

    @extend_schema(responses={200: dict})
    def get(self, request):
        now = timezone.now()
        last_24h = now - timedelta(hours=24)
        prev_24h = last_24h - timedelta(hours=24)
        current = ProxyRequest.objects.filter(timestamp__gte=last_24h)
        previous = ProxyRequest.objects.filter(timestamp__gte=prev_24h, timestamp__lt=last_24h)
        curr_total = current.count()
        curr_blocked = current.filter(blocked=True).count()
        prev_total = previous.count()
        prev_blocked = previous.filter(blocked=True).count()

        def pct_change(curr, prev):
            if prev == 0:
                return 100.0 if curr > 0 else 0.0
            return round(((curr - prev) / prev) * 100, 1)

        blocklist_counts = {}
        try:
            from apps.blocklist.models import BlockedDomain, BlockedIP, BlockedPort, BlockRule
            blocklist_counts = {
                'blocked_domains': BlockedDomain.objects.filter(is_active=True).count(),
                'blocked_ips': BlockedIP.objects.filter(is_active=True).count(),
                'blocked_ports': BlockedPort.objects.filter(is_active=True).count(),
                'active_rules': BlockRule.objects.filter(is_active=True).count(),
            }
        except Exception:
            blocklist_counts = {'blocked_domains': 0, 'blocked_ips': 0, 'blocked_ports': 0, 'active_rules': 0}

        return Response({
            'total_requests': curr_total,
            'blocked_requests': curr_blocked,
            'allowed_requests': curr_total - curr_blocked,
            'block_rate': round((curr_blocked / curr_total * 100) if curr_total else 0, 1),
            'unique_clients': current.values('source_ip').distinct().count(),
            'unique_domains': current.values('hostname').distinct().count(),
            'avg_response_time': round(current.aggregate(avg=Avg('response_time'))['avg'] or 0, 1),
            'trends': {'requests_change': pct_change(curr_total, prev_total), 'blocked_change': pct_change(curr_blocked, prev_blocked)},
            'blocklist': blocklist_counts,
        })


class AnalyticsView(APIView):
    """GET /api/v1/analytics/?period=24h"""
    permission_classes = [IsAuthenticated]

    @extend_schema(responses={200: dict}, parameters=[
        OpenApiParameter(name='period', type=str, enum=['1h', '6h', '24h', '7d', '30d']),
    ])
    def get(self, request):
        period = request.query_params.get('period', '24h')
        time_map = {'1h': timedelta(hours=1), '6h': timedelta(hours=6), '24h': timedelta(days=1),
                    '7d': timedelta(days=7), '30d': timedelta(days=30)}
        since = timezone.now() - time_map.get(period, timedelta(days=1))
        qs = ProxyRequest.objects.filter(timestamp__gte=since)
        total = qs.count()
        blocked = qs.filter(blocked=True).count()
        trunc = TruncHour('timestamp') if period in ('1h', '6h', '24h') else TruncDay('timestamp')

        return Response({
            'period': period,
            'total_requests': total,
            'blocked_requests': blocked,
            'allowed_requests': total - blocked,
            'block_rate': round((blocked / total * 100) if total else 0, 2),
            'unique_clients': qs.values('source_ip').distinct().count(),
            'unique_domains': qs.values('hostname').distinct().count(),
            'avg_response_time': round(qs.aggregate(avg=Avg('response_time'))['avg'] or 0, 2),
            'total_bytes': qs.aggregate(total=Sum('content_length'))['total'] or 0,
            'top_domains': list(qs.values('hostname').annotate(count=Count('id')).order_by('-count')[:15]),
            'top_blocked_domains': list(qs.filter(blocked=True).values('hostname').annotate(count=Count('id')).order_by('-count')[:15]),
            'top_clients': list(qs.values('source_ip').annotate(count=Count('id'), blocked_count=Count('id', filter=Q(blocked=True))).order_by('-count')[:15]),
            'requests_over_time': list(qs.annotate(bucket=trunc).values('bucket').annotate(total=Count('id'), blocked_count=Count('id', filter=Q(blocked=True))).order_by('bucket')),
            'methods_distribution': list(qs.values('method').annotate(count=Count('id')).order_by('-count')),
            'status_distribution': list(qs.values('status_code').annotate(count=Count('id')).order_by('-count')[:10]),
            'block_reasons': list(qs.filter(blocked=True).exclude(block_type__isnull=True).exclude(block_type='').values('block_type').annotate(count=Count('id')).order_by('-count')),
        })
