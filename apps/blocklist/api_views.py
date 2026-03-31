# apps/blocklist/api_views.py

from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from django.db.models import Count, Sum
import django_filters
from drf_spectacular.utils import extend_schema

from .models import BlockedDomain, BlockedIP, BlockedPort, BlockRule
from .api_serializers import (
    BlockedDomainSerializer, BlockedDomainListSerializer,
    BulkDomainImportSerializer,
    BlockedIPSerializer,
    BlockedPortSerializer,
    BlockRuleSerializer, BlockRuleListSerializer,
    RuleTestSerializer,
)
from apps.api.permissions import ReadOnlyOrOperator
from apps.api.pagination import StandardPagination
from apps.api.mixins import AuditMixin, BulkDeleteMixin, ExportMixin


# ━━━ BLOCKED DOMAINS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class BlockedDomainFilter(django_filters.FilterSet):
    domain = django_filters.CharFilter(lookup_expr='icontains')
    category = django_filters.ChoiceFilter(choices=BlockedDomain.CATEGORY_CHOICES)
    is_active = django_filters.BooleanFilter()
    is_wildcard = django_filters.BooleanFilter()

    class Meta:
        model = BlockedDomain
        fields = ['domain', 'category', 'is_active', 'is_wildcard']


class BlockedDomainViewSet(AuditMixin, BulkDeleteMixin, ExportMixin, viewsets.ModelViewSet):
    """/api/v1/blocklist/domains/"""
    queryset = BlockedDomain.objects.all()
    permission_classes = [IsAuthenticated, ReadOnlyOrOperator]
    pagination_class = StandardPagination
    filterset_class = BlockedDomainFilter
    search_fields = ['domain', 'reason']
    ordering_fields = ['domain', 'created_at', 'hit_count', 'category']
    audit_target_type = 'domain'
    export_filename = 'blocked_domains'

    def get_serializer_class(self):
        if self.action == 'list':
            return BlockedDomainListSerializer
        return BlockedDomainSerializer

    @extend_schema(responses={200: dict})
    @action(detail=True, methods=['post'])
    def toggle(self, request, pk=None):
        obj = self.get_object()
        obj.is_active = not obj.is_active
        obj.save(update_fields=['is_active'])
        self._log('update', obj)
        return Response({'id': obj.id, 'domain': obj.domain, 'is_active': obj.is_active})

    @extend_schema(request=BulkDomainImportSerializer, responses={201: dict})
    @action(detail=False, methods=['post'], url_path='bulk-import')
    def bulk_import(self, request):
        serializer = BulkDomainImportSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        domains = serializer.validated_data['domains']
        category = serializer.validated_data['category']
        reason = serializer.validated_data.get('reason', 'Bulk import via API')
        existing = set(BlockedDomain.objects.filter(domain__in=[d.lower().strip().rstrip('.') for d in domains]).values_list('domain', flat=True))
        new_entries = []
        for d in domains:
            clean = d.lower().strip().rstrip('.')
            if clean and clean not in existing:
                new_entries.append(BlockedDomain(domain=clean, category=category, reason=reason, is_wildcard='*' in clean or clean.startswith('.')))
                existing.add(clean)
        created = BlockedDomain.objects.bulk_create(new_entries, ignore_conflicts=True)
        return Response({'submitted': len(domains), 'created': len(created), 'skipped_duplicates': len(domains) - len(created)}, status=status.HTTP_201_CREATED)

    @extend_schema(responses={200: dict})
    @action(detail=False, methods=['post'], url_path='bulk-delete')
    def bulk_remove(self, request):
        return self.bulk_delete(request)

    @extend_schema(responses={200: dict})
    @action(detail=False, methods=['get'])
    def check(self, request):
        domain = request.query_params.get('domain', '').strip().lower()
        if not domain:
            return Response({'error': 'domain parameter is required.'}, status=status.HTTP_400_BAD_REQUEST)
        is_blocked, matched = BlockedDomain.is_blocked(domain)
        return Response({'domain': domain, 'is_blocked': is_blocked, 'matched_rule': str(matched.domain) if matched else None, 'category': matched.category if matched else None})

    @action(detail=False, methods=['get'], url_path='export')
    def export_domains(self, request):
        return self.export_data(request)


# ━━━ BLOCKED IPs ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class BlockedIPFilter(django_filters.FilterSet):
    ip_address = django_filters.CharFilter(lookup_expr='icontains')
    ip_type = django_filters.ChoiceFilter(choices=BlockedIP.TYPE_CHOICES)
    is_active = django_filters.BooleanFilter()
    is_range = django_filters.BooleanFilter()

    class Meta:
        model = BlockedIP
        fields = ['ip_address', 'ip_type', 'is_active', 'is_range']


class BlockedIPViewSet(AuditMixin, BulkDeleteMixin, viewsets.ModelViewSet):
    """/api/v1/blocklist/ips/"""
    queryset = BlockedIP.objects.all()
    serializer_class = BlockedIPSerializer
    permission_classes = [IsAuthenticated, ReadOnlyOrOperator]
    pagination_class = StandardPagination
    filterset_class = BlockedIPFilter
    search_fields = ['ip_address', 'reason']
    ordering_fields = ['ip_address', 'created_at', 'hit_count']
    audit_target_type = 'ip'

    @extend_schema(responses={200: dict})
    @action(detail=True, methods=['post'])
    def toggle(self, request, pk=None):
        obj = self.get_object()
        obj.is_active = not obj.is_active
        obj.save(update_fields=['is_active'])
        self._log('update', obj)
        return Response({'id': obj.id, 'ip_address': obj.ip_address, 'is_active': obj.is_active})

    @extend_schema(responses={200: dict})
    @action(detail=False, methods=['get'])
    def check(self, request):
        ip = request.query_params.get('ip', '').strip()
        check_type = request.query_params.get('type', 'source')
        if not ip:
            return Response({'error': 'ip parameter is required.'}, status=status.HTTP_400_BAD_REQUEST)
        is_blocked, matched = BlockedIP.is_blocked(ip, check_type)
        return Response({'ip': ip, 'check_type': check_type, 'is_blocked': is_blocked, 'matched_rule': str(matched) if matched else None})

    @extend_schema(responses={200: dict})
    @action(detail=False, methods=['post'], url_path='bulk-delete')
    def bulk_remove(self, request):
        return self.bulk_delete(request)


# ━━━ BLOCKED PORTS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class BlockedPortFilter(django_filters.FilterSet):
    port = django_filters.NumberFilter()
    port_type = django_filters.ChoiceFilter(choices=BlockedPort.TYPE_CHOICES)
    protocol = django_filters.CharFilter()
    is_active = django_filters.BooleanFilter()

    class Meta:
        model = BlockedPort
        fields = ['port', 'port_type', 'protocol', 'is_active']


class BlockedPortViewSet(AuditMixin, BulkDeleteMixin, viewsets.ModelViewSet):
    """/api/v1/blocklist/ports/"""
    queryset = BlockedPort.objects.all()
    serializer_class = BlockedPortSerializer
    permission_classes = [IsAuthenticated, ReadOnlyOrOperator]
    pagination_class = StandardPagination
    filterset_class = BlockedPortFilter
    search_fields = ['reason']
    ordering_fields = ['port', 'created_at', 'hit_count']
    audit_target_type = 'port'

    @extend_schema(responses={200: dict})
    @action(detail=True, methods=['post'])
    def toggle(self, request, pk=None):
        obj = self.get_object()
        obj.is_active = not obj.is_active
        obj.save(update_fields=['is_active'])
        self._log('update', obj)
        return Response({'id': obj.id, 'port': obj.port, 'is_active': obj.is_active})

    @extend_schema(responses={200: dict})
    @action(detail=False, methods=['post'], url_path='bulk-delete')
    def bulk_remove(self, request):
        return self.bulk_delete(request)


# ━━━ BLOCK RULES ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class BlockRuleFilter(django_filters.FilterSet):
    name = django_filters.CharFilter(lookup_expr='icontains')
    action = django_filters.ChoiceFilter(choices=[('block', 'Block'), ('allow', 'Allow'), ('log', 'Log Only')])
    is_active = django_filters.BooleanFilter()

    class Meta:
        model = BlockRule
        fields = ['name', 'action', 'is_active']


class BlockRuleViewSet(AuditMixin, BulkDeleteMixin, viewsets.ModelViewSet):
    """/api/v1/blocklist/rules/"""
    queryset = BlockRule.objects.all()
    permission_classes = [IsAuthenticated, ReadOnlyOrOperator]
    pagination_class = StandardPagination
    filterset_class = BlockRuleFilter
    search_fields = ['name', 'reason', 'domain_pattern']
    ordering_fields = ['priority', 'name', 'created_at', 'hit_count']
    audit_target_type = 'rule'

    def get_serializer_class(self):
        if self.action == 'list':
            return BlockRuleListSerializer
        return BlockRuleSerializer

    @extend_schema(responses={200: dict})
    @action(detail=True, methods=['post'])
    def toggle(self, request, pk=None):
        obj = self.get_object()
        obj.is_active = not obj.is_active
        obj.save(update_fields=['is_active'])
        self._log('update', obj)
        return Response({'id': obj.id, 'name': obj.name, 'is_active': obj.is_active})

    @extend_schema(request=RuleTestSerializer, responses={200: dict})
    @action(detail=False, methods=['post'])
    def test(self, request):
        serializer = RuleTestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        action_result, matched_rule = BlockRule.check_request(
            hostname=data.get('hostname') or None, source_ip=data.get('source_ip') or None,
            dest_ip=data.get('dest_ip') or None, source_port=data.get('source_port'), dest_port=data.get('dest_port'))
        return Response({'action': action_result, 'matched_rule': BlockRuleListSerializer(matched_rule).data if matched_rule else None, 'tested_against': data})

    @extend_schema(responses={200: dict})
    @action(detail=True, methods=['post'], url_path='move')
    def move_priority(self, request, pk=None):
        obj = self.get_object()
        new_priority = request.data.get('priority')
        if new_priority is None:
            return Response({'error': 'priority is required.'}, status=status.HTTP_400_BAD_REQUEST)
        obj.priority = int(new_priority)
        obj.save(update_fields=['priority'])
        self._log('update', obj)
        return Response({'id': obj.id, 'name': obj.name, 'priority': obj.priority})

    @extend_schema(responses={200: dict})
    @action(detail=False, methods=['post'], url_path='bulk-delete')
    def bulk_remove(self, request):
        return self.bulk_delete(request)


# ━━━ STATS & CHECK ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class BlocklistStatsView(APIView):
    """GET /api/v1/blocklist/stats/"""
    permission_classes = [IsAuthenticated]

    @extend_schema(responses={200: dict})
    def get(self, request):
        return Response({
            'blocked_domains': {
                'total': BlockedDomain.objects.count(),
                'active': BlockedDomain.objects.filter(is_active=True).count(),
                'wildcard': BlockedDomain.objects.filter(is_wildcard=True).count(),
                'total_hits': BlockedDomain.objects.aggregate(total=Sum('hit_count'))['total'] or 0,
            },
            'blocked_ips': {
                'total': BlockedIP.objects.count(),
                'active': BlockedIP.objects.filter(is_active=True).count(),
                'ranges': BlockedIP.objects.filter(is_range=True).count(),
                'total_hits': BlockedIP.objects.aggregate(total=Sum('hit_count'))['total'] or 0,
            },
            'blocked_ports': {
                'total': BlockedPort.objects.count(),
                'active': BlockedPort.objects.filter(is_active=True).count(),
                'total_hits': BlockedPort.objects.aggregate(total=Sum('hit_count'))['total'] or 0,
            },
            'block_rules': {
                'total': BlockRule.objects.count(),
                'active': BlockRule.objects.filter(is_active=True).count(),
                'by_action': list(BlockRule.objects.values('action').annotate(count=Count('id')).order_by('-count')),
                'total_hits': BlockRule.objects.aggregate(total=Sum('hit_count'))['total'] or 0,
            },
            'top_hit_domains': list(BlockedDomain.objects.filter(hit_count__gt=0).order_by('-hit_count').values('domain', 'category', 'hit_count')[:10]),
            'top_hit_ips': list(BlockedIP.objects.filter(hit_count__gt=0).order_by('-hit_count').values('ip_address', 'ip_type', 'hit_count')[:10]),
            'categories': list(BlockedDomain.objects.values('category').annotate(count=Count('id')).order_by('-count')),
        })


class FullCheckView(APIView):
    """POST /api/v1/blocklist/check/"""
    permission_classes = [IsAuthenticated]

    @extend_schema(responses={200: dict})
    def post(self, request):
        hostname = request.data.get('hostname', '')
        source_ip = request.data.get('source_ip', '')
        dest_ip = request.data.get('dest_ip', '')
        source_port = request.data.get('source_port')
        dest_port = request.data.get('dest_port')

        results = {'hostname': hostname, 'source_ip': source_ip, 'dest_ip': dest_ip,
                   'source_port': source_port, 'dest_port': dest_port, 'blocked': False, 'checks': {}}

        if hostname:
            is_blocked, match = BlockedDomain.is_blocked(hostname)
            results['checks']['domain'] = {'blocked': is_blocked, 'matched': str(match.domain) if match else None, 'category': match.category if match else None}
            if is_blocked:
                results['blocked'] = True

        if source_ip:
            is_blocked, match = BlockedIP.is_blocked(source_ip, 'source')
            results['checks']['source_ip'] = {'blocked': is_blocked, 'matched': str(match) if match else None}
            if is_blocked:
                results['blocked'] = True

        if dest_ip:
            is_blocked, match = BlockedIP.is_blocked(dest_ip, 'destination')
            results['checks']['dest_ip'] = {'blocked': is_blocked, 'matched': str(match) if match else None}
            if is_blocked:
                results['blocked'] = True

        if dest_port:
            is_blocked, match = BlockedPort.is_blocked(dest_port, 'destination')
            results['checks']['dest_port'] = {'blocked': is_blocked, 'matched': str(match) if match else None}
            if is_blocked:
                results['blocked'] = True

        if source_port:
            is_blocked, match = BlockedPort.is_blocked(source_port, 'source')
            results['checks']['source_port'] = {'blocked': is_blocked, 'matched': str(match) if match else None}
            if is_blocked:
                results['blocked'] = True

        rule_action, rule_match = BlockRule.check_request(hostname=hostname or None, source_ip=source_ip or None,
                                                          dest_ip=dest_ip or None, source_port=source_port, dest_port=dest_port)
        results['checks']['rules'] = {'action': rule_action, 'matched_rule': {'id': rule_match.id, 'name': rule_match.name, 'priority': rule_match.priority} if rule_match else None}
        if rule_action == 'block':
            results['blocked'] = True
        elif rule_action == 'allow':
            results['blocked'] = False

        return Response(results)