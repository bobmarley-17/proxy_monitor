from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
import json

from .models import BlockedDomain, BlockedIP, BlockedPort, BlockRule
from .serializers import (
    BlockedDomainSerializer, 
    BlockedIPSerializer, 
    BlockedPortSerializer,
    BlockRuleSerializer
)


class BlockedDomainViewSet(viewsets.ModelViewSet):
    queryset = BlockedDomain.objects.all()
    serializer_class = BlockedDomainSerializer

    @action(detail=True, methods=['post'])
    def toggle(self, request, pk=None):
        domain = self.get_object()
        domain.is_active = not domain.is_active
        domain.save()
        return Response({'status': 'ok', 'is_active': domain.is_active})

    @action(detail=True, methods=['post'])
    def reset_hits(self, request, pk=None):
        domain = self.get_object()
        domain.hit_count = 0
        domain.save()
        return Response({'status': 'ok'})

    @action(detail=False, methods=['post'])
    def bulk_add(self, request):
        """Add multiple domains at once"""
        domains = request.data.get('domains', [])
        category = request.data.get('category', 'manual')
        reason = request.data.get('reason', '')
        
        created = 0
        for domain in domains:
            domain = domain.strip().lower()
            if domain:
                obj, is_new = BlockedDomain.objects.get_or_create(
                    domain=domain,
                    defaults={'category': category, 'reason': reason}
                )
                if is_new:
                    created += 1
        
        return Response({'status': 'ok', 'created': created})

    @action(detail=False, methods=['post'])
    def check(self, request):
        """Check if a domain is blocked"""
        hostname = request.data.get('hostname', '')
        is_blocked, rule = BlockedDomain.is_blocked(hostname)
        return Response({
            'hostname': hostname,
            'is_blocked': is_blocked,
            'rule': BlockedDomainSerializer(rule).data if rule else None
        })


class BlockedIPViewSet(viewsets.ModelViewSet):
    queryset = BlockedIP.objects.all()
    serializer_class = BlockedIPSerializer

    @action(detail=True, methods=['post'])
    def toggle(self, request, pk=None):
        ip = self.get_object()
        ip.is_active = not ip.is_active
        ip.save()
        return Response({'status': 'ok', 'is_active': ip.is_active})

    @action(detail=True, methods=['post'])
    def reset_hits(self, request, pk=None):
        ip = self.get_object()
        ip.hit_count = 0
        ip.save()
        return Response({'status': 'ok'})

    @action(detail=False, methods=['post'])
    def check(self, request):
        """Check if an IP is blocked"""
        ip = request.data.get('ip', '')
        check_type = request.data.get('type', 'source')
        is_blocked, rule = BlockedIP.is_blocked(ip, check_type)
        return Response({
            'ip': ip,
            'type': check_type,
            'is_blocked': is_blocked,
            'rule': BlockedIPSerializer(rule).data if rule else None
        })


class BlockedPortViewSet(viewsets.ModelViewSet):
    queryset = BlockedPort.objects.all()
    serializer_class = BlockedPortSerializer

    @action(detail=True, methods=['post'])
    def toggle(self, request, pk=None):
        port = self.get_object()
        port.is_active = not port.is_active
        port.save()
        return Response({'status': 'ok', 'is_active': port.is_active})

    @action(detail=False, methods=['post'])
    def check(self, request):
        """Check if a port is blocked"""
        port = request.data.get('port')
        check_type = request.data.get('type', 'destination')
        is_blocked, rule = BlockedPort.is_blocked(port, check_type)
        return Response({
            'port': port,
            'type': check_type,
            'is_blocked': is_blocked,
            'rule': BlockedPortSerializer(rule).data if rule else None
        })


class BlockRuleViewSet(viewsets.ModelViewSet):
    queryset = BlockRule.objects.all()
    serializer_class = BlockRuleSerializer

    @action(detail=True, methods=['post'])
    def toggle(self, request, pk=None):
        rule = self.get_object()
        rule.is_active = not rule.is_active
        rule.save()
        return Response({'status': 'ok', 'is_active': rule.is_active})

    @action(detail=False, methods=['post'])
    def check(self, request):
        """Check if a request matches any rule"""
        hostname = request.data.get('hostname')
        source_ip = request.data.get('source_ip')
        dest_ip = request.data.get('dest_ip')
        source_port = request.data.get('source_port')
        dest_port = request.data.get('dest_port')

        action_result, rule = BlockRule.check_request(
            hostname=hostname,
            source_ip=source_ip,
            dest_ip=dest_ip,
            source_port=source_port,
            dest_port=dest_port
        )

        return Response({
            'action': action_result,
            'rule': BlockRuleSerializer(rule).data if rule else None
        })


# Simple function-based views for quick checks
@csrf_exempt
@require_http_methods(["POST"])
def check_blocked(request):
    """Check if a request should be blocked"""
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)

    hostname = data.get('hostname', '').lower().strip()
    source_ip = data.get('source_ip', '')
    dest_ip = data.get('dest_ip', '')
    source_port = data.get('source_port')
    dest_port = data.get('dest_port')

    # Check combined rules first (highest priority)
    action_result, rule = BlockRule.check_request(
        hostname=hostname,
        source_ip=source_ip,
        dest_ip=dest_ip,
        source_port=source_port,
        dest_port=dest_port
    )

    if action_result:
        return JsonResponse({
            'blocked': action_result == 'block',
            'action': action_result,
            'reason': f"Rule: {rule.name}" if rule else None,
            'rule_type': 'combined'
        })

    # Check domain
    if hostname:
        is_blocked, domain_rule = BlockedDomain.is_blocked(hostname)
        if is_blocked:
            return JsonResponse({
                'blocked': True,
                'action': 'block',
                'reason': f"Domain blocked: {domain_rule.domain}",
                'rule_type': 'domain',
                'category': domain_rule.category
            })

    # Check source IP
    if source_ip:
        is_blocked, ip_rule = BlockedIP.is_blocked(source_ip, 'source')
        if is_blocked:
            return JsonResponse({
                'blocked': True,
                'action': 'block',
                'reason': f"Source IP blocked: {ip_rule.ip_address}",
                'rule_type': 'source_ip'
            })

    # Check destination IP
    if dest_ip:
        is_blocked, ip_rule = BlockedIP.is_blocked(dest_ip, 'destination')
        if is_blocked:
            return JsonResponse({
                'blocked': True,
                'action': 'block',
                'reason': f"Destination IP blocked: {ip_rule.ip_address}",
                'rule_type': 'dest_ip'
            })

    # Check source port
    if source_port:
        is_blocked, port_rule = BlockedPort.is_blocked(int(source_port), 'source')
        if is_blocked:
            return JsonResponse({
                'blocked': True,
                'action': 'block',
                'reason': f"Source port blocked: {port_rule.port}",
                'rule_type': 'source_port'
            })

    # Check destination port
    if dest_port:
        is_blocked, port_rule = BlockedPort.is_blocked(int(dest_port), 'destination')
        if is_blocked:
            return JsonResponse({
                'blocked': True,
                'action': 'block',
                'reason': f"Destination port blocked: {port_rule.port}",
                'rule_type': 'dest_port'
            })

    return JsonResponse({
        'blocked': False,
        'action': 'allow',
        'reason': None,
        'rule_type': None
    })
