from django.shortcuts import render
from django.db.models import Sum
from rest_framework import viewsets, status
from rest_framework.decorators import api_view, action
from rest_framework.response import Response

from .models import BlockedDomain, BlockedIP, BlockedPort, BlockRule
from .serializers import (
    BlockedDomainSerializer, 
    BlockedIPSerializer, 
    BlockedPortSerializer, 
    BlockRuleSerializer
)


def blocklist_view(request):
    """Main blocklist management page"""
    blocked_domains = BlockedDomain.objects.all().order_by('-created_at')
    blocked_ips = BlockedIP.objects.all().order_by('-created_at')
    blocked_ports = BlockedPort.objects.all().order_by('-created_at')
    block_rules = BlockRule.objects.all().order_by('priority')
    
    domain_hits = BlockedDomain.objects.aggregate(total=Sum('hit_count'))['total'] or 0
    ip_hits = BlockedIP.objects.aggregate(total=Sum('hit_count'))['total'] or 0
    port_hits = BlockedPort.objects.aggregate(total=Sum('hit_count'))['total'] or 0
    rule_hits = BlockRule.objects.aggregate(total=Sum('hit_count'))['total'] or 0
    
    context = {
        'blocked_domains': blocked_domains,
        'blocked_ips': blocked_ips,
        'blocked_ports': blocked_ports,
        'block_rules': block_rules,
        'domain_count': blocked_domains.filter(is_active=True).count(),
        'ip_count': blocked_ips.filter(is_active=True).count(),
        'port_count': blocked_ports.filter(is_active=True).count(),
        'rule_count': block_rules.filter(is_active=True).count(),
        'total_hits': domain_hits + ip_hits + port_hits + rule_hits,
    }
    return render(request, 'dashboard/blocklist.html', context)


# ============ API ViewSets ============

class BlockedDomainViewSet(viewsets.ModelViewSet):
    queryset = BlockedDomain.objects.all().order_by('-created_at')
    serializer_class = BlockedDomainSerializer
    
    @action(detail=True, methods=['post'])
    def toggle(self, request, pk=None):
        obj = self.get_object()
        obj.is_active = not obj.is_active
        obj.save()
        return Response({'status': 'toggled', 'is_active': obj.is_active})


class BlockedIPViewSet(viewsets.ModelViewSet):
    queryset = BlockedIP.objects.all().order_by('-created_at')
    serializer_class = BlockedIPSerializer
    
    @action(detail=True, methods=['post'])
    def toggle(self, request, pk=None):
        obj = self.get_object()
        obj.is_active = not obj.is_active
        obj.save()
        return Response({'status': 'toggled', 'is_active': obj.is_active})


class BlockedPortViewSet(viewsets.ModelViewSet):
    queryset = BlockedPort.objects.all().order_by('-created_at')
    serializer_class = BlockedPortSerializer
    
    @action(detail=True, methods=['post'])
    def toggle(self, request, pk=None):
        obj = self.get_object()
        obj.is_active = not obj.is_active
        obj.save()
        return Response({'status': 'toggled', 'is_active': obj.is_active})


class BlockRuleViewSet(viewsets.ModelViewSet):
    queryset = BlockRule.objects.all().order_by('priority')
    serializer_class = BlockRuleSerializer
    
    @action(detail=True, methods=['post'])
    def toggle(self, request, pk=None):
        obj = self.get_object()
        obj.is_active = not obj.is_active
        obj.save()
        return Response({'status': 'toggled', 'is_active': obj.is_active})


@api_view(['POST'])
def check_blocked(request):
    """API to check if a connection should be blocked"""
    hostname = request.data.get('hostname', '')
    src_ip = request.data.get('source_ip', '')
    dst_ip = request.data.get('dest_ip', '')
    src_port = request.data.get('source_port')
    dst_port = request.data.get('dest_port')
    
    # Check custom rules first
    action, rule = BlockRule.check_request(hostname, src_ip, dst_ip, src_port, dst_port)
    if action == 'allow':
        return Response({'blocked': False, 'reason': f'Allowed by rule: {rule.name}'})
    elif action == 'block':
        return Response({'blocked': True, 'reason': rule.reason or f'Blocked by rule: {rule.name}'})
    
    # Check domain
    if hostname:
        is_blocked, domain_rule = BlockedDomain.is_blocked(hostname)
        if is_blocked:
            return Response({'blocked': True, 'reason': domain_rule.reason or f'Domain blocked'})
    
    # Check source IP
    if src_ip:
        is_blocked, ip_rule = BlockedIP.is_blocked(src_ip, 'source')
        if is_blocked:
            return Response({'blocked': True, 'reason': ip_rule.reason or f'Source IP blocked'})
    
    # Check destination IP
    if dst_ip:
        is_blocked, ip_rule = BlockedIP.is_blocked(dst_ip, 'destination')
        if is_blocked:
            return Response({'blocked': True, 'reason': ip_rule.reason or f'Destination IP blocked'})
    
    # Check source port
    if src_port:
        is_blocked, port_rule = BlockedPort.is_blocked(int(src_port), 'source')
        if is_blocked:
            return Response({'blocked': True, 'reason': port_rule.reason or f'Source port blocked'})
    
    # Check destination port
    if dst_port:
        is_blocked, port_rule = BlockedPort.is_blocked(int(dst_port), 'destination')
        if is_blocked:
            return Response({'blocked': True, 'reason': port_rule.reason or f'Destination port blocked'})
    
    return Response({'blocked': False})
