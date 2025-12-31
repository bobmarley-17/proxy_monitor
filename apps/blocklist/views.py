from django.shortcuts import get_object_or_404
from rest_framework.decorators import api_view
from rest_framework.response import Response
import traceback

from .models import BlockedDomain, BlockedIP, BlockedPort, BlockRule


def get_client_ip(request):
    """Get client IP from request"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0]
    return request.META.get('REMOTE_ADDR')


def log_audit(request, action, target_type, target_id, target_name, details=None):
    """Log action to audit log"""
    try:
        from apps.dashboard.models import AuditLog
        
        user = request.user if request.user.is_authenticated else None
        ip_address = get_client_ip(request)
        
        AuditLog.objects.create(
            user=user,
            action=action,
            target_type=target_type,
            target_id=str(target_id) if target_id else None,
            target_name=target_name,
            details=details,
            ip_address=ip_address
        )
    except Exception as e:
        print(f"Audit log error: {e}")


# ============ Domain Views ============

@api_view(['GET', 'POST'])
def domain_list(request):
    if request.method == 'GET':
        show_all = request.GET.get('all', 'true') == 'true'
        if show_all:
            domains = BlockedDomain.objects.all().order_by('-is_active', '-created_at')
        else:
            domains = BlockedDomain.objects.filter(is_active=True).order_by('-created_at')
        
        data = [{
            'id': d.id,
            'domain': d.domain,
            'category': d.category,
            'reason': d.reason,
            'is_active': d.is_active,
            'created_at': d.created_at.isoformat() if d.created_at else None,
        } for d in domains]
        return Response(data)
    
    elif request.method == 'POST':
        try:
            data = request.data
            domain = data.get('domain', '').strip().lower()
            category = data.get('category', 'custom')
            reason = data.get('reason', '')
            
            if not domain:
                return Response({'error': 'Domain is required'}, status=400)
            
            domain = domain.replace('http://', '').replace('https://', '').split('/')[0]
            
            if BlockedDomain.objects.filter(domain=domain).exists():
                return Response({'error': 'Domain already exists'}, status=400)
            
            blocked = BlockedDomain.objects.create(
                domain=domain,
                category=category,
                reason=reason,
                is_active=True
            )
            
            # Audit log
            log_audit(
                request, 
                'block', 
                'domain', 
                blocked.id, 
                domain,
                f"Added blocked domain. Category: {category}. Reason: {reason or 'None'}"
            )
            
            return Response({
                'id': blocked.id,
                'domain': blocked.domain,
                'message': f'Domain {domain} blocked successfully'
            }, status=201)
            
        except Exception as e:
            traceback.print_exc()
            return Response({'error': str(e)}, status=500)


@api_view(['GET', 'PUT', 'DELETE'])
def domain_detail(request, pk):
    try:
        domain = BlockedDomain.objects.get(pk=pk)
    except BlockedDomain.DoesNotExist:
        return Response({'error': 'Domain not found'}, status=404)
    
    if request.method == 'GET':
        return Response({
            'id': domain.id,
            'domain': domain.domain,
            'category': domain.category,
            'reason': domain.reason,
            'is_active': domain.is_active,
        })
    
    elif request.method == 'PUT':
        try:
            data = request.data
            old_category = domain.category
            old_reason = domain.reason
            old_active = domain.is_active
            
            domain.category = data.get('category', domain.category)
            domain.reason = data.get('reason', domain.reason)
            
            is_active = data.get('is_active')
            if is_active is not None:
                if isinstance(is_active, bool):
                    domain.is_active = is_active
                else:
                    domain.is_active = str(is_active).lower() in ['true', '1', 'yes', 'on']
            
            domain.save()
            
            # Build change details
            changes = []
            if old_category != domain.category:
                changes.append(f"Category: {old_category} → {domain.category}")
            if old_reason != domain.reason:
                changes.append(f"Reason updated")
            if old_active != domain.is_active:
                changes.append(f"Status: {'Enabled' if domain.is_active else 'Disabled'}")
            
            # Audit log
            log_audit(
                request,
                'update',
                'domain',
                domain.id,
                domain.domain,
                ". ".join(changes) if changes else "Updated"
            )
            
            return Response({
                'message': 'Domain updated successfully',
                'is_active': domain.is_active
            })
        except Exception as e:
            traceback.print_exc()
            return Response({'error': str(e)}, status=500)
    
    elif request.method == 'DELETE':
        domain_name = domain.domain
        domain_id = domain.id
        
        # Audit log before delete
        log_audit(
            request,
            'delete',
            'domain',
            domain_id,
            domain_name,
            f"Deleted blocked domain. Category: {domain.category}"
        )
        
        domain.delete()
        return Response({'message': f'Domain {domain_name} deleted'})


@api_view(['POST'])
def domain_toggle(request, pk):
    """Toggle domain active status"""
    try:
        domain = BlockedDomain.objects.get(pk=pk)
        old_status = domain.is_active
        domain.is_active = not domain.is_active
        domain.save()
        
        action = 'enable' if domain.is_active else 'disable'
        
        # Audit log
        log_audit(
            request,
            'unblock' if not domain.is_active else 'block',
            'domain',
            domain.id,
            domain.domain,
            f"{'Enabled' if domain.is_active else 'Disabled'} domain blocking rule"
        )
        
        return Response({
            'message': f'Domain {"enabled" if domain.is_active else "disabled"}',
            'is_active': domain.is_active
        })
    except BlockedDomain.DoesNotExist:
        return Response({'error': 'Domain not found'}, status=404)
    except Exception as e:
        return Response({'error': str(e)}, status=500)


# ============ IP Views ============

@api_view(['GET', 'POST'])
def ip_list(request):
    if request.method == 'GET':
        show_all = request.GET.get('all', 'true') == 'true'
        if show_all:
            ips = BlockedIP.objects.all().order_by('-is_active', '-created_at')
        else:
            ips = BlockedIP.objects.filter(is_active=True).order_by('-created_at')
        
        data = [{
            'id': ip.id,
            'ip_address': ip.ip_address,
            'cidr_prefix': ip.cidr_prefix,
            'ip_type': ip.ip_type,
            'reason': ip.reason,
            'is_active': ip.is_active,
            'created_at': ip.created_at.isoformat() if ip.created_at else None,
        } for ip in ips]
        return Response(data)
    
    elif request.method == 'POST':
        try:
            data = request.data
            ip_address = data.get('ip_address', '').strip()
            cidr_prefix = data.get('cidr_prefix')
            ip_type = data.get('ip_type', 'both')
            reason = data.get('reason', '')
            
            if not ip_address:
                return Response({'error': 'IP address is required'}, status=400)
            
            if BlockedIP.objects.filter(ip_address=ip_address).exists():
                return Response({'error': 'IP already exists'}, status=400)
            
            blocked = BlockedIP.objects.create(
                ip_address=ip_address,
                cidr_prefix=int(cidr_prefix) if cidr_prefix else None,
                ip_type=ip_type,
                reason=reason,
                is_active=True
            )
            
            cidr_str = f"/{cidr_prefix}" if cidr_prefix else ""
            
            # Audit log
            log_audit(
                request,
                'block',
                'ip',
                blocked.id,
                f"{ip_address}{cidr_str}",
                f"Added blocked IP. Type: {ip_type}. Reason: {reason or 'None'}"
            )
            
            return Response({'id': blocked.id, 'message': f'IP {ip_address} blocked'}, status=201)
        except Exception as e:
            traceback.print_exc()
            return Response({'error': str(e)}, status=500)


@api_view(['GET', 'PUT', 'DELETE'])
def ip_detail(request, pk):
    try:
        ip = BlockedIP.objects.get(pk=pk)
    except BlockedIP.DoesNotExist:
        return Response({'error': 'IP not found'}, status=404)
    
    if request.method == 'GET':
        return Response({
            'id': ip.id,
            'ip_address': ip.ip_address,
            'cidr_prefix': ip.cidr_prefix,
            'ip_type': ip.ip_type,
            'reason': ip.reason,
            'is_active': ip.is_active,
        })
    
    elif request.method == 'PUT':
        try:
            data = request.data
            old_type = ip.ip_type
            old_reason = ip.reason
            old_active = ip.is_active
            
            ip.ip_type = data.get('ip_type', ip.ip_type)
            ip.reason = data.get('reason', ip.reason)
            
            is_active = data.get('is_active')
            if is_active is not None:
                if isinstance(is_active, bool):
                    ip.is_active = is_active
                else:
                    ip.is_active = str(is_active).lower() in ['true', '1', 'yes', 'on']
            
            ip.save()
            
            # Build changes
            changes = []
            if old_type != ip.ip_type:
                changes.append(f"Type: {old_type} → {ip.ip_type}")
            if old_reason != ip.reason:
                changes.append(f"Reason updated")
            if old_active != ip.is_active:
                changes.append(f"Status: {'Enabled' if ip.is_active else 'Disabled'}")
            
            # Audit log
            log_audit(
                request,
                'update',
                'ip',
                ip.id,
                ip.ip_address,
                ". ".join(changes) if changes else "Updated"
            )
            
            return Response({'message': 'IP updated', 'is_active': ip.is_active})
        except Exception as e:
            traceback.print_exc()
            return Response({'error': str(e)}, status=500)
    
    elif request.method == 'DELETE':
        ip_addr = ip.ip_address
        ip_id = ip.id
        
        # Audit log
        log_audit(
            request,
            'delete',
            'ip',
            ip_id,
            ip_addr,
            f"Deleted blocked IP. Type: {ip.ip_type}"
        )
        
        ip.delete()
        return Response({'message': f'IP {ip_addr} deleted'})


@api_view(['POST'])
def ip_toggle(request, pk):
    """Toggle IP active status"""
    try:
        ip = BlockedIP.objects.get(pk=pk)
        ip.is_active = not ip.is_active
        ip.save()
        
        # Audit log
        log_audit(
            request,
            'unblock' if not ip.is_active else 'block',
            'ip',
            ip.id,
            ip.ip_address,
            f"{'Enabled' if ip.is_active else 'Disabled'} IP blocking rule"
        )
        
        return Response({
            'message': f'IP {"enabled" if ip.is_active else "disabled"}',
            'is_active': ip.is_active
        })
    except BlockedIP.DoesNotExist:
        return Response({'error': 'IP not found'}, status=404)


# ============ Port Views ============

@api_view(['GET', 'POST'])
def port_list(request):
    if request.method == 'GET':
        show_all = request.GET.get('all', 'true') == 'true'
        if show_all:
            ports = BlockedPort.objects.all().order_by('-is_active', '-created_at')
        else:
            ports = BlockedPort.objects.filter(is_active=True).order_by('-created_at')
        
        data = [{
            'id': p.id,
            'port': p.port,
            'port_end': p.port_end,
            'protocol': p.protocol,
            'port_type': p.port_type,
            'reason': p.reason,
            'is_active': p.is_active,
            'created_at': p.created_at.isoformat() if p.created_at else None,
        } for p in ports]
        return Response(data)
    
    elif request.method == 'POST':
        try:
            data = request.data
            port = data.get('port')
            port_end = data.get('port_end')
            protocol = data.get('protocol', 'both')
            port_type = data.get('port_type', 'destination')
            reason = data.get('reason', '')
            
            if not port:
                return Response({'error': 'Port is required'}, status=400)
            
            blocked = BlockedPort.objects.create(
                port=int(port),
                port_end=int(port_end) if port_end else None,
                protocol=protocol,
                port_type=port_type,
                reason=reason,
                is_active=True
            )
            
            port_str = f"{port}-{port_end}" if port_end else str(port)
            
            # Audit log
            log_audit(
                request,
                'block',
                'port',
                blocked.id,
                port_str,
                f"Added blocked port. Protocol: {protocol}. Type: {port_type}. Reason: {reason or 'None'}"
            )
            
            return Response({'id': blocked.id, 'message': f'Port {port} blocked'}, status=201)
        except Exception as e:
            traceback.print_exc()
            return Response({'error': str(e)}, status=500)


@api_view(['GET', 'PUT', 'DELETE'])
def port_detail(request, pk):
    try:
        port = BlockedPort.objects.get(pk=pk)
    except BlockedPort.DoesNotExist:
        return Response({'error': 'Port not found'}, status=404)
    
    if request.method == 'GET':
        return Response({
            'id': port.id,
            'port': port.port,
            'port_end': port.port_end,
            'protocol': port.protocol,
            'port_type': port.port_type,
            'reason': port.reason,
            'is_active': port.is_active,
        })
    
    elif request.method == 'PUT':
        try:
            data = request.data
            old_protocol = port.protocol
            old_type = port.port_type
            old_active = port.is_active
            
            port.protocol = data.get('protocol', port.protocol)
            port.port_type = data.get('port_type', port.port_type)
            port.reason = data.get('reason', port.reason)
            
            is_active = data.get('is_active')
            if is_active is not None:
                if isinstance(is_active, bool):
                    port.is_active = is_active
                else:
                    port.is_active = str(is_active).lower() in ['true', '1', 'yes', 'on']
            
            port.save()
            
            # Build changes
            changes = []
            if old_protocol != port.protocol:
                changes.append(f"Protocol: {old_protocol} → {port.protocol}")
            if old_type != port.port_type:
                changes.append(f"Type: {old_type} → {port.port_type}")
            if old_active != port.is_active:
                changes.append(f"Status: {'Enabled' if port.is_active else 'Disabled'}")
            
            port_str = f"{port.port}-{port.port_end}" if port.port_end else str(port.port)
            
            # Audit log
            log_audit(
                request,
                'update',
                'port',
                port.id,
                port_str,
                ". ".join(changes) if changes else "Updated"
            )
            
            return Response({'message': 'Port updated', 'is_active': port.is_active})
        except Exception as e:
            traceback.print_exc()
            return Response({'error': str(e)}, status=500)
    
    elif request.method == 'DELETE':
        port_num = port.port
        port_id = port.id
        port_str = f"{port.port}-{port.port_end}" if port.port_end else str(port.port)
        
        # Audit log
        log_audit(
            request,
            'delete',
            'port',
            port_id,
            port_str,
            f"Deleted blocked port. Protocol: {port.protocol}"
        )
        
        port.delete()
        return Response({'message': f'Port {port_num} deleted'})


@api_view(['POST'])
def port_toggle(request, pk):
    """Toggle port active status"""
    try:
        port = BlockedPort.objects.get(pk=pk)
        port.is_active = not port.is_active
        port.save()
        
        port_str = f"{port.port}-{port.port_end}" if port.port_end else str(port.port)
        
        # Audit log
        log_audit(
            request,
            'unblock' if not port.is_active else 'block',
            'port',
            port.id,
            port_str,
            f"{'Enabled' if port.is_active else 'Disabled'} port blocking rule"
        )
        
        return Response({
            'message': f'Port {"enabled" if port.is_active else "disabled"}',
            'is_active': port.is_active
        })
    except BlockedPort.DoesNotExist:
        return Response({'error': 'Port not found'}, status=404)


# ============ Rule Views ============

@api_view(['GET', 'POST'])
def rule_list(request):
    if request.method == 'GET':
        show_all = request.GET.get('all', 'true') == 'true'
        if show_all:
            rules = BlockRule.objects.all().order_by('-is_active', 'priority', '-created_at')
        else:
            rules = BlockRule.objects.filter(is_active=True).order_by('priority', '-created_at')
        
        data = [{
            'id': r.id,
            'name': r.name,
            'priority': r.priority,
            'action': r.action,
            'domain_pattern': r.domain_pattern,
            'source_ip': r.source_ip,
            'dest_ip': r.dest_ip,
            'source_port': r.source_port,
            'dest_port': r.dest_port,
            'reason': r.reason,
            'is_active': r.is_active,
            'created_at': r.created_at.isoformat() if r.created_at else None,
        } for r in rules]
        return Response(data)
    
    elif request.method == 'POST':
        try:
            data = request.data
            name = data.get('name', '').strip()
            
            if not name:
                return Response({'error': 'Rule name is required'}, status=400)
            
            rule = BlockRule.objects.create(
                name=name,
                priority=int(data.get('priority', 100)),
                action=data.get('action', 'block'),
                domain_pattern=data.get('domain_pattern', ''),
                source_ip=data.get('source_ip', ''),
                dest_ip=data.get('dest_ip', ''),
                source_port=data.get('source_port', ''),
                dest_port=data.get('dest_port', ''),
                reason=data.get('reason', ''),
                is_active=True
            )
            
            # Build details
            details_parts = [f"Action: {rule.action}"]
            if rule.domain_pattern:
                details_parts.append(f"Domain: {rule.domain_pattern}")
            if rule.source_ip:
                details_parts.append(f"Source IP: {rule.source_ip}")
            if rule.dest_ip:
                details_parts.append(f"Dest IP: {rule.dest_ip}")
            if rule.reason:
                details_parts.append(f"Reason: {rule.reason}")
            
            # Audit log
            log_audit(
                request,
                'create',
                'rule',
                rule.id,
                name,
                ". ".join(details_parts)
            )
            
            return Response({'id': rule.id, 'message': f'Rule "{name}" created'}, status=201)
        except Exception as e:
            traceback.print_exc()
            return Response({'error': str(e)}, status=500)


@api_view(['GET', 'PUT', 'DELETE'])
def rule_detail(request, pk):
    try:
        rule = BlockRule.objects.get(pk=pk)
    except BlockRule.DoesNotExist:
        return Response({'error': 'Rule not found'}, status=404)
    
    if request.method == 'GET':
        return Response({
            'id': rule.id,
            'name': rule.name,
            'priority': rule.priority,
            'action': rule.action,
            'domain_pattern': rule.domain_pattern,
            'source_ip': rule.source_ip,
            'dest_ip': rule.dest_ip,
            'source_port': rule.source_port,
            'dest_port': rule.dest_port,
            'reason': rule.reason,
            'is_active': rule.is_active,
        })
    
    elif request.method == 'PUT':
        try:
            data = request.data
            
            # Track changes
            changes = []
            
            old_name = rule.name
            old_priority = rule.priority
            old_action = rule.action
            old_domain = rule.domain_pattern
            old_active = rule.is_active
            
            rule.name = data.get('name', rule.name)
            rule.priority = int(data.get('priority', rule.priority))
            rule.action = data.get('action', rule.action)
            rule.domain_pattern = data.get('domain_pattern', rule.domain_pattern)
            rule.source_ip = data.get('source_ip', rule.source_ip)
            rule.dest_ip = data.get('dest_ip', rule.dest_ip)
            rule.source_port = data.get('source_port', rule.source_port)
            rule.dest_port = data.get('dest_port', rule.dest_port)
            rule.reason = data.get('reason', rule.reason)
            
            is_active = data.get('is_active')
            if is_active is not None:
                if isinstance(is_active, bool):
                    rule.is_active = is_active
                else:
                    rule.is_active = str(is_active).lower() in ['true', '1', 'yes', 'on']
            
            rule.save()
            
            # Build change log
            if old_name != rule.name:
                changes.append(f"Name: {old_name} → {rule.name}")
            if old_priority != rule.priority:
                changes.append(f"Priority: {old_priority} → {rule.priority}")
            if old_action != rule.action:
                changes.append(f"Action: {old_action} → {rule.action}")
            if old_domain != rule.domain_pattern:
                changes.append(f"Domain pattern updated")
            if old_active != rule.is_active:
                changes.append(f"Status: {'Enabled' if rule.is_active else 'Disabled'}")
            
            # Audit log
            log_audit(
                request,
                'update',
                'rule',
                rule.id,
                rule.name,
                ". ".join(changes) if changes else "Updated"
            )
            
            return Response({'message': 'Rule updated', 'is_active': rule.is_active})
        except Exception as e:
            traceback.print_exc()
            return Response({'error': str(e)}, status=500)
    
    elif request.method == 'DELETE':
        rule_name = rule.name
        rule_id = rule.id
        
        # Audit log
        log_audit(
            request,
            'delete',
            'rule',
            rule_id,
            rule_name,
            f"Deleted custom rule. Action: {rule.action}. Pattern: {rule.domain_pattern or 'None'}"
        )
        
        rule.delete()
        return Response({'message': f'Rule "{rule_name}" deleted'})


@api_view(['POST'])
def rule_toggle(request, pk):
    """Toggle rule active status"""
    try:
        rule = BlockRule.objects.get(pk=pk)
        rule.is_active = not rule.is_active
        rule.save()
        
        # Audit log
        log_audit(
            request,
            'update',
            'rule',
            rule.id,
            rule.name,
            f"{'Enabled' if rule.is_active else 'Disabled'} custom rule"
        )
        
        return Response({
            'message': f'Rule {"enabled" if rule.is_active else "disabled"}',
            'is_active': rule.is_active
        })
    except BlockRule.DoesNotExist:
        return Response({'error': 'Rule not found'}, status=404)


# ============ Quick Actions ============

@api_view(['POST'])
def quick_block_domain(request):
    try:
        domain = request.data.get('domain', '').strip().lower()
        if not domain:
            return Response({'error': 'Domain is required'}, status=400)
        
        domain = domain.replace('http://', '').replace('https://', '').split('/')[0]
        
        if BlockedDomain.objects.filter(domain=domain).exists():
            return Response({'error': 'Domain already exists'}, status=400)
        
        blocked = BlockedDomain.objects.create(
            domain=domain, 
            category='custom', 
            reason='Quick blocked from dashboard', 
            is_active=True
        )
        
        # Audit log
        log_audit(
            request,
            'block',
            'domain',
            blocked.id,
            domain,
            "Quick blocked from dashboard"
        )
        
        return Response({'message': f'Domain {domain} blocked', 'domain': domain})
    except Exception as e:
        return Response({'error': str(e)}, status=500)


@api_view(['POST'])
def quick_block_ip(request):
    try:
        ip = request.data.get('ip', '').strip()
        if not ip:
            return Response({'error': 'IP is required'}, status=400)
        
        if BlockedIP.objects.filter(ip_address=ip).exists():
            return Response({'error': 'IP already exists'}, status=400)
        
        blocked = BlockedIP.objects.create(
            ip_address=ip, 
            ip_type='both', 
            reason='Quick blocked from dashboard', 
            is_active=True
        )
        
        # Audit log
        log_audit(
            request,
            'block',
            'ip',
            blocked.id,
            ip,
            "Quick blocked from dashboard"
        )
        
        return Response({'message': f'IP {ip} blocked', 'ip': ip})
    except Exception as e:
        return Response({'error': str(e)}, status=500)
