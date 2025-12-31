from rest_framework import serializers
from .models import ProxyRequest, DomainStats, AuditLog


class ProxyRequestSerializer(serializers.ModelSerializer):
    class Meta:
        model = ProxyRequest
        fields = [
            'id', 'timestamp', 'method', 'url', 'hostname',
            'status_code', 'blocked', 'block_reason', 'block_type',
            'response_time', 'content_length',
            'source_ip', 'source_port', 'destination_ip', 'destination_port'
        ]


class ProxyRequestListSerializer(serializers.ModelSerializer):
    """Lighter serializer for list views"""
    class Meta:
        model = ProxyRequest
        fields = [
            'id', 'timestamp', 'method', 'hostname',
            'status_code', 'blocked', 'response_time', 'source_ip'
        ]


class DomainStatsSerializer(serializers.ModelSerializer):
    class Meta:
        model = DomainStats
        fields = [
            'hostname', 'request_count', 'blocked_count',
            'total_bytes', 'first_seen', 'last_seen'
        ]


class AuditLogSerializer(serializers.ModelSerializer):
    username = serializers.CharField(source='user.username', read_only=True)
    
    class Meta:
        model = AuditLog
        fields = [
            'id', 'username', 'action', 'target_type',
            'target_id', 'target_name', 'details', 'ip_address', 'timestamp'
        ]
