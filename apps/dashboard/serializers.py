from rest_framework import serializers
from .models import ProxyRequest, DomainStats, AuditLog


class ProxyRequestSerializer(serializers.ModelSerializer):
    # Override to avoid DRF IPAddressField bug with Django 5.2
    source_ip = serializers.CharField(max_length=45)
    destination_ip = serializers.CharField(max_length=45)

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
    source_ip = serializers.CharField(max_length=45)

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
    username = serializers.CharField(source='user.username', read_only=True, default='System')
    ip_address = serializers.CharField(max_length=45, required=False, allow_null=True)

    class Meta:
        model = AuditLog
        fields = [
            'id', 'username', 'action', 'target_type',
            'target_id', 'target_name', 'details', 'ip_address', 'timestamp'
        ]