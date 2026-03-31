# apps/blocklist/api_serializers.py

from rest_framework import serializers
from .models import BlockedDomain, BlockedIP, BlockedPort, BlockRule


# ━━━ BLOCKED DOMAINS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class BlockedDomainSerializer(serializers.ModelSerializer):
    class Meta:
        model = BlockedDomain
        fields = [
            'id', 'domain', 'category', 'reason',
            'is_active', 'is_wildcard', 'hit_count',
            'created_at', 'updated_at',
        ]
        read_only_fields = ['id', 'is_wildcard', 'hit_count', 'created_at', 'updated_at']


class BlockedDomainListSerializer(serializers.ModelSerializer):
    class Meta:
        model = BlockedDomain
        fields = ['id', 'domain', 'category', 'is_active', 'is_wildcard', 'hit_count']


class BulkDomainImportSerializer(serializers.Serializer):
    domains = serializers.ListField(
        child=serializers.CharField(max_length=255),
        min_length=1,
        max_length=10000,
    )
    category = serializers.ChoiceField(
        choices=BlockedDomain.CATEGORY_CHOICES,
        default='manual',
    )
    reason = serializers.CharField(required=False, default='Bulk import via API')


# ━━━ BLOCKED IPs ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class BlockedIPSerializer(serializers.ModelSerializer):
    display = serializers.SerializerMethodField()

    class Meta:
        model = BlockedIP
        fields = [
            'id', 'ip_address', 'ip_type', 'is_range', 'cidr_prefix',
            'reason', 'is_active', 'hit_count',
            'created_at', 'updated_at', 'display',
        ]
        read_only_fields = ['id', 'is_range', 'hit_count', 'created_at', 'updated_at', 'display']

    def get_display(self, obj):
        if obj.is_range and obj.cidr_prefix:
            return '{}/{}'.format(obj.ip_address, obj.cidr_prefix)
        return obj.ip_address


# ━━━ BLOCKED PORTS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class BlockedPortSerializer(serializers.ModelSerializer):
    display = serializers.SerializerMethodField()

    class Meta:
        model = BlockedPort
        fields = [
            'id', 'port', 'port_end', 'port_type', 'protocol',
            'reason', 'is_active', 'hit_count',
            'created_at', 'updated_at', 'display',
        ]
        read_only_fields = ['id', 'hit_count', 'created_at', 'updated_at', 'display']

    def get_display(self, obj):
        if obj.port_end:
            return '{}-{}'.format(obj.port, obj.port_end)
        return str(obj.port)

    def validate(self, data):
        port = data.get('port', 0)
        port_end = data.get('port_end')
        if port < 1 or port > 65535:
            raise serializers.ValidationError({'port': 'Port must be 1-65535.'})
        if port_end is not None:
            if port_end < 1 or port_end > 65535:
                raise serializers.ValidationError({'port_end': 'Port must be 1-65535.'})
            if port_end <= port:
                raise serializers.ValidationError({'port_end': 'Must be greater than port.'})
        return data


# ━━━ BLOCK RULES ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class BlockRuleSerializer(serializers.ModelSerializer):
    class Meta:
        model = BlockRule
        fields = [
            'id', 'name', 'domain_pattern',
            'source_ip', 'source_ip_cidr',
            'dest_ip', 'dest_ip_cidr',
            'source_port_start', 'source_port_end',
            'dest_port_start', 'dest_port_end',
            'priority', 'action', 'reason',
            'is_active', 'hit_count',
            'created_at', 'updated_at',
        ]
        read_only_fields = ['id', 'hit_count', 'created_at', 'updated_at']


class BlockRuleListSerializer(serializers.ModelSerializer):
    class Meta:
        model = BlockRule
        fields = [
            'id', 'name', 'priority', 'action',
            'is_active', 'hit_count', 'domain_pattern',
        ]


class RuleTestSerializer(serializers.Serializer):
    hostname = serializers.CharField(required=False, allow_blank=True, default='')
    source_ip = serializers.CharField(required=False, allow_blank=True, default='')
    dest_ip = serializers.CharField(required=False, allow_blank=True, default='')
    source_port = serializers.IntegerField(required=False, allow_null=True, default=None)
    dest_port = serializers.IntegerField(required=False, allow_null=True, default=None)