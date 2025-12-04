from rest_framework import serializers
from .models import BlockedDomain, BlockedIP, BlockedPort, BlockRule


class BlockedDomainSerializer(serializers.ModelSerializer):
    class Meta:
        model = BlockedDomain
        fields = '__all__'
        read_only_fields = ['is_wildcard', 'hit_count', 'created_at', 'updated_at']


class BlockedIPSerializer(serializers.ModelSerializer):
    display_name = serializers.SerializerMethodField()

    class Meta:
        model = BlockedIP
        fields = '__all__'
        read_only_fields = ['is_range', 'hit_count', 'created_at', 'updated_at']

    def get_display_name(self, obj):
        if obj.is_range and obj.cidr_prefix:
            return f"{obj.ip_address}/{obj.cidr_prefix}"
        return obj.ip_address


class BlockedPortSerializer(serializers.ModelSerializer):
    display_name = serializers.SerializerMethodField()

    class Meta:
        model = BlockedPort
        fields = '__all__'
        read_only_fields = ['hit_count', 'created_at', 'updated_at']

    def get_display_name(self, obj):
        if obj.port_end:
            return f"{obj.port}-{obj.port_end}"
        return str(obj.port)


class BlockRuleSerializer(serializers.ModelSerializer):
    class Meta:
        model = BlockRule
        fields = '__all__'
        read_only_fields = ['hit_count', 'created_at', 'updated_at']
