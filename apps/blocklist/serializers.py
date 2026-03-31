from rest_framework import serializers
from .models import BlockedDomain, BlockedIP, BlockedPort, BlockRule


class BlockedDomainSerializer(serializers.ModelSerializer):
    class Meta:
        model = BlockedDomain
        fields = '__all__'
        read_only_fields = ['hit_count', 'is_wildcard', 'created_at', 'updated_at']


class BlockedIPSerializer(serializers.ModelSerializer):
    # Override to avoid DRF IPAddressField bug with Django 5.2
    ip_address = serializers.CharField(max_length=45)

    class Meta:
        model = BlockedIP
        fields = '__all__'
        read_only_fields = ['hit_count', 'is_range', 'created_at', 'updated_at']


class BlockedPortSerializer(serializers.ModelSerializer):
    class Meta:
        model = BlockedPort
        fields = '__all__'
        read_only_fields = ['hit_count', 'created_at', 'updated_at']


class BlockRuleSerializer(serializers.ModelSerializer):
    # Override to avoid DRF IPAddressField bug with Django 5.2
    source_ip = serializers.CharField(max_length=45, required=False, allow_blank=True, allow_null=True)
    dest_ip = serializers.CharField(max_length=45, required=False, allow_blank=True, allow_null=True)

    class Meta:
        model = BlockRule
        fields = '__all__'
        read_only_fields = ['hit_count', 'created_at', 'updated_at']