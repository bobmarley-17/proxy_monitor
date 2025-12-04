from rest_framework import serializers
from .models import BlockedDomain, BlockedIP, BlockedPort, BlockRule


class BlockedDomainSerializer(serializers.ModelSerializer):
    class Meta:
        model = BlockedDomain
        fields = '__all__'
        read_only_fields = ['hit_count', 'is_wildcard', 'created_at', 'updated_at']


class BlockedIPSerializer(serializers.ModelSerializer):
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
    class Meta:
        model = BlockRule
        fields = '__all__'
        read_only_fields = ['hit_count', 'created_at', 'updated_at']
