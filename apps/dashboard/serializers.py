from rest_framework import serializers
from .models import ProxyRequest, DomainStats, TrafficStats, Alert


class ProxyRequestListSerializer(serializers.ModelSerializer):
    class Meta:
        model = ProxyRequest
        fields = [
            'id', 'timestamp', 'method', 'hostname', 'status_code',
            'response_time', 'blocked', 'content_length',
            'source_ip', 'source_port', 'destination_ip', 'destination_port',
        ]


class ProxyRequestSerializer(serializers.ModelSerializer):
    class Meta:
        model = ProxyRequest
        fields = '__all__'


class DomainStatsSerializer(serializers.ModelSerializer):
    class Meta:
        model = DomainStats
        fields = '__all__'


class TrafficStatsSerializer(serializers.ModelSerializer):
    class Meta:
        model = TrafficStats
        fields = '__all__'


class AlertSerializer(serializers.ModelSerializer):
    class Meta:
        model = Alert
        fields = '__all__'
