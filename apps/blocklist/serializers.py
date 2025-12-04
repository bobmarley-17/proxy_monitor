from rest_framework import serializers
from .models import BlockedDomain


class BlockedDomainSerializer(serializers.ModelSerializer):
    class Meta:
        model = BlockedDomain
        fields = '__all__'
