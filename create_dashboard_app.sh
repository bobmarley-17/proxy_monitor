##############################
# apps/dashboard/models.py
##############################
cat > apps/dashboard/models.py << 'EOF'
from django.db import models
import uuid

class ProxyRequest(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)
    method = models.CharField(max_length=10)
    url = models.TextField()
    hostname = models.CharField(max_length=255, db_index=True)
    path = models.TextField(default='/')
    status_code = models.IntegerField(null=True, blank=True)
    content_type = models.CharField(max_length=255, null=True, blank=True)
    content_length = models.BigIntegerField(default=0)
    response_time = models.IntegerField(default=0)
    blocked = models.BooleanField(default=False, db_index=True)
    source_ip = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(null=True, blank=True)
    
    class Meta:
        db_table = 'proxy_requests'
        ordering = ['-timestamp']

class DomainStats(models.Model):
    hostname = models.CharField(max_length=255, unique=True, db_index=True)
    request_count = models.BigIntegerField(default=0)
    blocked_count = models.BigIntegerField(default=0)
    total_bytes = models.BigIntegerField(default=0)
    avg_response_time = models.FloatField(default=0)
    last_accessed = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'domain_stats'
        ordering = ['-request_count']
EOF

##############################
# apps/dashboard/serializers.py
##############################
cat > apps/dashboard/serializers.py << 'EOF'
from rest_framework import serializers
from .models import ProxyRequest, DomainStats

class ProxyRequestSerializer(serializers.ModelSerializer):
    class Meta:
        model = ProxyRequest
        fields = '__all__'

class ProxyRequestListSerializer(serializers.ModelSerializer):
    class Meta:
        model = ProxyRequest
        fields = ['id', 'timestamp', 'method', 'hostname', 'path', 'status_code', 'response_time', 'content_length', 'blocked']

class DomainStatsSerializer(serializers.ModelSerializer):
    class Meta:
        model = DomainStats
        fields = '__all__'
EOF

##############################
# apps/dashboard/views.py
##############################
cat > apps/dashboard/views.py << 'EOF'
from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.views import APIView
from django.db.models import Count, Sum, Avg, Q
from django.db.models.functions import TruncHour
from django.utils import timezone
from datetime import timedelta
from .models import ProxyRequest, DomainStats
from .serializers import ProxyRequestSerializer, ProxyRequestListSerializer, DomainStatsSerializer
from apps.blocklist.models import BlockedDomain

class ProxyRequestViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = ProxyRequest.objects.all()
    serializer_class = ProxyRequestListSerializer
    
    def get_queryset(self):
        qs = super().get_queryset()
        if h := self.request.query_params.get('hostname'):
            qs = qs.filter(hostname__icontains=h)
        if m := self.request.query_params.get('method'):
            qs = qs.filter(method=m.upper())
        if b := self.request.query_params.get('blocked'):
            qs = qs.filter(blocked=b.lower()=='true')
        return qs
    
    def get_serializer_class(self):
        return ProxyRequestSerializer if self.action == 'retrieve' else ProxyRequestListSerializer
    
    @action(detail=False, methods=['delete'])
    def clear_all(self, request):
        c = ProxyRequest.objects.count()
        ProxyRequest.objects.all().delete()
        DomainStats.objects.all().delete()
        return Response({'message': f'Cleared {c} requests'})

class DomainStatsViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = DomainStats.objects.all()
    serializer_class = DomainStatsSerializer

class OverviewStatsView(APIView):
    def get(self, request):
        return Response({
            'total_requests': ProxyRequest.objects.count(),
            'blocked_requests': ProxyRequest.objects.filter(blocked=True).count(),
            'unique_domains': DomainStats.objects.count(),
            'blocked_domains': BlockedDomain.objects.filter(is_active=True).count(),
            'top_domains': list(DomainStats.objects.order_by('-request_count')[:10].values('hostname', 'request_count')),
        })
EOF

##############################
# apps/dashboard/urls.py
##############################
cat > apps/dashboard/urls.py << 'EOF'
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import ProxyRequestViewSet, DomainStatsViewSet, OverviewStatsView

router = DefaultRouter()
router.register(r'requests', ProxyRequestViewSet)
router.register(r'domains', DomainStatsViewSet)

urlpatterns = [
    path('', include(router.urls)),
    path('stats/overview/', OverviewStatsView.as_view()),
]
EOF

##############################
# apps/dashboard/admin.py
##############################
cat > apps/dashboard/admin.py << 'EOF'
from django.contrib import admin
from django.utils.html import format_html
from .models import ProxyRequest, DomainStats

@admin.register(ProxyRequest)
class ProxyRequestAdmin(admin.ModelAdmin):
    list_display = ['timestamp', 'method', 'hostname', 'status_code', 'blocked', 'response_time']
    list_filter = ['method', 'blocked', 'timestamp']
    search_fields = ['hostname', 'url']

@admin.register(DomainStats)
class DomainStatsAdmin(admin.ModelAdmin):
    list_display = ['hostname', 'request_count', 'blocked_count', 'last_accessed']
    search_fields = ['hostname']
EOF

##############################
# apps/dashboard/consumers.py
##############################
cat > apps/dashboard/consumers.py << 'EOF'
import json
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from .models import ProxyRequest, DomainStats
from .serializers import ProxyRequestListSerializer, DomainStatsSerializer

class DashboardConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        await self.channel_layer.group_add('dashboard', self.channel_name)
        await self.accept()
        await self.send_initial_data()
    
    async def disconnect(self, code):
        await self.channel_layer.group_discard('dashboard', self.channel_name)
    
    @database_sync_to_async
    def get_data(self):
        return {
            'requests': ProxyRequestListSerializer(ProxyRequest.objects.all()[:50], many=True).data,
            'stats': DomainStatsSerializer(DomainStats.objects.all()[:20], many=True).data
        }
    
    async def send_initial_data(self):
        data = await self.get_data()
        await self.send(text_data=json.dumps({'type': 'initial_data', **data}))
    
    async def new_request(self, event):
        await self.send(text_data=json.dumps({'type': 'new_request', 'data': event['request']}))
    
    async def stats_update(self, event):
        await self.send(text_data=json.dumps({'type': 'stats_update', 'data': event['stats']}))
EOF

##############################
# apps/dashboard/routing.py
##############################
cat > apps/dashboard/routing.py << 'EOF'
from django.urls import path
from . import consumers

websocket_urlpatterns = [
    path('ws/dashboard/', consumers.DashboardConsumer.as_asgi()),
]
EOF

echo "✅ Dashboard app created!"
