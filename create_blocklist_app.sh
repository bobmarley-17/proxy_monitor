##############################
# apps/blocklist/models.py
##############################
cat > apps/blocklist/models.py << 'EOF'
from django.db import models

class BlockedDomain(models.Model):
    domain = models.CharField(max_length=255, unique=True, db_index=True)
    reason = models.TextField(blank=True)
    category = models.CharField(max_length=100, blank=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    hit_count = models.BigIntegerField(default=0)
    
    class Meta:
        db_table = 'blocked_domains'
        ordering = ['-created_at']

class BlockCategory(models.Model):
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True)
    domains = models.JSONField(default=list)
    
    class Meta:
        db_table = 'block_categories'
EOF

##############################
# apps/blocklist/serializers.py
##############################
cat > apps/blocklist/serializers.py << 'EOF'
from rest_framework import serializers
from .models import BlockedDomain, BlockCategory

class BlockedDomainSerializer(serializers.ModelSerializer):
    class Meta:
        model = BlockedDomain
        fields = '__all__'
        read_only_fields = ['hit_count', 'created_at']

class BlockCategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = BlockCategory
        fields = '__all__'
EOF

##############################
# apps/blocklist/views.py
##############################
cat > apps/blocklist/views.py << 'EOF'
from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.response import Response
from .models import BlockedDomain, BlockCategory
from .serializers import BlockedDomainSerializer, BlockCategorySerializer

class BlockedDomainViewSet(viewsets.ModelViewSet):
    queryset = BlockedDomain.objects.all()
    serializer_class = BlockedDomainSerializer
    lookup_field = 'domain'
    
    @action(detail=False, methods=['post'])
    def bulk_add(self, request):
        domains = request.data.get('domains', [])
        created = []
        for d in domains:
            obj, new = BlockedDomain.objects.get_or_create(domain=d)
            if new: created.append(d)
        return Response({'created': created, 'count': len(created)})

class BlockCategoryViewSet(viewsets.ModelViewSet):
    queryset = BlockCategory.objects.all()
    serializer_class = BlockCategorySerializer
    
    @action(detail=True, methods=['post'])
    def apply(self, request, pk=None):
        cat = self.get_object()
        created = []
        for d in cat.domains:
            obj, new = BlockedDomain.objects.get_or_create(domain=d, defaults={'category': cat.name})
            if new: created.append(d)
        return Response({'created': created})
EOF

##############################
# apps/blocklist/urls.py
##############################
cat > apps/blocklist/urls.py << 'EOF'
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import BlockedDomainViewSet, BlockCategoryViewSet

router = DefaultRouter()
router.register(r'domains', BlockedDomainViewSet)
router.register(r'categories', BlockCategoryViewSet)

urlpatterns = [path('', include(router.urls))]
EOF

##############################
# apps/blocklist/admin.py
##############################
cat > apps/blocklist/admin.py << 'EOF'
from django.contrib import admin
from .models import BlockedDomain, BlockCategory

@admin.register(BlockedDomain)
class BlockedDomainAdmin(admin.ModelAdmin):
    list_display = ['domain', 'category', 'is_active', 'hit_count', 'created_at']
    list_filter = ['is_active', 'category']
    search_fields = ['domain']
    list_editable = ['is_active']

@admin.register(BlockCategory)
class BlockCategoryAdmin(admin.ModelAdmin):
    list_display = ['name', 'description']
EOF

echo "✅ Blocklist app created!"
