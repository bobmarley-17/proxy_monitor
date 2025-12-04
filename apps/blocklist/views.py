from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from .models import BlockedDomain
from .serializers import BlockedDomainSerializer


class BlockedDomainViewSet(viewsets.ModelViewSet):
    queryset = BlockedDomain.objects.all().order_by('-hit_count', '-created_at')
    serializer_class = BlockedDomainSerializer
    
    def partial_update(self, request, *args, **kwargs):
        """Handle PATCH request for editing - domain cannot be changed"""
        instance = self.get_object()
        
        # Update allowed fields only
        instance.category = request.data.get('category', instance.category)
        instance.reason = request.data.get('reason', instance.reason)
        instance.is_active = request.data.get('is_active', instance.is_active)
        instance.save()
        
        serializer = self.get_serializer(instance)
        return Response(serializer.data)
    
    def update(self, request, *args, **kwargs):
        """Handle PUT request - redirect to partial_update"""
        return self.partial_update(request, *args, **kwargs)
    
    @action(detail=True, methods=['post'])
    def toggle(self, request, pk=None):
        """Toggle active status"""
        domain = self.get_object()
        domain.is_active = not domain.is_active
        domain.save()
        return Response({
            'id': domain.id,
            'domain': domain.domain,
            'is_active': domain.is_active
        })
    
    @action(detail=True, methods=['post'])
    def reset_hits(self, request, pk=None):
        """Reset hit counter"""
        domain = self.get_object()
        domain.hit_count = 0
        domain.save()
        return Response({'id': domain.id, 'hit_count': 0})
    
    @action(detail=False, methods=['post'])
    def bulk_add(self, request):
        """Add multiple domains at once"""
        domains = request.data.get('domains', [])
        category = request.data.get('category', 'manual')
        created = 0
        
        for domain in domains:
            domain = domain.strip().lower()
            if domain:
                _, is_new = BlockedDomain.objects.get_or_create(
                    domain=domain,
                    defaults={'category': category, 'is_active': True}
                )
                if is_new:
                    created += 1
        
        return Response({'created': created, 'total': len(domains)})
    
    @action(detail=False, methods=['delete'])
    def clear_all(self, request):
        """Delete all blocked domains"""
        count = BlockedDomain.objects.count()
        BlockedDomain.objects.all().delete()
        return Response({'deleted': count})
