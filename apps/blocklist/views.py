from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from .models import BlockedDomain
from .serializers import BlockedDomainSerializer


class BlockedDomainViewSet(viewsets.ModelViewSet):
    queryset = BlockedDomain.objects.all().order_by('-created_at')
    serializer_class = BlockedDomainSerializer
    
    @action(detail=True, methods=['post'])
    def toggle(self, request, pk=None):
        domain = self.get_object()
        domain.is_active = not domain.is_active
        domain.save()
        return Response({'is_active': domain.is_active})
    
    @action(detail=False, methods=['post'])
    def bulk_add(self, request):
        domains = request.data.get('domains', [])
        category = request.data.get('category', 'manual')
        created = 0
        for domain in domains:
            _, is_new = BlockedDomain.objects.get_or_create(
                domain=domain.strip().lower(),
                defaults={'category': category, 'is_active': True}
            )
            if is_new:
                created += 1
        return Response({'created': created})
