# apps/blocklist/api_urls.py

from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import api_views

router = DefaultRouter()
router.register(r'domains', api_views.BlockedDomainViewSet, basename='api-blocked-domain')
router.register(r'ips', api_views.BlockedIPViewSet, basename='api-blocked-ip')
router.register(r'ports', api_views.BlockedPortViewSet, basename='api-blocked-port')
router.register(r'rules', api_views.BlockRuleViewSet, basename='api-block-rule')

urlpatterns = [
    path('stats/', api_views.BlocklistStatsView.as_view(), name='api-blocklist-stats'),
    path('check/', api_views.FullCheckView.as_view(), name='api-blocklist-check'),
    path('', include(router.urls)),
]