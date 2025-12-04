from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

router = DefaultRouter()
router.register(r'domains', views.BlockedDomainViewSet, basename='blocked-domains')
router.register(r'ips', views.BlockedIPViewSet, basename='blocked-ips')
router.register(r'ports', views.BlockedPortViewSet, basename='blocked-ports')
router.register(r'rules', views.BlockRuleViewSet, basename='block-rules')

urlpatterns = [
    path('', include(router.urls)),
    path('check/', views.check_blocked, name='check-blocked'),
]
