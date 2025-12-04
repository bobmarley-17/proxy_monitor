from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

app_name = 'blocklist'

router = DefaultRouter()
router.register(r'domains', views.BlockedDomainViewSet, basename='domains')
router.register(r'ips', views.BlockedIPViewSet, basename='ips')
router.register(r'ports', views.BlockedPortViewSet, basename='ports')
router.register(r'rules', views.BlockRuleViewSet, basename='rules')

urlpatterns = [
    path('', include(router.urls)),
    path('check/', views.check_blocked, name='check_blocked'),
]
