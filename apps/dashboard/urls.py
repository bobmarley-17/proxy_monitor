from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

router = DefaultRouter()
router.register(r'requests', views.ProxyRequestViewSet, basename='proxy-requests')
router.register(r'domains', views.DomainStatsViewSet, basename='domain-stats')
router.register(r'alerts', views.AlertViewSet, basename='alerts')

urlpatterns = [
    # Pages
    path('', views.dashboard_view, name='dashboard'),
    path('requests/', views.requests_view, name='requests'),
    path('analytics/', views.analytics_view, name='analytics'),
    path('blocklist/', views.blocklist_view, name='blocklist'),
    path('settings/', views.settings_view, name='settings'),
    
    # API
    path('api/', include(router.urls)),
    path('api/analytics/', views.AnalyticsAPIView.as_view(), name='analytics-api'),
    path('api/stats/', views.StatsAPIView.as_view(), name='stats-api'),
]
