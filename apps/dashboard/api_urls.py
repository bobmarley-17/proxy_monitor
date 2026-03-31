# apps/dashboard/api_urls.py

from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import api_views

router = DefaultRouter()
router.register(r'users', api_views.UserViewSet, basename='api-user')
router.register(r'requests', api_views.ProxyRequestViewSet, basename='api-request')
router.register(r'domains', api_views.DomainStatsViewSet, basename='api-domain')
router.register(r'audit-logs', api_views.AuditLogViewSet, basename='api-audit')

urlpatterns = [
    # Auth
    path('auth/login/', api_views.LoginView.as_view(), name='api-login'),
    path('auth/logout/', api_views.LogoutView.as_view(), name='api-logout'),
    path('auth/profile/', api_views.ProfileView.as_view(), name='api-profile'),
    path('auth/change-password/', api_views.ChangePasswordView.as_view(), name='api-change-password'),

    # Dashboard & Analytics
    path('dashboard/stats/', api_views.DashboardStatsView.as_view(), name='api-dashboard-stats'),
    path('analytics/', api_views.AnalyticsView.as_view(), name='api-analytics'),

    # ViewSet routes
    path('', include(router.urls)),
]