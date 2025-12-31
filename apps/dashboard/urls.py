from django.urls import path
from . import views

app_name = 'dashboard'

urlpatterns = [
    # Auth
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    
    # Main pages (All users)
    path('', views.index, name='index'),
    path('requests/', views.requests_view, name='requests'),
    path('analytics/', views.analytics_view, name='analytics'),
    path('settings/', views.settings_view, name='settings'),
    
    # Blocklist (Operator & Admin)
    path('blocklist/', views.blocklist_view, name='blocklist'),
    
    # User Management (Admin only)
    path('users/', views.users_view, name='users'),
    path('users/create/', views.user_create, name='user_create'),
    path('users/<int:user_id>/edit/', views.user_edit, name='user_edit'),
    path('users/<int:user_id>/delete/', views.user_delete, name='user_delete'),
    
    # Audit Logs (Admin only)
    path('audit-logs/', views.audit_logs_view, name='audit_logs'),
    
    # API
    path('api/stats/', views.api_stats, name='api_stats'),
    path('api/requests/', views.api_requests, name='api_requests'),
    path('api/resolve/', views.api_resolve, name='api_resolve'),
    path('api/dns-cache/', views.api_dns_cache, name='api_dns_cache'),
]
