from django.urls import path
from . import views
from . import auth_views

app_name = 'dashboard'

urlpatterns = [
    # Auth
    path('login/', auth_views.login_view, name='login'),
    path('logout/', auth_views.logout_view, name='logout'),
    
    # Dashboard pages
    path('', views.index, name='index'),
    path('analytics/', views.analytics, name='analytics'),
    path('requests/', views.requests_view, name='requests'),
    path('blocklist/', views.blocklist_view, name='blocklist'),
    
    # API endpoints
    path('api/traffic-stats/', views.api_traffic_stats, name='api_traffic_stats'),
    path('api/recent-requests/', views.api_recent_requests, name='api_recent_requests'),
    path('api/domain-stats/', views.api_domain_stats, name='api_domain_stats'),
    path('api/ip-stats/', views.api_ip_stats, name='api_ip_stats'),
    path('api/alerts/', views.api_alerts, name='api_alerts'),
    path('api/resolve/', views.api_resolve_ip, name='api_resolve_ip'),
    path('api/dns-cache/', views.api_dns_cache, name='api_dns_cache'),
]
