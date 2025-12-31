from django.urls import path
from . import views

app_name = 'blocklist'

urlpatterns = [
    # Domain endpoints
    path('domains/', views.domain_list, name='domain_list'),
    path('domains/<int:pk>/', views.domain_detail, name='domain_detail'),
    path('domains/<int:pk>/toggle/', views.domain_toggle, name='domain_toggle'),
    
    # IP endpoints
    path('ips/', views.ip_list, name='ip_list'),
    path('ips/<int:pk>/', views.ip_detail, name='ip_detail'),
    path('ips/<int:pk>/toggle/', views.ip_toggle, name='ip_toggle'),
    
    # Port endpoints
    path('ports/', views.port_list, name='port_list'),
    path('ports/<int:pk>/', views.port_detail, name='port_detail'),
    path('ports/<int:pk>/toggle/', views.port_toggle, name='port_toggle'),
    
    # Rule endpoints
    path('rules/', views.rule_list, name='rule_list'),
    path('rules/<int:pk>/', views.rule_detail, name='rule_detail'),
    path('rules/<int:pk>/toggle/', views.rule_toggle, name='rule_toggle'),
    
    # Quick actions
    path('quick/domain/', views.quick_block_domain, name='quick_block_domain'),
    path('quick/ip/', views.quick_block_ip, name='quick_block_ip'),
]
