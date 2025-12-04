from django.contrib import admin
from django.utils.html import format_html
from .models import ProxyRequest, DomainStats

@admin.register(ProxyRequest)
class ProxyRequestAdmin(admin.ModelAdmin):
    list_display = ['timestamp', 'method', 'hostname', 'status_code', 'blocked', 'response_time']
    list_filter = ['method', 'blocked', 'timestamp']
    search_fields = ['hostname', 'url']

@admin.register(DomainStats)
class DomainStatsAdmin(admin.ModelAdmin):
    list_display = ['hostname', 'request_count', 'blocked_count', 'last_accessed']
    search_fields = ['hostname']
