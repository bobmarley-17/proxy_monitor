from django.contrib import admin
from .models import BlockedDomain, BlockedIP, BlockedPort, BlockRule


@admin.register(BlockedDomain)
class BlockedDomainAdmin(admin.ModelAdmin):
    list_display = ['domain', 'category', 'is_wildcard', 'is_active', 'hit_count', 'created_at']
    list_filter = ['category', 'is_active', 'is_wildcard']
    search_fields = ['domain', 'reason']
    list_editable = ['is_active']
    ordering = ['-created_at']


@admin.register(BlockedIP)
class BlockedIPAdmin(admin.ModelAdmin):
    list_display = ['ip_address', 'ip_type', 'is_range', 'cidr_prefix', 'is_active', 'hit_count', 'created_at']
    list_filter = ['ip_type', 'is_active', 'is_range']
    search_fields = ['ip_address', 'reason']
    list_editable = ['is_active']


@admin.register(BlockedPort)
class BlockedPortAdmin(admin.ModelAdmin):
    list_display = ['port', 'port_end', 'port_type', 'protocol', 'is_active', 'hit_count', 'created_at']
    list_filter = ['port_type', 'protocol', 'is_active']
    search_fields = ['reason']
    list_editable = ['is_active']


@admin.register(BlockRule)
class BlockRuleAdmin(admin.ModelAdmin):
    list_display = ['name', 'rule_type', 'action', 'priority', 'is_active', 'hit_count', 'created_at']
    list_filter = ['rule_type', 'action', 'is_active']
    search_fields = ['name', 'domain_pattern', 'reason']
    list_editable = ['is_active', 'priority']
    ordering = ['priority']
