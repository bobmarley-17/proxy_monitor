from django.contrib import admin
from django.utils.html import mark_safe
from .models import BlockedDomain, BlockedIP, BlockedPort, BlockRule


@admin.register(BlockedDomain)
class BlockedDomainAdmin(admin.ModelAdmin):
    list_display = ['domain', 'category', 'is_wildcard', 'is_active', 'hit_count', 'created_at']
    list_filter = ['category', 'is_active', 'is_wildcard']
    search_fields = ['domain', 'reason']
    list_editable = ['is_active']


@admin.register(BlockedIP)
class BlockedIPAdmin(admin.ModelAdmin):
    list_display = ['ip_display', 'ip_type', 'is_range', 'is_active', 'hit_count', 'created_at']
    list_filter = ['ip_type', 'is_active', 'is_range']
    search_fields = ['ip_address', 'reason']
    list_editable = ['is_active']
    
    def ip_display(self, obj):
        if obj.is_range and obj.cidr_prefix:
            return f"{obj.ip_address}/{obj.cidr_prefix}"
        return obj.ip_address
    ip_display.short_description = 'IP Address'


@admin.register(BlockedPort)
class BlockedPortAdmin(admin.ModelAdmin):
    list_display = ['port_display', 'port_type', 'protocol', 'is_active', 'hit_count', 'created_at']
    list_filter = ['port_type', 'protocol', 'is_active']
    search_fields = ['port', 'reason']
    list_editable = ['is_active']
    
    def port_display(self, obj):
        if obj.port_end:
            return f"{obj.port}-{obj.port_end}"
        return str(obj.port)
    port_display.short_description = 'Port'


@admin.register(BlockRule)
class BlockRuleAdmin(admin.ModelAdmin):
    list_display = ['priority_badge', 'name', 'conditions', 'action_badge', 'is_active', 'hit_count']
    list_filter = ['action', 'is_active']
    search_fields = ['name', 'domain_pattern', 'source_ip', 'dest_ip']
    list_editable = ['is_active']
    ordering = ['priority']
    
    def priority_badge(self, obj):
        if obj.priority <= 10:
            color = '#22c55e'
        elif obj.priority <= 50:
            color = '#eab308'
        else:
            color = '#64748b'
        return mark_safe(f'<span style="background:{color}; color:white; padding:3px 10px; border-radius:10px;">{obj.priority}</span>')
    priority_badge.short_description = 'Priority'
    
    def conditions(self, obj):
        parts = []
        if obj.domain_pattern:
            parts.append(f"Domain: {obj.domain_pattern}")
        if obj.source_ip:
            cidr = f"/{obj.source_ip_cidr}" if obj.source_ip_cidr else ""
            parts.append(f"SrcIP: {obj.source_ip}{cidr}")
        if obj.dest_ip:
            cidr = f"/{obj.dest_ip_cidr}" if obj.dest_ip_cidr else ""
            parts.append(f"DstIP: {obj.dest_ip}{cidr}")
        if obj.source_port_start:
            port = f"{obj.source_port_start}"
            if obj.source_port_end:
                port += f"-{obj.source_port_end}"
            parts.append(f"SrcPort: {port}")
        if obj.dest_port_start:
            port = f"{obj.dest_port_start}"
            if obj.dest_port_end:
                port += f"-{obj.dest_port_end}"
            parts.append(f"DstPort: {port}")
        return " | ".join(parts) if parts else "No conditions"
    conditions.short_description = 'Conditions'
    
    def action_badge(self, obj):
        colors = {'block': '#ef4444', 'allow': '#22c55e', 'log': '#3b82f6'}
        icons = {'block': '🚫', 'allow': '✅', 'log': '📝'}
        return mark_safe(f'<span style="background:{colors.get(obj.action, "#64748b")}; color:white; padding:3px 12px; border-radius:10px;">{icons.get(obj.action, "")} {obj.action.upper()}</span>')
    action_badge.short_description = 'Action'
