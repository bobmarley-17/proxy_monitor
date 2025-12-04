from django.contrib import admin
from .models import BlockedDomain


@admin.register(BlockedDomain)
class BlockedDomainAdmin(admin.ModelAdmin):
    list_display = ['domain', 'category', 'is_active', 'hit_count', 'created_at']
    list_filter = ['category', 'is_active']
    search_fields = ['domain']
    list_editable = ['is_active']
    ordering = ['-created_at']
