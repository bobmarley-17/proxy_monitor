import uuid
from django.db import models
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver


class UserProfile(models.Model):
    """User profile with role-based access control"""
    ROLE_CHOICES = [
        ('viewer', 'Viewer'),
        ('operator', 'Operator'),
        ('admin', 'Administrator'),
    ]

    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='viewer')
    department = models.CharField(max_length=100, blank=True, null=True)
    phone = models.CharField(max_length=20, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.user.username} - {self.get_role_display()}"

    @property
    def is_admin(self):
        return self.role == 'admin' or self.user.is_superuser

    @property
    def is_operator(self):
        return self.role in ['operator', 'admin'] or self.user.is_superuser

    @property
    def is_viewer(self):
        return True

    def can_manage_users(self):
        return self.is_admin

    def can_manage_blocklist(self):
        return self.is_operator

    def can_view_logs(self):
        return True

    def can_delete_logs(self):
        return self.is_admin


class ProxyRequest(models.Model):
    """Stores all proxy request logs"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)
    
    method = models.CharField(max_length=10, default='GET')

    url = models.TextField(blank=True, default='')
    hostname = models.CharField(max_length=255, db_index=True)
    status_code = models.IntegerField(default=0)
    
    source_ip = models.GenericIPAddressField(db_index=True)
    source_port = models.IntegerField(default=0)
    destination_ip = models.CharField(max_length=45, default='0.0.0.0')
    destination_port = models.IntegerField(default=0)
    
    content_length = models.BigIntegerField(default=0)
    response_time = models.IntegerField(default=0)
    
    blocked = models.BooleanField(default=False, db_index=True)
    block_reason = models.CharField(max_length=255, blank=True, null=True)
    block_type = models.CharField(max_length=50, blank=True, null=True)

    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['-timestamp', 'blocked']),
            models.Index(fields=['hostname', '-timestamp']),

            models.Index(fields=['-timestamp', 'method']),
            models.Index(fields=['-timestamp', 'status_code']),
            models.Index(fields=['source_ip', '-timestamp']),
            models.Index(fields=['content_length']),
        ]

    def __str__(self):
        return f"{self.method} {self.hostname} - {self.status_code}"


class DomainStats(models.Model):
    """Aggregated statistics per domain"""
    hostname = models.CharField(max_length=255, unique=True, db_index=True)
    request_count = models.BigIntegerField(default=0)
    blocked_count = models.BigIntegerField(default=0)
    total_bytes = models.BigIntegerField(default=0)
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-request_count']
        verbose_name_plural = "Domain stats"

    def __str__(self):
        return f"{self.hostname} ({self.request_count} requests)"


class IPHostnameCache(models.Model):
    """Cache for DNS reverse lookups"""
    ip_address = models.GenericIPAddressField(unique=True)
    hostname = models.CharField(max_length=255)
    last_updated = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.ip_address} -> {self.hostname}"


class AuditLog(models.Model):
    """Audit log for tracking all user actions"""
    ACTION_CHOICES = [
        ('login', 'Login'),
        ('logout', 'Logout'),
        ('create', 'Create'),
        ('update', 'Update'),
        ('delete', 'Delete'),
        ('block', 'Block/Enable'),
        ('unblock', 'Unblock/Disable'),
    ]
    
    TARGET_TYPE_CHOICES = [
        ('user', 'User'),
        ('domain', 'Blocked Domain'),
        ('ip', 'Blocked IP'),
        ('port', 'Blocked Port'),
        ('rule', 'Custom Rule'),
        ('settings', 'Settings'),
    ]

    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    action = models.CharField(max_length=20, choices=ACTION_CHOICES)
    target_type = models.CharField(max_length=50, blank=True, null=True)
    target_id = models.CharField(max_length=100, blank=True, null=True)
    target_name = models.CharField(max_length=255, blank=True, null=True)
    details = models.TextField(blank=True, null=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['-timestamp', 'action']),
            models.Index(fields=['user', '-timestamp']),
            models.Index(fields=['target_type', '-timestamp']),
        ]

    def __str__(self):
        user_str = self.user.username if self.user else 'System'
        return f"{user_str} - {self.action} - {self.target_type or ''} - {self.timestamp}"
    
    @property
    def action_icon(self):
        icons = {
            'login': 'fa-sign-in-alt',
            'logout': 'fa-sign-out-alt',
            'create': 'fa-plus-circle',
            'update': 'fa-edit',
            'delete': 'fa-trash',
            'block': 'fa-ban',
            'unblock': 'fa-check-circle',
        }
        return icons.get(self.action, 'fa-circle')
    
    @property
    def action_color(self):
        colors = {
            'login': 'text-green-400',
            'logout': 'text-gray-400',
            'create': 'text-blue-400',
            'update': 'text-yellow-400',
            'delete': 'text-red-400',
            'block': 'text-red-400',
            'unblock': 'text-green-400',
        }
        return colors.get(self.action, 'text-gray-400')


@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    """Auto-create UserProfile when User is created"""
    if created:
        role = 'admin' if instance.is_superuser else 'viewer'
        UserProfile.objects.get_or_create(user=instance, defaults={'role': role})
