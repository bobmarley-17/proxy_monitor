from django.db import models
from django.utils import timezone


class BlockedDomain(models.Model):
    CATEGORY_CHOICES = [
        ('manual', 'Manual'),
        ('ads', 'Advertising'),
        ('malware', 'Malware'),
        ('phishing', 'Phishing'),
        ('adult', 'Adult Content'),
        ('social', 'Social Media'),
        ('gambling', 'Gambling'),
        ('other', 'Other'),
    ]
    
    domain = models.CharField(max_length=255, unique=True, db_index=True)
    category = models.CharField(max_length=50, choices=CATEGORY_CHOICES, default='manual')
    reason = models.TextField(blank=True, null=True)
    is_active = models.BooleanField(default=True)
    hit_count = models.IntegerField(default=0)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']
        verbose_name = 'Blocked Domain'
        verbose_name_plural = 'Blocked Domains'

    def __str__(self):
        return f"{self.domain} ({self.category})"
