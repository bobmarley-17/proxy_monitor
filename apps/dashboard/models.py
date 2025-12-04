from django.db import models
from django.utils import timezone


class ProxyRequest(models.Model):
    # Timestamps
    timestamp = models.DateTimeField(default=timezone.now, db_index=True)
    
    # Request Info
    method = models.CharField(max_length=10, db_index=True)
    url = models.TextField(blank=True, null=True)
    hostname = models.CharField(max_length=255, db_index=True)
    path = models.TextField(blank=True, null=True)
    
    # Network Info
    source_ip = models.CharField(max_length=45, blank=True, null=True, db_index=True)
    source_port = models.IntegerField(blank=True, null=True)
    destination_ip = models.CharField(max_length=45, blank=True, null=True)
    destination_port = models.IntegerField(blank=True, null=True)
    
    # Response Info
    status_code = models.IntegerField(default=0, db_index=True)
    content_type = models.CharField(max_length=100, blank=True, null=True)
    content_length = models.BigIntegerField(default=0)
    response_time = models.IntegerField(default=0)
    
    # Status
    blocked = models.BooleanField(default=False, db_index=True)
    block_reason = models.CharField(max_length=255, blank=True, null=True)
    
    # Client Info
    user_agent = models.TextField(blank=True, null=True)
    
    # GeoIP
    country_code = models.CharField(max_length=2, blank=True, null=True)
    country_name = models.CharField(max_length=100, blank=True, null=True)

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        return f"{self.method} {self.hostname} - {self.status_code}"

    @property
    def status(self):
        if self.blocked:
            return 'blocked'
        elif self.status_code >= 400:
            return 'error'
        return 'success'


class DomainStats(models.Model):
    hostname = models.CharField(max_length=255, unique=True, db_index=True)
    request_count = models.IntegerField(default=0)
    blocked_count = models.IntegerField(default=0)
    error_count = models.IntegerField(default=0)
    total_bytes = models.BigIntegerField(default=0)
    avg_response_time = models.FloatField(default=0)
    last_accessed = models.DateTimeField(auto_now=True)
    first_accessed = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ['-request_count']
        verbose_name_plural = "Domain Stats"

    def __str__(self):
        return f"{self.hostname} ({self.request_count} requests)"


class TrafficStats(models.Model):
    hour = models.DateTimeField(unique=True, db_index=True)
    total_requests = models.IntegerField(default=0)
    blocked_requests = models.IntegerField(default=0)
    total_bytes = models.BigIntegerField(default=0)
    unique_ips = models.IntegerField(default=0)
    unique_domains = models.IntegerField(default=0)
    avg_response_time = models.FloatField(default=0)

    class Meta:
        ordering = ['-hour']

    def __str__(self):
        return f"Stats for {self.hour}"


class Alert(models.Model):
    SEVERITY_CHOICES = [
        ('info', 'Info'),
        ('warning', 'Warning'),
        ('critical', 'Critical'),
    ]

    timestamp = models.DateTimeField(default=timezone.now)
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, default='info')
    alert_type = models.CharField(max_length=50)
    title = models.CharField(max_length=255)
    message = models.TextField()
    source_ip = models.CharField(max_length=45, blank=True, null=True)
    hostname = models.CharField(max_length=255, blank=True, null=True)
    is_read = models.BooleanField(default=False)

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        return f"[{self.severity}] {self.title}"
