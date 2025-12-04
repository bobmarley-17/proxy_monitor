from django.db import models
from django.utils import timezone
from django.conf import settings
import dns.resolver
import dns.reversename
import socket


# Custom DNS Server Configuration
DNS_SERVERS = getattr(settings, 'DNS_SERVERS', ['10.113.32.32'])
DNS_TIMEOUT = getattr(settings, 'DNS_TIMEOUT', 5)


class ProxyRequest(models.Model):
    timestamp = models.DateTimeField(default=timezone.now, db_index=True)
    method = models.CharField(max_length=10, db_index=True)
    url = models.TextField(blank=True, null=True)
    hostname = models.CharField(max_length=255, db_index=True)
    path = models.TextField(blank=True, null=True)
    
    source_ip = models.CharField(max_length=45, blank=True, null=True, db_index=True)
    source_port = models.IntegerField(blank=True, null=True)
    destination_ip = models.CharField(max_length=45, blank=True, null=True)
    destination_port = models.IntegerField(blank=True, null=True)
    
    status_code = models.IntegerField(default=0, db_index=True)
    content_type = models.CharField(max_length=100, blank=True, null=True)
    content_length = models.BigIntegerField(default=0)
    response_time = models.IntegerField(default=0)
    
    blocked = models.BooleanField(default=False, db_index=True)
    block_reason = models.CharField(max_length=255, blank=True, null=True)
    
    user_agent = models.TextField(blank=True, null=True)
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


class IPHostnameCache(models.Model):
    """Cache for reverse DNS lookups using custom DNS server"""
    ip_address = models.CharField(max_length=45, unique=True, db_index=True)
    hostname = models.CharField(max_length=255, blank=True, null=True)
    dns_server = models.CharField(max_length=45, blank=True, null=True)
    resolved_at = models.DateTimeField(auto_now=True)
    resolution_time_ms = models.IntegerField(default=0)
    
    class Meta:
        verbose_name = "IP Hostname Cache"
        verbose_name_plural = "IP Hostname Cache"
    
    def __str__(self):
        return f"{self.ip_address} -> {self.hostname or 'Unknown'}"
    
    @classmethod
    def resolve_with_custom_dns(cls, ip_address, dns_server=None):
        """
        Resolve IP to hostname using custom DNS server
        
        Usage:
            hostname = IPHostnameCache.resolve_with_custom_dns('10.113.28.17', '10.113.32.32')
            
        This is equivalent to:
            nslookup 10.113.28.17 10.113.32.32
        """
        import time
        start_time = time.time()
        
        # Use provided DNS server or default from settings
        if dns_server is None:
            dns_server = DNS_SERVERS[0] if DNS_SERVERS else None
        
        # Check cache first
        try:
            cached = cls.objects.get(ip_address=ip_address)
            # Return cached if less than 1 hour old
            if (timezone.now() - cached.resolved_at).total_seconds() < 3600:
                return cached.hostname
        except cls.DoesNotExist:
            pass
        
        hostname = None
        resolution_time = 0
        
        try:
            # Create a custom resolver with our DNS server
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [dns_server] if dns_server else resolver.nameservers
            resolver.timeout = DNS_TIMEOUT
            resolver.lifetime = DNS_TIMEOUT
            
            # Convert IP to reverse DNS name (PTR record lookup)
            # 10.113.28.17 -> 17.28.113.10.in-addr.arpa
            rev_name = dns.reversename.from_address(ip_address)
            
            # Perform the PTR lookup
            answers = resolver.resolve(rev_name, 'PTR')
            
            if answers:
                # Get the first PTR record and remove trailing dot
                hostname = str(answers[0]).rstrip('.')
                
        except dns.resolver.NXDOMAIN:
            # No PTR record exists
            hostname = None
        except dns.resolver.NoAnswer:
            # No answer from DNS server
            hostname = None
        except dns.resolver.Timeout:
            # DNS query timed out
            hostname = None
        except dns.exception.DNSException as e:
            # Other DNS errors
            print(f"[DNS] Error resolving {ip_address}: {e}")
            hostname = None
        except Exception as e:
            print(f"[DNS] Unexpected error resolving {ip_address}: {e}")
            hostname = None
        
        resolution_time = int((time.time() - start_time) * 1000)
        
        # Cache the result
        cls.objects.update_or_create(
            ip_address=ip_address,
            defaults={
                'hostname': hostname,
                'dns_server': dns_server,
                'resolution_time_ms': resolution_time
            }
        )
        
        return hostname
    
    @classmethod
    def resolve(cls, ip_address):
        """Resolve using default DNS server from settings"""
        return cls.resolve_with_custom_dns(ip_address)
    
    @classmethod
    def resolve_bulk(cls, ip_list, dns_server=None, max_workers=10):
        """Resolve multiple IPs in parallel"""
        from concurrent.futures import ThreadPoolExecutor
        
        results = {}
        
        def resolve_single(ip):
            results[ip] = cls.resolve_with_custom_dns(ip, dns_server)
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            executor.map(resolve_single, ip_list)
        
        return results
