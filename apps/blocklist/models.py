from django.db import models
from django.utils import timezone
from django.core.validators import validate_ipv4_address, validate_ipv6_address
from django.core.exceptions import ValidationError
import re
import fnmatch


class BlockedDomain(models.Model):
    """Blocked domains with wildcard support"""
    CATEGORY_CHOICES = [
        ('manual', 'Manual'),
        ('ads', 'Advertising'),
        ('malware', 'Malware'),
        ('phishing', 'Phishing'),
        ('adult', 'Adult Content'),
        ('social', 'Social Media'),
        ('gambling', 'Gambling'),
        ('streaming', 'Streaming'),
        ('gaming', 'Gaming'),
        ('other', 'Other'),
    ]

    domain = models.CharField(max_length=255, unique=True, db_index=True)
    category = models.CharField(max_length=50, choices=CATEGORY_CHOICES, default='manual')
    reason = models.TextField(blank=True, null=True)
    is_active = models.BooleanField(default=True, db_index=True)
    is_wildcard = models.BooleanField(default=False, db_index=True)
    hit_count = models.IntegerField(default=0)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']
        verbose_name = 'Blocked Domain'
        verbose_name_plural = 'Blocked Domains'

    def __str__(self):
        return f"{self.domain} ({self.category})"

    def save(self, *args, **kwargs):
        # Auto-detect wildcard patterns
        self.is_wildcard = '*' in self.domain or self.domain.startswith('.')
        # Normalize domain
        self.domain = self.domain.lower().strip()
        super().save(*args, **kwargs)

    def matches(self, hostname):
        """Check if hostname matches this rule (including wildcards)"""
        hostname = hostname.lower().strip()
        domain = self.domain.lower().strip()

        if not self.is_wildcard:
            # Exact match or subdomain match
            return hostname == domain or hostname.endswith('.' + domain)

        # Wildcard matching
        if domain.startswith('*.'):
            # *.example.com matches sub.example.com, example.com
            base_domain = domain[2:]
            return hostname == base_domain or hostname.endswith('.' + base_domain)
        elif domain.startswith('.'):
            # .example.com matches any subdomain
            return hostname.endswith(domain) or hostname == domain[1:]
        else:
            # General wildcard pattern (e.g., *ads*, *.ads.*)
            return fnmatch.fnmatch(hostname, domain)

    @classmethod
    def is_blocked(cls, hostname):
        """Check if hostname is blocked by any rule"""
        hostname = hostname.lower().strip()

        # First check exact matches (faster)
        if cls.objects.filter(domain=hostname, is_active=True, is_wildcard=False).exists():
            rule = cls.objects.get(domain=hostname, is_active=True, is_wildcard=False)
            rule.hit_count += 1
            rule.save(update_fields=['hit_count'])
            return True, rule

        # Check if it's a subdomain of a blocked domain
        parts = hostname.split('.')
        for i in range(len(parts)):
            parent_domain = '.'.join(parts[i:])
            if cls.objects.filter(domain=parent_domain, is_active=True, is_wildcard=False).exists():
                rule = cls.objects.get(domain=parent_domain, is_active=True, is_wildcard=False)
                rule.hit_count += 1
                rule.save(update_fields=['hit_count'])
                return True, rule

        # Check wildcard patterns
        wildcard_rules = cls.objects.filter(is_active=True, is_wildcard=True)
        for rule in wildcard_rules:
            if rule.matches(hostname):
                rule.hit_count += 1
                rule.save(update_fields=['hit_count'])
                return True, rule

        return False, None


class BlockedIP(models.Model):
    """Blocked IP addresses and ranges"""
    TYPE_CHOICES = [
        ('source', 'Source IP'),
        ('destination', 'Destination IP'),
        ('both', 'Both'),
    ]

    ip_address = models.CharField(max_length=45, db_index=True)  # Supports IPv6
    ip_type = models.CharField(max_length=20, choices=TYPE_CHOICES, default='source')
    is_range = models.BooleanField(default=False)  # CIDR notation
    cidr_prefix = models.IntegerField(null=True, blank=True)  # e.g., 24 for /24
    reason = models.TextField(blank=True, null=True)
    is_active = models.BooleanField(default=True, db_index=True)
    hit_count = models.IntegerField(default=0)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']
        verbose_name = 'Blocked IP'
        verbose_name_plural = 'Blocked IPs'
        unique_together = ['ip_address', 'ip_type']

    def __str__(self):
        if self.is_range and self.cidr_prefix:
            return f"{self.ip_address}/{self.cidr_prefix} ({self.ip_type})"
        return f"{self.ip_address} ({self.ip_type})"

    def save(self, *args, **kwargs):
        # Parse CIDR notation
        if '/' in self.ip_address:
            parts = self.ip_address.split('/')
            self.ip_address = parts[0]
            self.cidr_prefix = int(parts[1])
            self.is_range = True
        super().save(*args, **kwargs)

    def matches(self, ip, check_type='source'):
        """Check if IP matches this rule"""
        if self.ip_type != 'both' and self.ip_type != check_type:
            return False

        if not self.is_range:
            return ip == self.ip_address

        # CIDR matching
        try:
            import ipaddress
            network = ipaddress.ip_network(f"{self.ip_address}/{self.cidr_prefix}", strict=False)
            return ipaddress.ip_address(ip) in network
        except Exception:
            return ip == self.ip_address

    @classmethod
    def is_blocked(cls, ip, check_type='source'):
        """Check if IP is blocked"""
        # Exact match first
        exact_match = cls.objects.filter(
            ip_address=ip,
            is_active=True,
            is_range=False
        ).filter(
            models.Q(ip_type=check_type) | models.Q(ip_type='both')
        ).first()

        if exact_match:
            exact_match.hit_count += 1
            exact_match.save(update_fields=['hit_count'])
            return True, exact_match

        # Check ranges
        range_rules = cls.objects.filter(
            is_active=True,
            is_range=True
        ).filter(
            models.Q(ip_type=check_type) | models.Q(ip_type='both')
        )

        for rule in range_rules:
            if rule.matches(ip, check_type):
                rule.hit_count += 1
                rule.save(update_fields=['hit_count'])
                return True, rule

        return False, None


class BlockedPort(models.Model):
    """Blocked ports"""
    TYPE_CHOICES = [
        ('source', 'Source Port'),
        ('destination', 'Destination Port'),
        ('both', 'Both'),
    ]

    port = models.IntegerField(db_index=True)
    port_end = models.IntegerField(null=True, blank=True)  # For port ranges
    port_type = models.CharField(max_length=20, choices=TYPE_CHOICES, default='destination')
    protocol = models.CharField(max_length=10, default='tcp', choices=[
        ('tcp', 'TCP'),
        ('udp', 'UDP'),
        ('both', 'Both'),
    ])
    reason = models.TextField(blank=True, null=True)
    is_active = models.BooleanField(default=True, db_index=True)
    hit_count = models.IntegerField(default=0)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']
        verbose_name = 'Blocked Port'
        verbose_name_plural = 'Blocked Ports'

    def __str__(self):
        if self.port_end:
            return f"{self.port}-{self.port_end} ({self.port_type})"
        return f"{self.port} ({self.port_type})"

    def matches(self, port, check_type='destination'):
        """Check if port matches this rule"""
        if self.port_type != 'both' and self.port_type != check_type:
            return False

        if self.port_end:
            return self.port <= port <= self.port_end
        return port == self.port

    @classmethod
    def is_blocked(cls, port, check_type='destination'):
        """Check if port is blocked"""
        if not port:
            return False, None

        # Exact match
        exact_match = cls.objects.filter(
            port=port,
            port_end__isnull=True,
            is_active=True
        ).filter(
            models.Q(port_type=check_type) | models.Q(port_type='both')
        ).first()

        if exact_match:
            exact_match.hit_count += 1
            exact_match.save(update_fields=['hit_count'])
            return True, exact_match

        # Range match
        range_rules = cls.objects.filter(
            port__lte=port,
            port_end__gte=port,
            is_active=True
        ).filter(
            models.Q(port_type=check_type) | models.Q(port_type='both')
        ).first()

        if range_rules:
            range_rules.hit_count += 1
            range_rules.save(update_fields=['hit_count'])
            return True, range_rules

        return False, None


class BlockRule(models.Model):
    """Combined blocking rules for complex conditions"""
    RULE_TYPES = [
        ('domain', 'Domain'),
        ('source_ip', 'Source IP'),
        ('dest_ip', 'Destination IP'),
        ('source_port', 'Source Port'),
        ('dest_port', 'Destination Port'),
        ('combined', 'Combined Rule'),
    ]

    name = models.CharField(max_length=255)
    rule_type = models.CharField(max_length=20, choices=RULE_TYPES, default='domain')
    
    # Domain matching
    domain_pattern = models.CharField(max_length=255, blank=True, null=True)
    
    # IP matching
    source_ip = models.CharField(max_length=45, blank=True, null=True)
    source_ip_cidr = models.IntegerField(null=True, blank=True)
    dest_ip = models.CharField(max_length=45, blank=True, null=True)
    dest_ip_cidr = models.IntegerField(null=True, blank=True)
    
    # Port matching
    source_port_start = models.IntegerField(null=True, blank=True)
    source_port_end = models.IntegerField(null=True, blank=True)
    dest_port_start = models.IntegerField(null=True, blank=True)
    dest_port_end = models.IntegerField(null=True, blank=True)
    
    # Rule metadata
    priority = models.IntegerField(default=100)  # Lower = higher priority
    action = models.CharField(max_length=20, default='block', choices=[
        ('block', 'Block'),
        ('allow', 'Allow'),
        ('log', 'Log Only'),
    ])
    reason = models.TextField(blank=True, null=True)
    is_active = models.BooleanField(default=True, db_index=True)
    hit_count = models.IntegerField(default=0)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['priority', '-created_at']
        verbose_name = 'Block Rule'
        verbose_name_plural = 'Block Rules'

    def __str__(self):
        return f"{self.name} ({self.rule_type})"

    def matches_ip(self, ip, rule_ip, cidr):
        """Check if IP matches rule"""
        if not rule_ip:
            return True  # No restriction
        if not ip:
            return False

        if cidr:
            try:
                import ipaddress
                network = ipaddress.ip_network(f"{rule_ip}/{cidr}", strict=False)
                return ipaddress.ip_address(ip) in network
            except Exception:
                return ip == rule_ip
        return ip == rule_ip

    def matches_port(self, port, port_start, port_end):
        """Check if port matches rule"""
        if port_start is None:
            return True  # No restriction
        if port is None:
            return False

        if port_end:
            return port_start <= port <= port_end
        return port == port_start

    def matches_domain(self, hostname):
        """Check if hostname matches domain pattern"""
        if not self.domain_pattern:
            return True  # No restriction
        if not hostname:
            return False

        hostname = hostname.lower()
        pattern = self.domain_pattern.lower()

        if '*' in pattern:
            return fnmatch.fnmatch(hostname, pattern)
        elif pattern.startswith('.'):
            return hostname.endswith(pattern) or hostname == pattern[1:]
        else:
            return hostname == pattern or hostname.endswith('.' + pattern)

    def matches(self, hostname=None, source_ip=None, dest_ip=None, source_port=None, dest_port=None):
        """Check if request matches this rule"""
        # Check all conditions
        if not self.matches_domain(hostname):
            return False
        if not self.matches_ip(source_ip, self.source_ip, self.source_ip_cidr):
            return False
        if not self.matches_ip(dest_ip, self.dest_ip, self.dest_ip_cidr):
            return False
        if not self.matches_port(source_port, self.source_port_start, self.source_port_end):
            return False
        if not self.matches_port(dest_port, self.dest_port_start, self.dest_port_end):
            return False

        return True

    @classmethod
    def check_request(cls, hostname=None, source_ip=None, dest_ip=None, source_port=None, dest_port=None):
        """Check if request matches any active rule"""
        rules = cls.objects.filter(is_active=True).order_by('priority')

        for rule in rules:
            if rule.matches(hostname, source_ip, dest_ip, source_port, dest_port):
                rule.hit_count += 1
                rule.save(update_fields=['hit_count'])
                return rule.action, rule

        return None, None
