from django.db import models
from django.utils import timezone
import ipaddress
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
        self.is_wildcard = '*' in self.domain or self.domain.startswith('.')
        self.domain = self.domain.lower().strip()
        super().save(*args, **kwargs)

    def matches(self, hostname):
        hostname = hostname.lower().strip()
        domain = self.domain.lower().strip()

        if not self.is_wildcard:
            return hostname == domain or hostname.endswith('.' + domain)

        if domain.startswith('*.'):
            base_domain = domain[2:]
            return hostname == base_domain or hostname.endswith('.' + base_domain)
        elif domain.startswith('.'):
            return hostname.endswith(domain) or hostname == domain[1:]
        else:
            return fnmatch.fnmatch(hostname, domain)

    @classmethod
    def is_blocked(cls, hostname):
        hostname = hostname.lower().strip()

        exact = cls.objects.filter(domain=hostname, is_active=True, is_wildcard=False).first()
        if exact:
            cls.objects.filter(id=exact.id).update(hit_count=models.F('hit_count') + 1)
            return True, exact

        parts = hostname.split('.')
        for i in range(len(parts)):
            parent = '.'.join(parts[i:])
            parent_match = cls.objects.filter(domain=parent, is_active=True, is_wildcard=False).first()
            if parent_match:
                cls.objects.filter(id=parent_match.id).update(hit_count=models.F('hit_count') + 1)
                return True, parent_match

        for rule in cls.objects.filter(is_active=True, is_wildcard=True):
            if rule.matches(hostname):
                cls.objects.filter(id=rule.id).update(hit_count=models.F('hit_count') + 1)
                return True, rule

        return False, None


class BlockedIP(models.Model):
    """Blocked IP addresses and ranges"""
    TYPE_CHOICES = [
        ('source', 'Source IP'),
        ('destination', 'Destination IP'),
        ('both', 'Both'),
    ]

    ip_address = models.CharField(max_length=45, db_index=True)
    ip_type = models.CharField(max_length=20, choices=TYPE_CHOICES, default='source')
    is_range = models.BooleanField(default=False)
    cidr_prefix = models.IntegerField(null=True, blank=True)
    reason = models.TextField(blank=True, null=True)
    is_active = models.BooleanField(default=True, db_index=True)
    hit_count = models.IntegerField(default=0)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']
        verbose_name = 'Blocked IP'
        verbose_name_plural = 'Blocked IPs'

    def __str__(self):
        if self.is_range and self.cidr_prefix:
            return f"{self.ip_address}/{self.cidr_prefix} ({self.ip_type})"
        return f"{self.ip_address} ({self.ip_type})"

    def save(self, *args, **kwargs):
        if '/' in self.ip_address:
            parts = self.ip_address.split('/')
            self.ip_address = parts[0]
            self.cidr_prefix = int(parts[1])
            self.is_range = True
        super().save(*args, **kwargs)

    def matches(self, ip, check_type='source'):
        if self.ip_type != 'both' and self.ip_type != check_type:
            return False

        if not self.is_range:
            return ip == self.ip_address

        try:
            network = ipaddress.ip_network(f"{self.ip_address}/{self.cidr_prefix}", strict=False)
            return ipaddress.ip_address(ip) in network
        except Exception:
            return ip == self.ip_address

    @classmethod
    def is_blocked(cls, ip, check_type='source'):
        exact_match = cls.objects.filter(
            ip_address=ip,
            is_active=True,
            is_range=False
        ).filter(
            models.Q(ip_type=check_type) | models.Q(ip_type='both')
        ).first()

        if exact_match:
            cls.objects.filter(id=exact_match.id).update(hit_count=models.F('hit_count') + 1)
            return True, exact_match

        range_rules = cls.objects.filter(
            is_active=True,
            is_range=True
        ).filter(
            models.Q(ip_type=check_type) | models.Q(ip_type='both')
        )

        for rule in range_rules:
            if rule.matches(ip, check_type):
                cls.objects.filter(id=rule.id).update(hit_count=models.F('hit_count') + 1)
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
    port_end = models.IntegerField(null=True, blank=True)
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

    @classmethod
    def is_blocked(cls, port, check_type='destination'):
        if not port:
            return False, None

        exact_match = cls.objects.filter(
            port=port,
            port_end__isnull=True,
            is_active=True
        ).filter(
            models.Q(port_type=check_type) | models.Q(port_type='both')
        ).first()

        if exact_match:
            cls.objects.filter(id=exact_match.id).update(hit_count=models.F('hit_count') + 1)
            return True, exact_match

        range_match = cls.objects.filter(
            port__lte=port,
            port_end__gte=port,
            is_active=True
        ).filter(
            models.Q(port_type=check_type) | models.Q(port_type='both')
        ).first()

        if range_match:
            cls.objects.filter(id=range_match.id).update(hit_count=models.F('hit_count') + 1)
            return True, range_match

        return False, None


class BlockRule(models.Model):
    """Combined blocking rules - Firewall style"""
    name = models.CharField(max_length=255)
    
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
    priority = models.IntegerField(default=100)
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
        return f"{self.name} ({self.action})"

    def _match_ip(self, ip, rule_ip, cidr):
        if not rule_ip:
            return True
        if not ip:
            return False

        if cidr:
            try:
                network = ipaddress.ip_network(f"{rule_ip}/{cidr}", strict=False)
                return ipaddress.ip_address(ip) in network
            except Exception:
                return ip == rule_ip
        return ip == rule_ip

    def _match_port(self, port, port_start, port_end):
        if port_start is None:
            return True
        if port is None:
            return False

        if port_end:
            return port_start <= port <= port_end
        return port == port_start

    def _match_domain(self, hostname):
        if not self.domain_pattern:
            return True
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
        if not self._match_domain(hostname):
            return False
        if not self._match_ip(source_ip, self.source_ip, self.source_ip_cidr):
            return False
        if not self._match_ip(dest_ip, self.dest_ip, self.dest_ip_cidr):
            return False
        if not self._match_port(source_port, self.source_port_start, self.source_port_end):
            return False
        if not self._match_port(dest_port, self.dest_port_start, self.dest_port_end):
            return False
        return True

    @classmethod
    def check_request(cls, hostname=None, source_ip=None, dest_ip=None, source_port=None, dest_port=None):
        rules = cls.objects.filter(is_active=True).order_by('priority')

        for rule in rules:
            if rule.matches(hostname, source_ip, dest_ip, source_port, dest_port):
                cls.objects.filter(id=rule.id).update(hit_count=models.F('hit_count') + 1)
                return rule.action, rule

        return None, None
