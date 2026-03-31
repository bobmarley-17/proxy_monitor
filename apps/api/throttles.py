# apps/api/throttles.py

from rest_framework.throttling import UserRateThrottle, AnonRateThrottle


class LoginRateThrottle(AnonRateThrottle):
    scope = 'login'


class BurstRateThrottle(UserRateThrottle):
    scope = 'burst'