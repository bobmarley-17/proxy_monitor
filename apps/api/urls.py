# apps/api/urls.py

from django.urls import path, include
from rest_framework_simplejwt.views import TokenRefreshView

urlpatterns = [
    # JWT token refresh
    path('auth/token/refresh/', TokenRefreshView.as_view(), name='api-token-refresh'),

    # New API endpoints
    path('', include('apps.dashboard.api_urls')),
    path('blocklist/', include('apps.blocklist.api_urls')),
]

# Add docs endpoints with error handling
try:
    from drf_spectacular.views import (
        SpectacularAPIView,
        SpectacularSwaggerView,
        SpectacularRedocView,
    )
    urlpatterns += [
        path('schema/', SpectacularAPIView.as_view(), name='api-schema'),
        path('docs/', SpectacularSwaggerView.as_view(url_name='api-schema'), name='api-swagger'),
        path('docs/redoc/', SpectacularRedocView.as_view(url_name='api-schema'), name='api-redoc'),
    ]
except Exception as e:
    print(f"Warning: Could not load API docs: {e}")