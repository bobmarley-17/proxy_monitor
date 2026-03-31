# config/urls.py

from django.urls import path, include

urlpatterns = [
    path('', include('apps.dashboard.urls')),
    path('api/blocklist/', include('apps.blocklist.urls')),
    path('api/v1/', include('apps.api.urls')),
]