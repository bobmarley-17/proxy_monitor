from django.urls import path, include

urlpatterns = [
    path('', include('apps.dashboard.urls')),
    path('api/blocklist/', include('apps.blocklist.urls')),
]
