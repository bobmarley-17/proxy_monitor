# apps/dashboard/migrations/0003_add_performance_indexes.py

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('dashboard', '0002_auto_20260106_1822'),
    ]

    operations = [
        migrations.AddIndex(
            model_name='proxyrequest',
            index=models.Index(
                fields=['-timestamp'],
                name='idx_proxy_timestamp_desc',
            ),
        ),
        migrations.AddIndex(
            model_name='proxyrequest',
            index=models.Index(
                fields=['timestamp', 'blocked'],
                name='idx_proxy_ts_blocked',
            ),
        ),
        migrations.AddIndex(
            model_name='proxyrequest',
            index=models.Index(
                fields=['hostname'],
                name='idx_proxy_hostname',
            ),
        ),
        migrations.AddIndex(
            model_name='proxyrequest',
            index=models.Index(
                fields=['source_ip'],
                name='idx_proxy_source_ip',
            ),
        ),
        migrations.AddIndex(
            model_name='proxyrequest',
            index=models.Index(
                fields=['method'],
                name='idx_proxy_method',
            ),
        ),
        migrations.AddIndex(
            model_name='proxyrequest',
            index=models.Index(
                fields=['blocked'],
                name='idx_proxy_blocked',
            ),
        ),
        migrations.AddIndex(
            model_name='iphostnamecache',
            index=models.Index(
                fields=['ip_address'],
                name='idx_ipcache_ip',
            ),
        ),
    ]
