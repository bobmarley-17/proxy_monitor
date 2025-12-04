from django.core.management.base import BaseCommand
from django.conf import settings

class Command(BaseCommand):
    help = 'Run proxy server'
    
    def add_arguments(self, parser):
        parser.add_argument('--port', type=int, default=getattr(settings, 'PROXY_PORT', 8080))
    
    def handle(self, *args, **options):
        from apps.proxy.proxy_server import run_proxy
        self.stdout.write(self.style.SUCCESS(f"Starting proxy on port {options['port']}..."))
        run_proxy(options['port'])
