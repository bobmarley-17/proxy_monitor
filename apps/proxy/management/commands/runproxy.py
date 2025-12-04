from django.core.management.base import BaseCommand
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from apps.proxy.proxy_server import run_proxy

class Command(BaseCommand):
    help = 'Run the proxy server'

    def add_arguments(self, parser):
        parser.add_argument('--port', type=int, default=8088, help='Port to bind')

    def handle(self, *args, **options):
        port = options['port']
        
        self.stdout.write(f'Starting proxy server on 0.0.0.0:{port}')
        
        try:
            run_proxy(port)  # Just pass port, not async
        except KeyboardInterrupt:
            self.stdout.write('Proxy server stopped')
