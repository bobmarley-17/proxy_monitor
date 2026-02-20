from django.core.management.base import BaseCommand
from apps.proxy.proxy_server import run_proxy


class Command(BaseCommand):
    help = "Run the proxy server"

    def add_arguments(self, parser):
        parser.add_argument(
            "--port",
            type=int,
            default=8088,
            help="Port to bind"
        )

    def handle(self, *args, **options):
        port = options["port"]

        self.stdout.write(
            self.style.SUCCESS(f"Starting proxy server on 0.0.0.0:{port}")
        )

        try:
            run_proxy(port)
        except KeyboardInterrupt:
            self.stdout.write(
                self.style.WARNING("Proxy server stopped")
            )