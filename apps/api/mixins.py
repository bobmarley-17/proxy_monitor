# apps/api/mixins.py

import csv
from django.http import HttpResponse
from rest_framework.response import Response
from rest_framework import status


class AuditMixin(object):
    """
    Logs create/update/delete to AuditLog.
    Set `audit_target_type` on the view.
    """

    audit_target_type = None

    def perform_create(self, serializer):
        instance = serializer.save()
        self._log('create', instance)

    def perform_update(self, serializer):
        instance = serializer.save()
        self._log('update', instance)

    def perform_destroy(self, instance):
        self._log('delete', instance)
        instance.delete()

    def _log(self, action, instance):
        from apps.dashboard.models import AuditLog
        try:
            AuditLog.objects.create(
                user=self.request.user if self.request.user.is_authenticated else None,
                action=action,
                target_type=self.audit_target_type or instance.__class__.__name__.lower(),
                target_id=str(instance.pk),
                target_name=str(instance)[:255],
                details='API {}: {}'.format(action, instance),
                ip_address=self._client_ip(),
            )
        except Exception:
            pass

    def _client_ip(self):
        xff = self.request.META.get('HTTP_X_FORWARDED_FOR')
        if xff:
            return xff.split(',')[0].strip()
        return self.request.META.get('REMOTE_ADDR', '')


class ExportMixin(object):
    """Adds export_data method. Set `export_filename` on view."""

    export_filename = 'export'

    def export_data(self, request):
        fmt = request.query_params.get('format', 'json')
        queryset = self.filter_queryset(self.get_queryset())[:10000]
        serializer = self.get_serializer(queryset, many=True)

        if fmt == 'csv' and serializer.data:
            response = HttpResponse(content_type='text/csv')
            response['Content-Disposition'] = (
                'attachment; filename="{}.csv"'.format(self.export_filename)
            )
            writer = csv.DictWriter(response, fieldnames=serializer.data[0].keys())
            writer.writeheader()
            writer.writerows(serializer.data)
            return response

        return Response(serializer.data)


class BulkDeleteMixin(object):
    """Bulk delete via POST {"ids": [...]}."""

    def bulk_delete(self, request):
        ids = request.data.get('ids', [])
        if not ids:
            return Response(
                {'error': 'No IDs provided'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        qs = self.get_queryset().filter(pk__in=ids)
        count = qs.count()

        if hasattr(self, '_log'):
            for obj in qs:
                self._log('delete', obj)

        qs.delete()
        return Response({'deleted': count})