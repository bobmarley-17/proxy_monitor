from functools import wraps
from django.shortcuts import redirect
from django.contrib import messages
from django.http import JsonResponse


def get_user_role(user):
    """Get user's role from profile"""
    if not user.is_authenticated:
        return None
    try:
        return user.profile.role
    except:
        return 'viewer'


def is_admin(user):
    """Check if user is admin"""
    if not user.is_authenticated:
        return False
    if user.is_superuser:
        return True
    try:
        return user.profile.role == 'admin'
    except:
        return False


def is_operator(user):
    """Check if user is operator or admin"""
    if not user.is_authenticated:
        return False
    if user.is_superuser:
        return True
    try:
        return user.profile.role in ['operator', 'admin']
    except:
        return False


def admin_required(view_func):
    """Decorator: Require admin role"""
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect('dashboard:login')
        if not is_admin(request.user):
            messages.error(request, 'Administrator access required.')
            return redirect('dashboard:index')
        return view_func(request, *args, **kwargs)
    return wrapper


def operator_required(view_func):
    """Decorator: Require operator or admin role"""
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect('dashboard:login')
        if not is_operator(request.user):
            messages.error(request, 'Operator access required.')
            return redirect('dashboard:index')
        return view_func(request, *args, **kwargs)
    return wrapper


def api_admin_required(view_func):
    """Decorator for API: Require admin role"""
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'error': 'Authentication required'}, status=401)
        if not is_admin(request.user):
            return JsonResponse({'error': 'Administrator access required'}, status=403)
        return view_func(request, *args, **kwargs)
    return wrapper


def api_operator_required(view_func):
    """Decorator for API: Require operator or admin role"""
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'error': 'Authentication required'}, status=401)
        if not is_operator(request.user):
            return JsonResponse({'error': 'Operator access required'}, status=403)
        return view_func(request, *args, **kwargs)
    return wrapper


def log_action(user, action, target_type=None, target_id=None, target_name=None, details=None, ip_address=None):
    """Log user action to audit log"""
    from .models import AuditLog
    try:
        AuditLog.objects.create(
            user=user,
            action=action,
            target_type=target_type,
            target_id=str(target_id) if target_id else None,
            target_name=target_name,
            details=details,
            ip_address=ip_address
        )
    except Exception as e:
        print(f"Audit log error: {e}")
