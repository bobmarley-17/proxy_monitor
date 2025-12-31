from functools import wraps
from django.shortcuts import redirect
from django.contrib import messages


def role_required(allowed_roles):
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            if not request.user.is_authenticated:
                return redirect('dashboard:login')
            
            if request.user.is_superuser:
                return view_func(request, *args, **kwargs)
            
            if hasattr(request.user, 'profile'):
                if request.user.profile.role in allowed_roles:
                    return view_func(request, *args, **kwargs)
            
            messages.error(request, 'You do not have permission.')
            return redirect('dashboard:index')
        return wrapper
    return decorator


def admin_required(view_func):
    return role_required(['admin'])(view_func)


def operator_required(view_func):
    return role_required(['admin', 'operator'])(view_func)
