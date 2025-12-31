from django.conf import settings


def rbac_context(request):
    """Add RBAC info to all templates"""
    context = {
        'is_admin': False,
        'is_operator': False,
        'user_role': 'viewer',
        'dns_server': getattr(settings, 'DNS_SERVERS', ['8.8.8.8'])[0],
        'proxy_port': getattr(settings, 'PROXY_PORT', 8088),
    }
    
    if request.user.is_authenticated:
        # Superuser is always admin
        if request.user.is_superuser:
            context['is_admin'] = True
            context['is_operator'] = True
            context['user_role'] = 'admin'
        else:
            try:
                profile = request.user.profile
                role = profile.role
                context['user_role'] = role
                context['is_admin'] = role == 'admin'
                context['is_operator'] = role in ['admin', 'operator']
            except Exception as e:
                print(f"RBAC context error: {e}")
    
    # Debug output
    print(f"RBAC Context: user={request.user}, is_admin={context['is_admin']}, is_operator={context['is_operator']}")
    
    return context
