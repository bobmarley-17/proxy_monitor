def filter_api_v1_only(endpoints):
    """
    Only include /api/v1/ endpoints in schema.
    Excludes old /api/blocklist/ views that cause IPAddressField errors.
    """
    filtered = []
    for (path, path_regex, method, callback) in endpoints:
        # Only include paths that start with /api/v1/
        if path.startswith('/api/v1/'):
            filtered.append((path, path_regex, method, callback))
    return filtered