from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages


def login_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard:index')
    
    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        password = request.POST.get('password', '')
        
        if username and password:
            user = authenticate(request, username=username, password=password)
            if user and user.is_active:
                login(request, user)
                role = 'User'
                if hasattr(user, 'profile'):
                    role = user.profile.get_role_display()
                messages.success(request, f'Welcome, {user.username}! ({role})')
                return redirect('dashboard:index')
            else:
                messages.error(request, 'Invalid username or password.')
        else:
            messages.error(request, 'Please enter username and password.')
    
    return render(request, 'dashboard/login.html')


def logout_view(request):
    logout(request)
    messages.info(request, 'Logged out successfully.')
    return redirect('dashboard:login')


@login_required
def profile_view(request):
    if request.method == 'POST':
        user = request.user
        user.first_name = request.POST.get('first_name', '')
        user.last_name = request.POST.get('last_name', '')
        user.email = request.POST.get('email', '')
        user.save()
        
        if hasattr(user, 'profile'):
            user.profile.phone = request.POST.get('phone', '')
            user.profile.department = request.POST.get('department', '')
            user.profile.save()
        
        messages.success(request, 'Profile updated.')
    
    return render(request, 'dashboard/profile.html', {'title': 'My Profile'})
