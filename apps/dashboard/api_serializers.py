# apps/dashboard/api_serializers.py

from rest_framework import serializers
from django.contrib.auth.models import User
from .models import UserProfile, ProxyRequest, DomainStats, AuditLog


# ━━━ AUTH ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class ProfileSerializer(serializers.ModelSerializer):
    role = serializers.CharField(source='profile.role', read_only=True)
    department = serializers.CharField(
        source='profile.department', required=False, allow_blank=True, allow_null=True,
    )
    phone = serializers.CharField(
        source='profile.phone', required=False, allow_blank=True, allow_null=True,
    )

    class Meta:
        model = User
        fields = [
            'id', 'username', 'email', 'first_name', 'last_name',
            'role', 'department', 'phone',
            'is_active', 'is_staff', 'is_superuser',
            'last_login', 'date_joined',
        ]
        read_only_fields = [
            'id', 'username', 'role', 'is_active', 'is_staff',
            'is_superuser', 'last_login', 'date_joined',
        ]

    def update(self, instance, validated_data):
        profile_data = validated_data.pop('profile', {})
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        if profile_data:
            profile = instance.profile
            for attr, value in profile_data.items():
                setattr(profile, attr, value)
            profile.save()
        return instance


class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True, min_length=8)
    new_password_confirm = serializers.CharField(required=True)

    def validate_old_password(self, value):
        user = self.context['request'].user
        if not user.check_password(value):
            raise serializers.ValidationError('Current password is incorrect.')
        return value

    def validate(self, data):
        if data['new_password'] != data['new_password_confirm']:
            raise serializers.ValidationError(
                {'new_password_confirm': 'Passwords do not match.'}
            )
        return data


# ━━━ USER MANAGEMENT ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class UserProfileInlineSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserProfile
        fields = ['role', 'department', 'phone']


class UserListSerializer(serializers.ModelSerializer):
    role = serializers.CharField(source='profile.role', read_only=True)
    department = serializers.CharField(source='profile.department', read_only=True)

    class Meta:
        model = User
        fields = [
            'id', 'username', 'email', 'first_name', 'last_name',
            'role', 'department', 'is_active', 'last_login', 'date_joined',
        ]


class UserDetailSerializer(serializers.ModelSerializer):
    profile = UserProfileInlineSerializer()

    class Meta:
        model = User
        fields = [
            'id', 'username', 'email', 'first_name', 'last_name',
            'profile', 'is_active', 'is_staff',
            'last_login', 'date_joined',
        ]
        read_only_fields = ['id', 'last_login', 'date_joined']

    def update(self, instance, validated_data):
        profile_data = validated_data.pop('profile', {})
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        if profile_data:
            profile = instance.profile
            for attr, value in profile_data.items():
                setattr(profile, attr, value)
            profile.save()
        return instance


class UserCreateSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, min_length=8)
    password_confirm = serializers.CharField(write_only=True)
    role = serializers.ChoiceField(
        choices=UserProfile.ROLE_CHOICES, default='viewer',
    )
    department = serializers.CharField(required=False, allow_blank=True, default='')
    phone = serializers.CharField(required=False, allow_blank=True, default='')

    class Meta:
        model = User
        fields = [
            'username', 'email', 'password', 'password_confirm',
            'first_name', 'last_name', 'role', 'department', 'phone',
        ]

    def validate(self, data):
        if data['password'] != data.pop('password_confirm'):
            raise serializers.ValidationError(
                {'password_confirm': 'Passwords do not match.'}
            )
        return data

    def create(self, validated_data):
        role = validated_data.pop('role', 'viewer')
        department = validated_data.pop('department', '')
        phone = validated_data.pop('phone', '')
        password = validated_data.pop('password')

        user = User(**validated_data)
        user.set_password(password)
        user.save()

        # Update the auto-created profile (from post_save signal)
        profile = user.profile
        profile.role = role
        profile.department = department
        profile.phone = phone
        profile.save()

        return user


# ━━━ PROXY REQUESTS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class ProxyRequestSerializer(serializers.ModelSerializer):
    class Meta:
        model = ProxyRequest
        fields = [
            'id', 'timestamp', 'method', 'url', 'hostname',
            'status_code', 'source_ip', 'source_port',
            'destination_ip', 'destination_port',
            'content_length', 'response_time',
            'blocked', 'block_reason', 'block_type',
        ]


class ProxyRequestListSerializer(serializers.ModelSerializer):
    class Meta:
        model = ProxyRequest
        fields = [
            'id', 'timestamp', 'method', 'hostname',
            'status_code', 'source_ip', 'blocked',
            'block_reason', 'response_time',
        ]


# ━━━ DOMAIN STATS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class DomainStatsSerializer(serializers.ModelSerializer):
    block_rate = serializers.SerializerMethodField()

    class Meta:
        model = DomainStats
        fields = [
            'id', 'hostname', 'request_count', 'blocked_count',
            'total_bytes', 'first_seen', 'last_seen', 'block_rate',
        ]

    def get_block_rate(self, obj):
        if obj.request_count == 0:
            return 0.0
        return round((obj.blocked_count / obj.request_count) * 100, 1)


# ━━━ AUDIT LOGS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class AuditLogSerializer(serializers.ModelSerializer):
    username = serializers.SerializerMethodField()

    class Meta:
        model = AuditLog
        fields = [
            'id', 'username', 'user', 'action', 'target_type',
            'target_id', 'target_name', 'details',
            'ip_address', 'timestamp',
        ]

    def get_username(self, obj):
        if obj.user:
            return obj.user.username
        return 'System'