from django.contrib import admin

from django.contrib import admin
from .models import PasswordPolicy, EncryptionMethod, UsageLog

@admin.register(PasswordPolicy)
class PasswordPolicyAdmin(admin.ModelAdmin):
    list_display = ['name', 'min_length', 'max_length', 'include_uppercase', 
                    'include_numbers', 'include_symbols', 'created_at']
    list_filter = ['include_uppercase', 'include_lowercase', 'include_numbers', 'include_symbols']
    search_fields = ['name']
    readonly_fields = ['created_at']

@admin.register(EncryptionMethod)
class EncryptionMethodAdmin(admin.ModelAdmin):
    list_display = ['name', 'description', 'is_active']
    list_filter = ['is_active']
    search_fields = ['name', 'description']

@admin.register(UsageLog)
class UsageLogAdmin(admin.ModelAdmin):
    list_display = ['action_type', 'timestamp', 'ip_address']
    list_filter = ['action_type', 'timestamp']
    readonly_fields = ['action_type', 'timestamp', 'ip_address', 'user_agent']
    
    def has_add_permission(self, request):
        return False  # Prevent manual addition of logs