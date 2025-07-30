from django.db import models

from django.db import models
from django.contrib.auth.models import User

class PasswordPolicy(models.Model):
    """Store different password generation policies"""
    name = models.CharField(max_length=100)
    min_length = models.IntegerField(default=8)
    max_length = models.IntegerField(default=20)
    include_uppercase = models.BooleanField(default=True)
    include_lowercase = models.BooleanField(default=True)
    include_numbers = models.BooleanField(default=True)
    include_symbols = models.BooleanField(default=True)
    exclude_similar = models.BooleanField(default=False)  # exclude 0, O, l, 1, etc.
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return self.name
    
    class Meta:
        verbose_name_plural = "Password Policies"

class EncryptionMethod(models.Model):
    """Store different encryption/scrambling methods"""
    name = models.CharField(max_length=100)
    description = models.TextField()
    is_active = models.BooleanField(default=True)
    
    def __str__(self):
        return self.name

class UsageLog(models.Model):
    """Log usage without storing actual passwords"""
    action_type = models.CharField(max_length=50)  # 'generate', 'encrypt', 'decrypt'
    timestamp = models.DateTimeField(auto_now_add=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    
    def __str__(self):
        return f"{self.action_type} - {self.timestamp}"
    
    class Meta:
        ordering = ['-timestamp']