from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)

from .api_views import *

# Router for viewsets (if you want to add any later)
router = DefaultRouter()

urlpatterns = [
    # Authentication endpoints
    path('auth/login/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('auth/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    
    # API info
    path('', api_info, name='api_info'),
    
    # Functional endpoints
    path('generate/', generate_password_api, name='api_generate_password'),
    path('encrypt/', encrypt_password_api, name='api_encrypt_password'),
    path('decrypt/', decrypt_password_api, name='api_decrypt_password'),
    path('strength/', check_password_strength_api, name='api_password_strength'),
    
    # CRUD endpoints
    path('policies/', PasswordPolicyListCreateView.as_view(), name='api_password_policies'),
    path('policies/<int:pk>/', PasswordPolicyDetailView.as_view(), name='api_password_policy_detail'),
    path('methods/', EncryptionMethodListView.as_view(), name='api_encryption_methods'),
    path('logs/', UsageLogListView.as_view(), name='api_usage_logs'),
    
    # Include router URLs
    path('', include(router.urls)),
]