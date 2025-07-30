from rest_framework import generics, status, permissions
from rest_framework.decorators import api_view, permission_classes, throttle_classes
from rest_framework.response import Response
from rest_framework.throttling import UserRateThrottle, AnonRateThrottle
from django.utils import timezone
from datetime import datetime
import string
import math
import re

from .models import PasswordPolicy, EncryptionMethod, UsageLog
from .serializers import *
from .utils import generate_password_from_form, encrypt_password, decrypt_password, log_usage

# Custom throttle classes
class PasswordGenerationThrottle(UserRateThrottle):
    scope = 'password_generation'

class EncryptionThrottle(UserRateThrottle):
    scope = 'encryption'

# CRUD API Views for Models
class PasswordPolicyListCreateView(generics.ListCreateAPIView):
    queryset = PasswordPolicy.objects.all()
    serializer_class = PasswordPolicySerializer
    permission_classes = [permissions.IsAuthenticated]

class PasswordPolicyDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = PasswordPolicy.objects.all()
    serializer_class = PasswordPolicySerializer
    permission_classes = [permissions.IsAuthenticated]

class EncryptionMethodListView(generics.ListAPIView):
    queryset = EncryptionMethod.objects.filter(is_active=True)
    serializer_class = EncryptionMethodSerializer
    permission_classes = [permissions.AllowAny]  # Public endpoint

class UsageLogListView(generics.ListAPIView):
    serializer_class = UsageLogSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        # Only show logs for the current user's session
        return UsageLog.objects.filter(
            timestamp__gte=timezone.now().replace(hour=0, minute=0, second=0)
        ).order_by('-timestamp')

# Functional API Endpoints
@api_view(['POST'])
@permission_classes([permissions.AllowAny])  # Allow anonymous access
@throttle_classes([PasswordGenerationThrottle, AnonRateThrottle])
def generate_password_api(request):
    """
    Generate a password based on provided criteria or policy.
    """
    serializer = PasswordGenerationRequestSerializer(data=request.data)
    
    if not serializer.is_valid():
        return Response({
            'error': 'Invalid request data',
            'details': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)
    
    data = serializer.validated_data
    
    # Use policy if provided
    if data.get('policy_id'):
        try:
            policy = PasswordPolicy.objects.get(id=data['policy_id'])
            form_data = {
                'min_length': policy.min_length,
                'max_length': policy.max_length,
                'include_uppercase': policy.include_uppercase,
                'include_lowercase': policy.include_lowercase,
                'include_numbers': policy.include_numbers,
                'include_symbols': policy.include_symbols,
                'exclude_similar': policy.exclude_similar,
            }
        except PasswordPolicy.DoesNotExist:
            return Response({
                'error': 'Password policy not found'
            }, status=status.HTTP_404_NOT_FOUND)
    else:
        form_data = data
    
    # Generate password
    generated_password = generate_password_from_form(form_data)
    
    if generated_password.startswith('Error:'):
        return Response({
            'error': generated_password
        }, status=status.HTTP_400_BAD_REQUEST)
    
    # Calculate password strength
    strength_info = calculate_password_strength(generated_password)
    
    # Log usage
    log_usage('api_generate', request)
    
    response_data = {
        'password': generated_password,
        'length': len(generated_password),
        'strength_score': strength_info['strength_score'],
        'entropy': strength_info['entropy'],
        'timestamp': timezone.now()
    }
    
    response_serializer = PasswordGenerationResponseSerializer(response_data)
    return Response(response_serializer.data, status=status.HTTP_200_OK)

@api_view(['POST'])
@permission_classes([permissions.AllowAny])
@throttle_classes([EncryptionThrottle, AnonRateThrottle])
def encrypt_password_api(request):
    """
    Encrypt a password using specified method.
    """
    serializer = PasswordEncryptionRequestSerializer(data=request.data)
    
    if not serializer.is_valid():
        return Response({
            'error': 'Invalid request data',
            'details': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)
    
    data = serializer.validated_data
    
    try:
        encrypted = encrypt_password(
            data['password'],
            data['encryption_method'],
            data.get('shift_amount', 3)
        )
        
        log_usage('api_encrypt', request)
        
        response_data = {
            'encrypted_password': encrypted,
            'encryption_method': data['encryption_method'],
            'timestamp': timezone.now()
        }
        
        response_serializer = PasswordEncryptionResponseSerializer(response_data)
        return Response(response_serializer.data, status=status.HTTP_200_OK)
        
    except Exception as e:
        return Response({
            'error': f'Encryption failed: {str(e)}'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['POST'])
@permission_classes([permissions.AllowAny])
@throttle_classes([EncryptionThrottle, AnonRateThrottle])
def decrypt_password_api(request):
    """
    Decrypt a password using specified method.
    """
    serializer = PasswordDecryptionRequestSerializer(data=request.data)
    
    if not serializer.is_valid():
        return Response({
            'error': 'Invalid request data',
            'details': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)
    
    data = serializer.validated_data
    
    try:
        decrypted = decrypt_password(
            data['encrypted_password'],
            data['encryption_method'],
            data.get('shift_amount', 3)
        )
        
        if decrypted.startswith('Error decrypting:'):
            return Response({
                'error': decrypted
            }, status=status.HTTP_400_BAD_REQUEST)
        
        log_usage('api_decrypt', request)
        
        response_data = {
            'decrypted_password': decrypted,
            'encryption_method': data['encryption_method'],
            'timestamp': timezone.now()
        }
        
        response_serializer = PasswordDecryptionResponseSerializer(response_data)
        return Response(response_serializer.data, status=status.HTTP_200_OK)
        
    except Exception as e:
        return Response({
            'error': f'Decryption failed: {str(e)}'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['POST'])
@permission_classes([permissions.AllowAny])
def check_password_strength_api(request):
    """
    Analyze password strength and provide recommendations.
    """
    serializer = PasswordStrengthRequestSerializer(data=request.data)
    
    if not serializer.is_valid():
        return Response({
            'error': 'Invalid request data',
            'details': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)
    
    password = serializer.validated_data['password']
    strength_info = calculate_password_strength(password)
    
    log_usage('api_strength_check', request)
    
    response_serializer = PasswordStrengthResponseSerializer(strength_info)
    return Response(response_serializer.data, status=status.HTTP_200_OK)

@api_view(['GET'])
@permission_classes([permissions.AllowAny])
def api_info(request):
    """
    Provide information about the API endpoints.
    """
    info = {
        'name': 'PassEncrypt API',
        'version': '1.0.0',
        'description': 'RESTful API for password generation and encryption',
        'endpoints': {
            'authentication': '/api/auth/',
            'password_generation': '/api/generate/',
            'password_encryption': '/api/encrypt/',
            'password_decryption': '/api/decrypt/',
            'password_strength': '/api/strength/',
            'password_policies': '/api/policies/',
            'encryption_methods': '/api/methods/',
            'usage_logs': '/api/logs/',
        },
        'rate_limits': {
            'anonymous': '100 requests/hour',
            'authenticated': '500 requests/hour',
            'password_generation': '50 requests/hour',
            'encryption': '100 requests/hour',
        },
        'timestamp': timezone.now()
    }
    
    return Response(info, status=status.HTTP_200_OK)

# Utility functions
def calculate_password_strength(password):
    """
    Calculate password strength and provide analysis.
    """
    length = len(password)
    
    # Character set analysis
    has_lowercase = bool(re.search(r'[a-z]', password))
    has_uppercase = bool(re.search(r'[A-Z]', password))
    has_numbers = bool(re.search(r'\d', password))
    has_symbols = bool(re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]', password))
    
    # Calculate character set size
    charset_size = 0
    if has_lowercase:
        charset_size += 26
    if has_uppercase:
        charset_size += 26
    if has_numbers:
        charset_size += 10
    if has_symbols:
        charset_size += 32
    
    # Calculate entropy
    entropy = length * math.log2(charset_size) if charset_size > 0 else 0
    
    # Determine strength score
    if entropy >= 60:
        strength_score = "Very Strong"
    elif entropy >= 50:
        strength_score = "Strong"
    elif entropy >= 35:
        strength_score = "Moderate"
    elif entropy >= 25:
        strength_score = "Weak"
    else:
        strength_score = "Very Weak"
    
    # Generate recommendations
    recommendations = []
    if length < 12:
        recommendations.append("Use at least 12 characters")
    if not has_uppercase:
        recommendations.append("Include uppercase letters")
    if not has_lowercase:
        recommendations.append("Include lowercase letters")
    if not has_numbers:
        recommendations.append("Include numbers")
    if not has_symbols:
        recommendations.append("Include special symbols")
    if not recommendations:
        recommendations.append("Password strength is good!")
    
    return {
        'password_length': length,
        'strength_score': strength_score,
        'entropy': round(entropy, 2),
        'has_uppercase': has_uppercase,
        'has_lowercase': has_lowercase,
        'has_numbers': has_numbers,
        'has_symbols': has_symbols,
        'recommendations': recommendations
    }