import secrets
import string
import hashlib
import base64
import codecs 
from .models import UsageLog

def log_usage(action_type, request=None):
    """Log usage without storing sensitive data"""
    ip_address = None
    user_agent = ""
    
    if request:
        ip_address = request.META.get('REMOTE_ADDR')
        user_agent = request.META.get('HTTP_USER_AGENT', '')
    
    UsageLog.objects.create(
        action_type=action_type,
        ip_address=ip_address,
        user_agent=user_agent
    )

def generate_password_from_form(form_data):
    """Generate password from form data"""
    characters = ""
    
    if form_data.get('include_lowercase'):
        characters += string.ascii_lowercase
    if form_data.get('include_uppercase'):
        characters += string.ascii_uppercase
    if form_data.get('include_numbers'):
        characters += string.digits
    if form_data.get('include_symbols'):
        characters += "!@#$%^&*()_+-=[]{}|;:,.<>?"
    
    if form_data.get('exclude_similar'):
        similar_chars = "0O1lI"
        characters = ''.join(c for c in characters if c not in similar_chars)
    
    if not characters:
        return "Error: No character types selected"
    
    min_len = form_data.get('min_length', 8)
    max_len = form_data.get('max_length', 16)
    
    length = secrets.randbelow(max_len - min_len + 1) + min_len
    password = ''.join(secrets.choice(characters) for _ in range(length))
    return password

def encrypt_password(password, method, shift=3):
    """Encrypt password using specified method"""
    if method == 'caesar':
        return caesar_cipher(password, shift)
    elif method == 'reverse':
        return password[::-1]
    elif method == 'base64':
        return base64.b64encode(password.encode()).decode()
    elif method == 'rot13':
        return codecs.encode(password, 'rot13')  # Fixed line
    else:
        return password

def decrypt_password(encrypted_password, method, shift=3):
    """Decrypt password using specified method"""
    try:
        if method == 'caesar':
            return caesar_cipher(encrypted_password, -shift)
        elif method == 'reverse':
            return encrypted_password[::-1]
        elif method == 'base64':
            return base64.b64decode(encrypted_password.encode()).decode()
        elif method == 'rot13':
            return codecs.decode(encrypted_password, 'rot13')  # Fixed line
        else:
            return encrypted_password
    except Exception as e:
        return f"Error decrypting: {str(e)}"

def caesar_cipher(text, shift):
    """Caesar cipher implementation"""
    result = ""
    for char in text:
        if char.isalpha():
            ascii_offset = 65 if char.isupper() else 97
            shifted = (ord(char) - ascii_offset + shift) % 26
            result += chr(shifted + ascii_offset)
        else:
            result += char
    return result