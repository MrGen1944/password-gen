import secrets
import string
import hashlib
import base64
import codecs 
from .models import UsageLog
import hashlib
import secrets
import re
import math

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

def analyze_password_strength(password):
    """
    Comprehensive password strength analysis
    """
    analysis = {
        'length': len(password),
        'has_uppercase': bool(re.search(r'[A-Z]', password)),
        'has_lowercase': bool(re.search(r'[a-z]', password)),
        'has_numbers': bool(re.search(r'\d', password)),
        'has_symbols': bool(re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]', password)),
        'has_spaces': ' ' in password,
        'unique_chars': len(set(password)),
        'repeated_chars': len(password) - len(set(password)),
    }
    
    # Check for common patterns
    analysis['has_sequential'] = bool(re.search(r'(012|123|234|345|456|567|678|789|890|abc|bcd|cde|def)', password.lower()))
    analysis['has_repeated_patterns'] = bool(re.search(r'(.)\1{2,}', password))
    analysis['has_keyboard_patterns'] = bool(re.search(r'(qwerty|asdf|zxcv|1234|password)', password.lower()))
    
    # Calculate character set size
    charset_size = 0
    if analysis['has_lowercase']:
        charset_size += 26
    if analysis['has_uppercase']:
        charset_size += 26
    if analysis['has_numbers']:
        charset_size += 10
    if analysis['has_symbols']:
        charset_size += 32
    if analysis['has_spaces']:
        charset_size += 1
    
    # Calculate entropy
    analysis['entropy'] = analysis['length'] * math.log2(charset_size) if charset_size > 0 else 0
    
    # Determine strength score
    if analysis['entropy'] >= 70:
        analysis['strength_level'] = "Very Strong"
        analysis['strength_color'] = "success"
        analysis['strength_percentage'] = 100
    elif analysis['entropy'] >= 60:
        analysis['strength_level'] = "Strong"
        analysis['strength_color'] = "success"
        analysis['strength_percentage'] = 85
    elif analysis['entropy'] >= 50:
        analysis['strength_level'] = "Good"
        analysis['strength_color'] = "warning"
        analysis['strength_percentage'] = 70
    elif analysis['entropy'] >= 35:
        analysis['strength_level'] = "Moderate"
        analysis['strength_color'] = "warning"
        analysis['strength_percentage'] = 50
    elif analysis['entropy'] >= 25:
        analysis['strength_level'] = "Weak"
        analysis['strength_color'] = "danger"
        analysis['strength_percentage'] = 30
    else:
        analysis['strength_level'] = "Very Weak"
        analysis['strength_color'] = "danger"
        analysis['strength_percentage'] = 15
    
    # Generate recommendations
    recommendations = []
    if analysis['length'] < 12:
        recommendations.append("Use at least 12 characters")
    if not analysis['has_uppercase']:
        recommendations.append("Include uppercase letters (A-Z)")
    if not analysis['has_lowercase']:
        recommendations.append("Include lowercase letters (a-z)")
    if not analysis['has_numbers']:
        recommendations.append("Include numbers (0-9)")
    if not analysis['has_symbols']:
        recommendations.append("Include special symbols (!@#$%)")
    if analysis['has_sequential']:
        recommendations.append("Avoid sequential characters (123, abc)")
    if analysis['has_repeated_patterns']:
        recommendations.append("Avoid repeated characters (aaa, 111)")
    if analysis['has_keyboard_patterns']:
        recommendations.append("Avoid common keyboard patterns")
    if analysis['unique_chars'] < analysis['length'] * 0.7:
        recommendations.append("Use more unique characters")
    
    if not recommendations:
        recommendations.append("Excellent password strength!")
    
    analysis['recommendations'] = recommendations
    analysis['score'] = min(100, max(0, int(analysis['entropy'] * 1.5)))
    
    return analysis

def generate_salt(length=16, custom_chars=None):
    """
    Generate a cryptographically secure salt
    """
    if custom_chars:
        chars = custom_chars
    else:
        chars = string.ascii_letters + string.digits + "!@#$%^&*"
    
    return ''.join(secrets.choice(chars) for _ in range(length))

def apply_salt(password, salt, method):
    """
    Apply salt to password using specified method
    """
    methods = {
        'prefix': f"{salt}{password}",
        'suffix': f"{password}{salt}",
        'sandwich': f"{salt}{password}{salt}",
    }
    
    return methods.get(method, f"{salt}{password}")

def hash_password(password):
    """
    Create SHA-256 hash of password
    """
    return hashlib.sha256(password.encode()).hexdigest()

def calculate_time_to_crack(password):
    """
    Estimate time to crack password
    """
    charset_size = 0
    
    if re.search(r'[a-z]', password):
        charset_size += 26
    if re.search(r'[A-Z]', password):
        charset_size += 26
    if re.search(r'\d', password):
        charset_size += 10
    if re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]', password):
        charset_size += 32
    
    if charset_size == 0:
        return "Unable to calculate"
    
    # Assume 1 billion attempts per second (modern GPU)
    total_combinations = charset_size ** len(password)
    average_attempts = total_combinations / 2
    seconds = average_attempts / 1_000_000_000
    
    if seconds < 60:
        return f"{seconds:.2f} seconds"
    elif seconds < 3600:
        return f"{seconds/60:.2f} minutes"
    elif seconds < 86400:
        return f"{seconds/3600:.2f} hours"
    elif seconds < 31536000:
        return f"{seconds/86400:.2f} days"
    elif seconds < 31536000000:
        return f"{seconds/31536000:.2f} years"
    else:
        return "Millions of years"