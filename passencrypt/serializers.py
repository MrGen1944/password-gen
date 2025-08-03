from rest_framework import serializers
from .models import PasswordPolicy, EncryptionMethod, UsageLog

class PasswordPolicySerializer(serializers.ModelSerializer):
    class Meta:
        model = PasswordPolicy
        fields = '__all__'
        read_only_fields = ('created_at',)

class EncryptionMethodSerializer(serializers.ModelSerializer):
    class Meta:
        model = EncryptionMethod
        fields = '__all__'

class UsageLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = UsageLog
        fields = '__all__'
        read_only_fields = ('timestamp',)

class PasswordGenerationRequestSerializer(serializers.Serializer):
    policy_id = serializers.IntegerField(required=False, allow_null=True)
    min_length = serializers.IntegerField(min_value=4, max_value=50, default=8)
    max_length = serializers.IntegerField(min_value=4, max_value=50, default=16)
    include_uppercase = serializers.BooleanField(default=True)
    include_lowercase = serializers.BooleanField(default=True)
    include_numbers = serializers.BooleanField(default=True)
    include_symbols = serializers.BooleanField(default=True)
    exclude_similar = serializers.BooleanField(default=False)
    
    def validate(self, data):
        if data['min_length'] > data['max_length']:
            raise serializers.ValidationError("min_length cannot be greater than max_length")
        
        # Check if at least one character type is selected
        char_types = [
            data.get('include_uppercase', False),
            data.get('include_lowercase', False),
            data.get('include_numbers', False),
            data.get('include_symbols', False)
        ]
        
        if not any(char_types):
            raise serializers.ValidationError("At least one character type must be selected")
        
        return data

class PasswordGenerationResponseSerializer(serializers.Serializer):
    password = serializers.CharField()
    length = serializers.IntegerField()
    strength_score = serializers.CharField()
    entropy = serializers.FloatField()
    timestamp = serializers.DateTimeField()

class PasswordEncryptionRequestSerializer(serializers.Serializer):
    password = serializers.CharField(max_length=200)
    encryption_method = serializers.ChoiceField(choices=[
        ('caesar', 'Caesar Cipher'),
        ('reverse', 'Reverse Text'),
        ('base64', 'Base64 Encoding'),
        ('rot13', 'ROT13'),
    ])
    shift_amount = serializers.IntegerField(min_value=1, max_value=25, default=3)

class PasswordEncryptionResponseSerializer(serializers.Serializer):
    encrypted_password = serializers.CharField()
    encryption_method = serializers.CharField()
    timestamp = serializers.DateTimeField()

class PasswordDecryptionRequestSerializer(serializers.Serializer):
    encrypted_password = serializers.CharField(max_length=500)
    encryption_method = serializers.ChoiceField(choices=[
        ('caesar', 'Caesar Cipher'),
        ('reverse', 'Reverse Text'),
        ('base64', 'Base64 Encoding'),
        ('rot13', 'ROT13'),
    ])
    shift_amount = serializers.IntegerField(min_value=1, max_value=25, default=3)

class PasswordDecryptionResponseSerializer(serializers.Serializer):
    decrypted_password = serializers.CharField()
    encryption_method = serializers.CharField()
    timestamp = serializers.DateTimeField()

class PasswordStrengthRequestSerializer(serializers.Serializer):
    password = serializers.CharField(max_length=200)

class PasswordStrengthResponseSerializer(serializers.Serializer):
    password_length = serializers.IntegerField()
    strength_score = serializers.CharField()
    entropy = serializers.FloatField()
    has_uppercase = serializers.BooleanField()
    has_lowercase = serializers.BooleanField()
    has_numbers = serializers.BooleanField()
    has_symbols = serializers.BooleanField()
    recommendations = serializers.ListField(child=serializers.CharField())

class PasswordSaltingRequestSerializer(serializers.Serializer):
    password = serializers.CharField(max_length=200)
    salt_method = serializers.ChoiceField(choices=[
        ('prefix', 'Prefix Salt'),
        ('suffix', 'Suffix Salt'),
        ('sandwich', 'Sandwich Salt'),
    ])
    custom_salt = serializers.CharField(max_length=50, required=False, allow_blank=True)
    salt_length = serializers.IntegerField(min_value=4, max_value=32, default=16)
    hash_result = serializers.BooleanField(default=False)

class PasswordSaltingResponseSerializer(serializers.Serializer):
    original_password = serializers.CharField()
    salt = serializers.CharField()
    salt_method = serializers.CharField()
    salted_password = serializers.CharField()
    final_result = serializers.CharField()
    is_hashed = serializers.BooleanField()
    strength_improvement = serializers.DictField()
    timestamp = serializers.DateTimeField()

class SaltGenerationRequestSerializer(serializers.Serializer):
    length = serializers.IntegerField(min_value=4, max_value=64, default=16)
    custom_characters = serializers.CharField(max_length=200, required=False, allow_blank=True)

class SaltGenerationResponseSerializer(serializers.Serializer):
    salt = serializers.CharField()
    length = serializers.IntegerField()
    timestamp = serializers.DateTimeField()

class PasswordStrengthAnalysisResponseSerializer(serializers.Serializer):
    password_length = serializers.IntegerField()
    strength_level = serializers.CharField()
    strength_percentage = serializers.IntegerField()
    entropy = serializers.FloatField()
    character_analysis = serializers.DictField()
    security_analysis = serializers.DictField()
    recommendations = serializers.ListField(child=serializers.CharField())
    score = serializers.IntegerField()
    timestamp = serializers.DateTimeField()