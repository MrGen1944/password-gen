from django import forms
from .models import PasswordPolicy, EncryptionMethod

class PasswordGeneratorForm(forms.Form):
    # Use existing policy or custom settings
    use_policy = forms.ModelChoiceField(
        queryset=PasswordPolicy.objects.all(),
        empty_label="Custom Settings",
        required=False,
        widget=forms.Select(attrs={'class': 'form-control mb-3'})
    )
    
    min_length = forms.IntegerField(
        min_value=4, max_value=50, initial=8,
        widget=forms.NumberInput(attrs={'class': 'form-control'})
    )
    max_length = forms.IntegerField(
        min_value=4, max_value=50, initial=16,
        widget=forms.NumberInput(attrs={'class': 'form-control'})
    )
    include_uppercase = forms.BooleanField(
        required=False, initial=True,
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input'})
    )
    include_lowercase = forms.BooleanField(
        required=False, initial=True,
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input'})
    )
    include_numbers = forms.BooleanField(
        required=False, initial=True,
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input'})
    )
    include_symbols = forms.BooleanField(
        required=False, initial=True,
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input'})
    )
    exclude_similar = forms.BooleanField(
        required=False, initial=False,
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input'})
    )

class PasswordEncryptForm(forms.Form):
    password = forms.CharField(
        max_length=200,
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter password to encrypt'
        })
    )
    encryption_method = forms.ChoiceField(
        choices=[
            ('caesar', 'Caesar Cipher (Simple)'),
            ('reverse', 'Reverse Text'),
            ('base64', 'Base64 Encoding'),
            ('rot13', 'ROT13'),
        ],
        widget=forms.Select(attrs={'class': 'form-control'})
    )
    shift_amount = forms.IntegerField(
        min_value=1, max_value=25, initial=3,
        widget=forms.NumberInput(attrs={'class': 'form-control'}),
        help_text="Only used for Caesar Cipher"
    )

class PasswordDecryptForm(forms.Form):
    encrypted_password = forms.CharField(
        max_length=200,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter encrypted text to decrypt'
        })
    )
    encryption_method = forms.ChoiceField(
        choices=[
            ('caesar', 'Caesar Cipher (Simple)'),
            ('reverse', 'Reverse Text'),
            ('base64', 'Base64 Encoding'),
            ('rot13', 'ROT13'),
        ],
        widget=forms.Select(attrs={'class': 'form-control'})
    )
    shift_amount = forms.IntegerField(
        min_value=1, max_value=25, initial=3,
        widget=forms.NumberInput(attrs={'class': 'form-control'}),
        help_text="Only used for Caesar Cipher"
    )

class PasswordStrengthForm(forms.Form):
    password = forms.CharField(
        max_length=200,
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter password to analyze',
            'id': 'password-input'
        })
    )
    show_password = forms.BooleanField(
        required=False,
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input'}),
        help_text="Show password in plain text"
    )

class PasswordSaltingForm(forms.Form):
    password = forms.CharField(
        max_length=200,
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter password to salt'
        })
    )
    salt_method = forms.ChoiceField(
        choices=[
            ('prefix', 'Prefix Salt (salt + password)'),
            ('suffix', 'Suffix Salt (password + salt)'),
            ('sandwich', 'Sandwich Salt (salt + password + salt)'),
            # Remove the 'custom' option
        ],
        widget=forms.Select(attrs={'class': 'form-control'})
    )
    custom_salt = forms.CharField(
        max_length=50,
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter custom salt (leave empty for auto-generated)'
        }),
        help_text="Leave empty to auto-generate a secure salt"
    )
    salt_length = forms.IntegerField(
        min_value=4, max_value=32, initial=16,
        widget=forms.NumberInput(attrs={'class': 'form-control'}),
        help_text="Length of auto-generated salt (4-32 characters)"
    )
    hash_result = forms.BooleanField(
        required=False,
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input'}),
        help_text="Apply SHA-256 hash to the salted password"
    )