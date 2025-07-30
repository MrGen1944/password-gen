from django.shortcuts import render
from django.http import JsonResponse
from .forms import PasswordGeneratorForm, PasswordEncryptForm, PasswordDecryptForm
from .utils import generate_password_from_form, encrypt_password, decrypt_password, log_usage
from .models import PasswordPolicy

def home(request):
    return render(request, 'passencrypt/home.html')

def generate_password(request):
    form = PasswordGeneratorForm()
    generated_password = None
    debug_info = None
    
    if request.method == 'POST':
        # Debug: Let's see what's being submitted
        debug_info = {
            'POST_data': dict(request.POST),
            'policy_selected': request.POST.get('use_policy'),
        }
        
        form = PasswordGeneratorForm(request.POST)
        
        # Check if a policy was selected
        policy_id = request.POST.get('use_policy')
        
        if policy_id:
            # Use predefined policy
            try:
                policy = PasswordPolicy.objects.get(id=policy_id)
                form_data = {
                    'min_length': policy.min_length,
                    'max_length': policy.max_length,
                    'include_uppercase': policy.include_uppercase,
                    'include_lowercase': policy.include_lowercase,
                    'include_numbers': policy.include_numbers,
                    'include_symbols': policy.include_symbols,
                    'exclude_similar': policy.exclude_similar,
                }
                debug_info['using_policy'] = policy.name
                debug_info['policy_settings'] = form_data
                generated_password = generate_password_from_form(form_data)
                log_usage('generate', request)
            except PasswordPolicy.DoesNotExist:
                debug_info['error'] = 'Policy not found'
                # Fall back to custom settings if policy doesn't exist
                if form.is_valid():
                    generated_password = generate_password_from_form(form.cleaned_data)
                    log_usage('generate', request)
                else:
                    debug_info['form_errors'] = form.errors
        else:
            # Use custom settings
            debug_info['using_custom'] = True
            if form.is_valid():
                debug_info['custom_settings'] = form.cleaned_data
                generated_password = generate_password_from_form(form.cleaned_data)
                log_usage('generate', request)
            else:
                debug_info['form_errors'] = form.errors
    
    return render(request, 'passencrypt/generate.html', {
        'form': form,
        'generated_password': generated_password,
    })

def encrypt_password_view(request):
    encrypt_form = PasswordEncryptForm()
    decrypt_form = PasswordDecryptForm()
    result = None
    action = None
    
    if request.method == 'POST':
        if 'encrypt' in request.POST:
            encrypt_form = PasswordEncryptForm(request.POST)
            if encrypt_form.is_valid():
                password = encrypt_form.cleaned_data['password']
                method = encrypt_form.cleaned_data['encryption_method']
                shift = encrypt_form.cleaned_data['shift_amount']
                
                result = encrypt_password(password, method, shift)
                action = 'encrypted'
                log_usage('encrypt', request)
        
        elif 'decrypt' in request.POST:
            decrypt_form = PasswordDecryptForm(request.POST)
            if decrypt_form.is_valid():
                encrypted_password = decrypt_form.cleaned_data['encrypted_password']
                method = decrypt_form.cleaned_data['encryption_method']
                shift = decrypt_form.cleaned_data['shift_amount']
                
                result = decrypt_password(encrypted_password, method, shift)
                action = 'decrypted'
                log_usage('decrypt', request)
    
    return render(request, 'passencrypt/encrypt.html', {
        'encrypt_form': encrypt_form,
        'decrypt_form': decrypt_form,
        'result': result,
        'action': action
    })

