# PassEncrypt - Django Password Security Tool

A modern Django web application for secure password generation, encryption, and analysis with a complete REST API.

## Features

### 🔐 Password Generation
- Customizable password length and character sets
- Predefined security policies
- Exclude similar characters option
- Instant secure generation

### 🛡️ Password Encryption & Decryption
- Caesar Cipher with custom shift amounts
- Base64 Encoding
- ROT13 Encryption
- Text Reversal
- Easy encrypt/decrypt interface

### 🔍 Password Analysis & Salting *(New in v1.1.0)*
- **Strength Analysis**: Visual strength meter with percentage scores
- **Entropy Calculation**: Mathematical security rating
- **Security Recommendations**: Personalized improvement suggestions
- **Password Salting**: Multiple methods (prefix, suffix, sandwich)
- **SHA-256 Hashing**: Irreversible password encryption
- **Time-to-Crack Estimates**: Security timeline projections

### 🌐 REST API
Complete RESTful API with endpoints for:
- Password generation with custom policies
- Encryption and decryption operations
- Password strength analysis
- Password salting and hashing
- Salt generation
- Rate limiting and authentication

### 🎨 Modern Interface
- Responsive design that works on all devices
- Dark/Light mode toggle with persistent storage
- Copy-to-clipboard functionality
- Auto-hide sensitive data for security
- Bootstrap-powered UI with custom styling

## Quick Start

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/password-tool.git
   cd password-tool
   ```

2. **Create virtual environment**
   ```bash
   python -m venv password_tool_env
   
   # Windows
   password_tool_env\Scripts\activate
   
   # Mac/Linux
   source password_tool_env/bin/activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Setup database**
   ```bash
   python manage.py migrate
   python manage.py createsuperuser
   ```

5. **Run the application**
   ```bash
   python manage.py runserver
   ```

6. **Access the application**
   - Web Interface: http://127.0.0.1:8000/
   - Admin Panel: http://127.0.0.1:8000/admin/
   - API Info: http://127.0.0.1:8000/api/

## API Usage Examples

### Generate a Password
```bash
curl -X POST http://127.0.0.1:8000/api/generate/ \
  -H "Content-Type: application/json" \
  -d '{"min_length": 16, "max_length": 20, "include_symbols": true}'
```

### Analyze Password Strength
```bash
curl -X POST http://127.0.0.1:8000/api/analyze/ \
  -H "Content-Type: application/json" \
  -d '{"password": "MyTestPassword123!"}'
```

### Salt a Password
```bash
curl -X POST http://127.0.0.1:8000/api/salt/ \
  -H "Content-Type: application/json" \
  -d '{
    "password": "mypassword",
    "salt_method": "sandwich",
    "hash_result": true
  }'
```

## Technology Stack

- **Backend**: Django 5.2.4, Django REST Framework
- **Database**: SQLite (development), PostgreSQL (production ready)
- **Frontend**: HTML5, CSS3, JavaScript, Bootstrap 5
- **Security**: JWT Authentication, Rate Limiting, CORS Protection
- **API**: RESTful architecture with comprehensive endpoints

## Security Features

✅ **No Password Storage** - All processing happens client-side  
✅ **Rate Limiting** - Prevents abuse of API endpoints  
✅ **Input Validation** - Comprehensive data sanitization  
✅ **CORS Protection** - Secure cross-origin requests  
✅ **Auto-Hide Results** - Sensitive data disappears after time limits  
✅ **Cryptographic Security** - Uses Python's `secrets` module  

## Project Structure

```
password_tool/
├── password_tool/          # Django project settings
├── passencrypt/            # Main application
│   ├── models.py          # Database models
│   ├── views.py           # Web interface views
│   ├── api_views.py       # REST API views
│   ├── forms.py           # Django forms
│   ├── utils.py           # Utility functions
│   └── templates/         # HTML templates
├── requirements.txt        # Python dependencies
└── README.md              # This file
```

## Version History

### v1.1.0 (Latest)
- Added password strength analysis with visual indicators
- Added password salting with multiple methods
- Added SHA-256 hashing capability
- Added entropy calculations and recommendations
- Added new REST API endpoints
- Enhanced UI/UX consistency

### v1.0.0
- Initial release with password generation
- Encryption/decryption functionality
- Basic REST API
- Admin interface
- Dark/light mode toggle

## Development

This project was developed as a final project demonstrating:
- Django web framework proficiency
- REST API development
- Modern web UI/UX design
- Security best practices
- Database modeling
- Authentication and authorization

## License

Educational project - developed for academic purposes.

---

**Built with Django** • **Powered by Security** • **Designed for Privacy**