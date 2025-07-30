PassEncrypt - A Django Password Tool
A modern Django web application for secure password generation and encryption with a RESTful API.

Password Generation
Password Encryption 
Modern UI
RESTful API
Clientside processing, no server password storage

Installation Prerequisites
Python 3.10+
pip (Python package manager)

Setup

Clone the repository
bashgit clone https://github.com/yourusername/password-tool.git
cd password-tool

Create virtual environment
bashpython -m venv password_tool_env 
or use your global dependecies
Install dependencies
bashpip install -r requirements.txt

Run migrations
bashpython manage.py migrate

Create superuser
bashpython manage.py createsuperuser

Start development server
bashpython manage.py runserver

Visit the application

Web Interface: http://127.0.0.1:8000/
Admin Panel: http://127.0.0.1:8000/admin/
API Documentation: http://127.0.0.1:8000/api/

Public Endpoints

GET /api/ - API information
POST /api/generate/ - Generate password
POST /api/encrypt/ - Encrypt password
POST /api/decrypt/ - Decrypt password
POST /api/strength/ - Check password strength

Possible Future Enhancements

 AES encryption support
 Password history (encrypted)
 Batch password generation
 Mobile app integration
 Advanced password policies
 Export functionality

How to Contribute

Fork the repository
Create a feature branch
Make your changes
Submit a pull request

License
This project is created for educational purposes. It is my final project of CS-225 at Bunker Hill Community College, MA.

GitHub: MrGen1944
Email: mrgenares@gmail.com