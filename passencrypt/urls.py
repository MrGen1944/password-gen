from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='home'),
    path('generate/', views.generate_password, name='generate'),
    path('encrypt/', views.encrypt_password_view, name='encrypt'),
    path('tools/', views.password_tools, name='password_tools'),
]