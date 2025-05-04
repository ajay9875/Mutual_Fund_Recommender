from django.db import models
from django.contrib.auth.models import User
from django.conf import settings

class MutualFund(models.Model):
    name = models.CharField(max_length=255)
    category = models.CharField(max_length=255)  
    risk = models.CharField(max_length=50, choices=[('low', 'Low'), ('medium', 'Medium'), ('high', 'High')])
    return_rate = models.DecimalField(max_digits=5, decimal_places=2)  
    duration = models.CharField(
        max_length=50, 
        choices=[('1_year', '1 Year'), ('3_years', '3 Years'), ('5_years', '5+ Years')],
        default='3_years'  # Provide a default value
    )
    investment_type = models.CharField(
        max_length=50,
        choices=[('lump_sum', 'Lump Sum'), ('sip', 'SIP')],
        default='sip'  # Provide a default value
    )
    profit_type = models.CharField(
        max_length=50,
        choices=[('high', 'High'), ('medium', 'Medium'), ('low', 'Low')],
        default='medium'  # Provide a default value
    )

    def __str__(self):
        return self.name
        
# Create your models here.
class Contact(models.Model):
    name = models.CharField(max_length=100)
    phone = models.CharField(max_length=15)
    email = models.EmailField()
    message = models.TextField()
    date = models.DateTimeField()

    def __str__(self):
        return self.name

from django.db import models
from django.contrib.auth.models import User

class ProfilePic(models.Model):
    username = models.OneToOneField(User, on_delete=models.CASCADE)  # Link to User model
    filename = models.ImageField(upload_to="media/", default="default_profile.png")

    def __str__(self):
        return self.username.username

