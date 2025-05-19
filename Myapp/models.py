from django.db import models
from django.contrib.auth.models import User
from django.conf import settings

class MutualFund(models.Model):
    username = models.CharField(max_length=255)
    fund_name = models.CharField(max_length=255)
    investment_type = models.CharField(max_length=100, null=True, blank=True)
    subcategory = models.CharField(max_length=100, null=True, blank=True)

    def __str__(self):
        return self.fund_name
        
# Create your models here.
class Contact(models.Model):
    name = models.CharField(max_length=100)
    phone = models.CharField(max_length=15)
    email = models.EmailField()
    message = models.TextField()
    date = models.DateTimeField()

    def __str__(self):
        return self.name

class ProfilePic(models.Model):
    username = models.OneToOneField(User, on_delete=models.CASCADE)  # Link to User model
    filename = models.ImageField(upload_to="media/", default="default_profile.png")

    def __str__(self):
        return self.username.username
