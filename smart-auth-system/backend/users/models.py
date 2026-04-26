from django.contrib.auth.models import AbstractUser
from django.utils import timezone
from django.conf import settings
from django.db import models

class CustomUser(AbstractUser):
    email = models.EmailField(unique=True)
    device_info = models.CharField(max_length=255,blank=True,null=True)
    last_login_ip=models.GenericIPAddressField(blank=True,null=True)
    risk_score = models.FloatField(default=0.0)
    is_locked = models.BooleanField(default=False)
    failed_attempts =models.IntegerField(default=0)
    lock_until=models.DateTimeField(null=True,blank=True)

    USERNAME_FIELD='email'
    REQUIRED_FIELDS=['username']

    def __str__(self):
        return self.email
    
class LoginHistory(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    ip_address = models.CharField(max_length=50)
    user_agent = models.TextField(blank=True, null=True)
    login_time = models.DateTimeField(auto_now_add=True)
    is_suspicious = models.BooleanField(default=False)
    location = models.CharField(max_length=100, blank=True, null=True)
    device_fingerprint = models.CharField(max_length=255, blank=True, null=True)
    location = models.CharField(max_length=100, blank=True, null=True)
    login_status = models.CharField(max_length=20, default="SUCCESS")
    risk_reason = models.TextField(blank=True, null=True)

    def __str__(self):
        return f"{self.user}"

class LoginAttempt(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, null=True, blank=True)
    email = models.EmailField()
    ip_address = models.CharField(max_length=50)
    success = models.BooleanField(default=False)
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.email

