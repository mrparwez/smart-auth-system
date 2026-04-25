from django.contrib import admin
from .models import CustomUser

#  Register your models here.
@admin.register(CustomUser)
class CustomUserAdmin(admin.ModelAdmin):
    list_display = ('email', 'username', 'risk_score', 'last_login_ip')
    search_fields=('email','username')
    list_filter=('is_staff','is_active')