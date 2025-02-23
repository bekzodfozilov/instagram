from django.contrib import admin
from django.contrib import admin
from post.admin import PostInline

from .models import User, UserConfirmation


# Register your models here.

class UserAdminModel(admin.ModelAdmin):
    list_display = ['username', 'email', 'phone_number']
    inlines = [PostInline]



class UserConfirmationModel(admin.ModelAdmin):
    list_display = []



admin.site.register(User, UserAdminModel)
admin.site.register(UserConfirmation)



