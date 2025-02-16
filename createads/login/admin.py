from django.contrib import admin
from .models import User, AdminSettings, Notification

admin.site.register(User)
admin.site.register(AdminSettings)
admin.site.register(Notification)


