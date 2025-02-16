from django.contrib import admin
from .models import Advertisement, UserWallet,Proof, UserTransaction, UserProfile, Notification

admin.site.register(Advertisement)
admin.site.register(UserWallet)
admin.site.register(UserTransaction)
admin.site.register(UserProfile)
admin.site.register(Notification)
admin.site.register(Proof)

