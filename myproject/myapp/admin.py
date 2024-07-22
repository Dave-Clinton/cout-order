
from django.contrib import admin
from .models import Profile,Affidavit

class ProfileAdmin(admin.ModelAdmin):
    list_display = ('user', 'first_name', 'last_name')
    search_fields = ('user__username', 'first_name', 'last_name')

admin.site.register(Profile, ProfileAdmin)


class AffidavitAdmin(admin.ModelAdmin):
    list_display = ('profile','status' )
    search_fields = ('profile__user__username','status' )

admin.site.register(Affidavit, AffidavitAdmin)



