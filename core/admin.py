from django.contrib import admin
# from .models import Member,Account,School
from .models import Account
# Register your models here.


# class MemberAdmin(admin.ModelAdmin):
#     list_display = [f.name for f in Member._meta.fields]
#
# admin.site.register(Member,MemberAdmin)


class AccountAdmin(admin.ModelAdmin):
    # todo account_profile should return fk model __str__
    list_display = ['email','full_name','account_type','account_profile','is_superuser','is_staff','is_active']
    list_filter = ('account_type',)

admin.site.register(Account,AccountAdmin)

#
# class SchoolAdmin(admin.ModelAdmin):
#     list_display = [f.name for f in School._meta.fields]
#
# admin.site.register(School,SchoolAdmin)
