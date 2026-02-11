from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as DjangoUserAdmin
from django.utils.translation import gettext_lazy as _

from .models import User


@admin.register(User)
class UserAdmin(DjangoUserAdmin):
    fieldsets = DjangoUserAdmin.fieldsets + (
        (_("Authentication"), {"fields": ("auth_mode", "ad_enabled", "ad_identifier", "last_auth_source")}),
    )
    list_display = DjangoUserAdmin.list_display + ("auth_mode", "ad_enabled", "ad_identifier", "last_auth_source")
    list_filter = DjangoUserAdmin.list_filter + ("auth_mode", "ad_enabled", "last_auth_source")
    search_fields = DjangoUserAdmin.search_fields + ("ad_identifier",)
