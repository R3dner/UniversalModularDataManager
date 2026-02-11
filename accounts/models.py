from __future__ import annotations

from django.contrib.auth.models import AbstractUser
from django.core.exceptions import ValidationError
from django.db import models
from django.conf import settings
from django.utils import timezone
from datetime import timedelta


class AuthMode(models.TextChoices):
    LOCAL = "LOCAL", "Local only"
    AD = "AD", "Active Directory only"
    LOCAL_OR_AD = "LOCAL_OR_AD", "Local or AD"


class User(AbstractUser):
    """
    Użytkownik UMDM (logowanie do tej aplikacji).
    Core feature: możliwość uwierzytelniania przez AD per użytkownik.
    IDM (wnioski/uprawnienia do systemów) jest osobnym modułem i NIE miesza się tutaj.
    """

    auth_mode = models.CharField(
        max_length=20,
        choices=AuthMode.choices,
        default=AuthMode.LOCAL,
        db_index=True,
    )

    # szybki przełącznik (łatwo filtrować)
    ad_enabled = models.BooleanField(default=False, db_index=True)

    # UPN (user@domena) albo DOMAIN\\user – wpisujesz zgodnie z polityką firmy
    ad_identifier = models.CharField(
        max_length=255,
        blank=True,
        null=True,
        help_text="UPN (user@domain) lub DOMAIN\\user",
    )

    # przydatne operacyjnie (audit/zarządzanie)
    last_auth_source = models.CharField(
        max_length=16,
        blank=True,
        null=True,
        help_text="LOCAL / AD (informacyjnie, ustawiane przez backend auth)",
    )

    updated_at = models.DateTimeField(auto_now=True)

    must_change_password = models.BooleanField(
        default=False,
        help_text="Wymuś zmianę hasła przy następnym logowaniu.",
    )

    password_changed_at = models.DateTimeField(
        blank=True,
        null=True,
        help_text="Data ostatniej zmiany hasła.",
    )

    password_never_expires = models.BooleanField(
        default=False,
        help_text="Jeśli True, hasło nie wygasa.",
    )

    def is_password_expired(self) -> bool:
        """
        Sprawdza czy hasło wygasło (tylko dla LOCAL users).
        """
        if self.auth_mode != "LOCAL":
            return False

        if self.password_never_expires:
            return False

        if not self.password_changed_at:
            return True

        max_age_days = getattr(settings, "PASSWORD_MAX_AGE_DAYS", 90)
        expiration_date = self.password_changed_at + timedelta(days=max_age_days)

        return timezone.now() > expiration_date

    def clean(self):
        super().clean()

        if self.ad_enabled:
            if self.auth_mode == AuthMode.LOCAL:
                raise ValidationError({"auth_mode": "Gdy AD jest włączone, auth_mode nie może być LOCAL."})

        else:
            if self.auth_mode in (AuthMode.AD, AuthMode.LOCAL_OR_AD):
                # możesz to złagodzić, ale taki „guardrail” oszczędza bałagan
                raise ValidationError({"auth_mode": "Jeśli AD jest wyłączone, ustaw auth_mode=LOCAL."})

    def set_password(self, raw_password):
        super().set_password(raw_password)
        self.password_changed_at = timezone.now()
        self.must_change_password = False

    def __str__(self) -> str:
        return self.get_username()
