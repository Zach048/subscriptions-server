from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils.translation import ugettext_lazy as _

class Subscription(models.Model):
    name = models.CharField(max_length=255)
    description = models.TextField()
    currency = models.CharField(max_length=255)
    amount = models.IntegerField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


    def str(self):
        return self.name


# class CustomUser(AbstractUser):
#     class Meta:
#         verbose_name = _("user")
#         verbose_name_plural = _("users")
#     username = models.CharField(max_length=255, default='google_user')
#     email = models.EmailField(_("email address"), unique=True)
#
#     USERNAME_FIELD = "email"
#     REQUIRED_FIELDS = []
#
#     def __str__(self):
#         return self.email
