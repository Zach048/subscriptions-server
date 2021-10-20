from django.contrib.auth.models import User
from django.contrib.auth.backends import BaseBackend


class JohnsHopkinsAuth(BaseBackend):

    def authenticate(self, username):
        user = None
        user, created = User.objects.get_or_create(username=username)
        if created:
            user.set_unusable_password()
        return user

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None
