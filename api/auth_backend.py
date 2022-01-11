from django.contrib.auth.models import User
from django.contrib.auth.backends import BaseBackend
import requests
import os


class JohnsHopkinsAuth(BaseBackend):

    def authenticate(self, username):
        user_data_url = 'https://api.jh.edu/internal/v3/data/user/id/' + username
        headers = {'client_id': os.environ.get('JHU_CLIENT_ID'),
                   'client_secret': os.environ.get('JHU_SECRET')}
        response = requests.get(user_data_url, headers=headers).json()
        if response['department'] == 'KSAS - Centers for Civic Impact':
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
