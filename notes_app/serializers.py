from rest_framework import serializers
from .models import Subscription
from django.contrib.auth.models import User

class SubscriptionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Subscription
        fields = ('id', 'name', 'description', 'currency',
            'amount', 'created_at', 'updated_at'
        )

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ("id", "username", "email")