from django.db import models

class Subscription(models.Model):
    name = models.CharField(max_length=255)
    description = models.TextField()
    currency = models.CharField(max_length=255)
    amount = models.IntegerField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


    def str(self):
        return self.name