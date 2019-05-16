from django.contrib.auth.models import User
from django.db import models

# Create your models here.
from django.utils.timezone import now


class Voter(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    pub_key = models.CharField(max_length=1000, null=False)
    private_key = models.CharField

class Vote(models.Model):
    # Voter est le votant
    voter = models.ForeignKey(Voter, on_delete=models.CASCADE)
    vote_date = models.DateTimeField(default=now)
    file = models.FileField(null=False)