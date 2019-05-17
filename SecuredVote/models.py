from django.contrib.auth.models import User
from django.db import models

# Create your models here.
from django.utils.timezone import now


class Candidate(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    birth_date = models.DateTimeField(default=now, null=True)
    add_date = models.DateTimeField(default=now)

    def __str__(self):
        return self.user.first_name + " " + self.user.last_name + " | " + str(self.add_date)

    @property
    def votesCounter(self):
        counter = 0
        for vote in Vote.objects.filter(candidate_id=self.id, is_valid=True):
            counter += 1
        return counter

class Voter(models.Model):
    user = models.OneToOneField(User, unique=True, on_delete=models.CASCADE)
    birth_date = models.DateTimeField(default=now, null=True)
    public_key = models.CharField(max_length=1000, null=True)
    private_key = models.CharField(max_length=1000, null=True)

    def __str__(self):
        return self.user.first_name + " " + self.user.last_name + " | Public key: " + self.public_key +\
               " | Private key: " + self.private_key

class Pending(models.Model):
    co_file = models.FileField(null=False)
    do_file = models.FileField(null=False)
    date = models.DateTimeField(default=now)
    done = models.BooleanField(default=False)

    def __str__(self):
        return "Co file: " + self.co_file.name + " | Do file: " + self.do_file.name + " | Date: " + self.date.__str__()\
        + " | Done: " + str(self.done)

class Revision(models.Model):
    pending = models.ForeignKey(Pending, on_delete=models.CASCADE)
    do_file = models.FileField(null=False)
    date = models.DateTimeField(default=now)
    done = models.BooleanField(default=False)

    def __str__(self):
        return "Co file: " + self.co_file.name + " | Date: " + self.date.__str__()\
        + " | Done: " + str(self.done)

class Vote(models.Model):
    # Voter est le votant
    voter = models.ForeignKey(Voter, on_delete=models.CASCADE)
    vote_date = models.DateTimeField(default=now)
    candidate = models.ForeignKey(Candidate, on_delete=models.CASCADE, null=False)
    is_valid = models.BooleanField(default=False, null=True)

    def __str__(self):
        return self.voter.public_key + " | " + self.candidate.user.username + " | " + str(self.vote_date)
