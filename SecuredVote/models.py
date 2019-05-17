from django.contrib.auth.models import User
from django.db import models
from django.utils.timezone import now
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding


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
    public_key = models.FileField(max_length=1000, unique=True, null=True)
    private_key = models.FileField(max_length=1000, unique=True, null=True)
    is_voted = models.BooleanField(default=False)

    def __str__(self):
        return self.user.first_name + " " + self.user.last_name + " | Public key: " + self.public_key.name + \
               " | Private key: " + self.private_key.name

    @property
    def private_key_text(self):
        try:
            # Reading Keys
            with open(self.private_key.path, "rb") as key_file:
                private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None,
                    backend=default_backend()
                )
                pem = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
                return pem.decode("UTF-8")
        except Exception as e:
            print(e)
            return None

    @property
    def public_key_text(self):
        try:
            with open(self.public_key.path,"rb") as key_file:
                public_key = serialization.load_pem_public_key(
                    key_file.read(),
                    backend=default_backend()
                )
                pem = public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                return pem.decode("UTF-8")
        except:
            return None


class Signature(models.Model):
    sig = models.BinaryField(max_length=10000, null=False, blank=False)
    message = models.BinaryField(max_length=10000, null=False, blank=False)
    public_key = models.FileField(max_length=10000, null=False, blank=False)
    is_valid = models.BooleanField(default=None, null=True, blank=True)

    def __str__(self):
        return "Signature: " + str(self.sig) + " | Message: " + str(self.message) + " | Public key: " + self.public_key.name


class Pending(models.Model):
    # Sent to CO from the voter
    co_file = models.FileField(null=False)
    # Sent to DO from the voter
    do_file = models.FileField(null=False)
    date = models.DateTimeField(default=now)
    done = models.BooleanField(default=False)
    signature = models.ForeignKey(Signature, on_delete=models.CASCADE)

    def __str__(self):
        return "Co file: " + self.co_file.name + " | Do file: " + self.do_file.name + " | Date: " + self.date.__str__() \
               + " | Done: " + str(self.done) + " | Signature: " + self.signature.__str__()


class Revision(models.Model):
    pending = models.ForeignKey(Pending, on_delete=models.CASCADE)
    # Sent to DO from CO
    do_file = models.FileField(null=False)
    date = models.DateTimeField(default=now)
    done = models.BooleanField(default=False)

    def __str__(self):
        return "Co file: " + self.co_file.name + " | Date: " + self.date.__str__() \
               + " | Done: " + str(self.done)


class Vote(models.Model):
    # Voter est le votant
    voter = models.ForeignKey(Voter, on_delete=models.CASCADE)
    vote_date = models.DateTimeField(default=now)
    candidate = models.ForeignKey(Candidate, on_delete=models.CASCADE, null=False)
    is_valid = models.BooleanField(default=False, null=True)

    def __str__(self):
        return self.voter.public_key + " | " + self.candidate.user.username + " | " + str(self.vote_date)
