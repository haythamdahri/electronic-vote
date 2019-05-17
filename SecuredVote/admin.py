from django.contrib import admin
from SecuredVote.models import Candidate, Voter, Vote, Pending, Revision

# Register your models here.

admin.site.register(Candidate)
admin.site.register(Voter)
admin.site.register(Vote)
admin.site.register(Pending)
admin.site.register(Revision)