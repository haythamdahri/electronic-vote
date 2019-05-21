from django.contrib import admin
from django.contrib.admin import AdminSite
from django.utils.translation import ugettext_lazy

from SecuredVote.models import Candidate, Voter, Vote, Pending, Revision, Signature


# Register your models here.
admin.site.site_header = "Vote Sécurisé"
admin.site.site_title = "Vote Sécurisé"
admin.site.index_title = "Bienvenue Au Vote Sécurisé"

admin.site.register(Candidate)
admin.site.register(Voter)
admin.site.register(Vote)
admin.site.register(Pending)
admin.site.register(Revision)
admin.site.register(Signature)
