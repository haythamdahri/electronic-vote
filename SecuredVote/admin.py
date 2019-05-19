from django.contrib import admin
from django.contrib.admin import AdminSite
from django.utils.translation import ugettext_lazy

from SecuredVote.models import Candidate, Voter, Vote, Pending, Revision, Signature


# Register your models here.
class MyAdminSite(AdminSite):
    # Text to put at the end of each page's <title>.
    site_title = ugettext_lazy('Administration Vote Électronique Sécurisé')

    # Text to put in each page's <h1> (and above login form).
    site_header = ugettext_lazy('Administration Vote Électronique Sécurisé')

    # Text to put at the top of the admin index page.
    index_title = ugettext_lazy('Administration Vote Électronique Sécurisé')


admin_site = MyAdminSite()

admin.site.register(Candidate)
admin.site.register(Voter)
admin.site.register(Vote)
admin.site.register(Pending)
admin.site.register(Revision)
admin.site.register(Signature)
