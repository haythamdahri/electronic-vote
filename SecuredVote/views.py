import os
import tempfile

from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.files import File
from django.core.paginator import Paginator
from django.db.models import Q, Count
from django.shortcuts import render, redirect
from django.urls import reverse
from django.views import View

from ElectronicVote.settings import BASE_DIR
from SecuredVote import utils
from SecuredVote.forms import LoginForm
# --------------- Home ---------------
from SecuredVote.models import Candidate, Vote, Voter, Pending


class Home(View):

    def get(self, request, *args, **kwargs):
        context = dict()
        search = request.GET.get("search" or None)
        if search is not None:
            candidates = Candidate.objects.filter(
                Q(user__first_name__contains=search) | Q(user__last_name__contains=search) |
                Q(user__username__contains=search) | Q(user__email__contains=search)
            )
        else:
            candidates = Candidate.objects.all()
        candidates = candidates.annotate(count=Count("vote__id")).order_by("-count")

        # Pagination
        paginator = Paginator(candidates, 2)  # Show 25 contacts per page
        page = request.GET.get("page")
        candidates = paginator.get_page(page)
        context["candidates"] = candidates
        return render(request, "vote/index.html", context)

    def post(self, request, *args, **kwargs):
        return redirect("vote:home")


# --------------- Login ---------------
class Login(View):
    def get(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            return redirect("vote:home")
        context = dict()
        context["login_form"] = LoginForm()
        return render(request, "vote/login.html", context)

    def post(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            return redirect("vote:home")
        context = dict()
        login_form = LoginForm(request.POST or None)
        if login_form.is_valid():
            user = authenticate(request, username=login_form.cleaned_data["email"],
                                password=login_form.cleaned_data["password"])
            if user is not None:
                login(request, user)
                redirect_url = request.POST.get("next", reverse("vote:home"))
                return redirect(redirect_url)
        else:
            messages.error(request, "Adresse email ou mot de passe non valide!")
        context["login_form"] = login_form

        return render(request, "vote/login.html", context)


# --------------- Login ---------------
class Logout(View):
    def get(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            logout(request)
            return redirect("vote:login")

    def post(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            logout(request)
            return redirect("vote:login")


# --------------- Profile ---------------
class Profile(LoginRequiredMixin, View):
    login_url = "/login/"
    redirect_field_name = "next"

    def get(self, request, *args, **kwargs):
        context = dict()
        voter = Voter.objects.get_or_create(user=request.user)[
            0]  # The method generate a voter and a boolean if created or not
        voter = utils.generate_keys(voter)
        context["voter"] = voter
        return render(request, "vote/profile.html", context)


# --------------- Make Vote ---------------
class MakeVote(LoginRequiredMixin, View):
    login_url = "/login/"
    redirect_field_name = "next"

    def get(self, request, *args, **kwargs):
        return redirect("vote:home")

    def post(self, request, *args, **kwargs):
        context = dict()
        try:
            candidate = Candidate.objects.filter(id=request.POST.get("candidate_id"))
            if candidate.exists():
                if not Vote.objects.filter(voter__user=request.user).exists():
                    candidate = candidate[0]
                    voter = Voter.objects.get(user=request.user)
                    pending = Pending.objects.create()
                    file = open(os.path.join(BASE_DIR) + "/media/" + "data.txt", "w+")
                    # encrypt voter id with user private key
                    # encrypt candidate id (Bulletin du vote) with DE public key(Only DE who can decrypt Voting results)
                    # encrypt files with user private key
                    # sign co_file and do_file for authentication
                    file.write(str(voter.pk) + "\n" + str(candidate.pk))

                    # Remove the file if exists to prevent space management problems
                    if os.path.exists(os.path.join(BASE_DIR) + "/media/" + voter.user.username + '_co_file.txt'):
                        os.remove(os.path.join(BASE_DIR) + "/media/" + voter.user.username + '_co_file.txt')
                    if os.path.exists(os.path.join(BASE_DIR) + "/media/" + voter.user.username + '_do_file.txt'):
                        os.remove(os.path.join(BASE_DIR) + "/media/" + voter.user.username + '_do_file.txt')

                    pending.co_file.save(voter.user.username + '_co_file.txt', File(file), save=True)
                    pending.do_file.save(voter.user.username + '_do_file.txt', File(file), save=True)
                    file.close()
                    pending.save()
                    messages.success(request, "Votre vote est ajouté avec succé!")
                    messages.success(request,
                                     "Votre vote sera pris en charge aussitôt qu'il sera verifié par les autorités!")
                else:
                    messages.warning(request, "Vous avez déja voté!")
            else:
                messages.warning(request, "Candidat non trouvé!")
        except Exception as ex:
            print(ex)
            messages.error(request, "Une erreur est survenue, veuillez ressayer!")
        return redirect("vote:home")
