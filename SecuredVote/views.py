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
from SecuredVote.models import Candidate, Vote, Voter, Pending, Signature


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
        paginator = Paginator(candidates, 2)  # Show 2 candidates per page (Temprory until having a good number of candidates)
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
                if not Vote.objects.filter(voter__user=request.user).exists() and Voter.objects.filter(user=request.user).exists() and not Voter.objects.get(user=request.user).is_voted:
                    candidate = candidate[0]
                    voter = Voter.objects.get_or_create(user=request.user)[0]

                    # encrypt voter id with user private key
                    # encrypt candidate id (Bulletin du vote) with DE public key(Only DE who can decrypt Voting results)
                    # encrypt files with user private key
                    # sign co_file and do_file for authentication
                    co_file, do_file, signature = utils.encrypt_data(voter, candidate)

                    # Create a new pending vote even if the user has already voted
                    # The last vote is only the one which will be decrypted and used for operation process
                    pending = Pending.objects.create(signature=signature)

                    # Remove the file if exists to prevent space management problems
                    if os.path.exists(os.path.join(BASE_DIR) + "/media/" + voter.user.username + '_co_file.encrypt'):
                        os.remove(os.path.join(BASE_DIR) + "/media/" + voter.user.username + '_co_file.encrypt')
                    if os.path.exists(os.path.join(BASE_DIR) + "/media/" + voter.user.username + '_do_file.encrypt'):
                        os.remove(os.path.join(BASE_DIR) + "/media/" + voter.user.username + '_do_file.encrypt')

                    # Save co and do files on pending recored
                    # Set the associated signature
                    pending.co_file.save(voter.user.username + '_co_file.encrypt', File(co_file), save=True)
                    pending.do_file.save(voter.user.username + '_do_file.encrypt', File(do_file), save=True)
                    co_file.close()
                    do_file.close()
                    pending.save()

                    # Park the voter as voted
                    voter.is_voted = True
                    voter.save()


                    messages.success(request, "Votre vote est ajouté avec succé!")
                    messages.success(request,
                                     "Votre vote sera pris en charge aussitôt qu'il sera verifié par les autorités!")
                else:
                    messages.warning(request, "Vous avez déja voté!")
            else:
                messages.warning(request, "Candidat non trouvé!")
        except Exception as ex:
            print(ex)
            # Delete the lest created pending if exists
            try:
                Pending.objects.last().delete()
            except:
                pass
            messages.error(request, "Une erreur est survenue, veuillez ressayer!")
        return redirect("vote:home")

# --------------- Manage Votes ---------------
class Manage(LoginRequiredMixin, View):
    login_url = "/login/"
    redirect_field_name = "next"

    def get(self, request, *args, **kwargs):
        context = dict()
        user = request.user
        if not user.is_superuser and user.is_staff:
            search = request.GET.get("search" or None)
            if search is not None:
                try:
                    pendings = Pending.objects.filter(id=search)
                except:
                    pendings = []
            else:
                pendings = Pending.objects.all()
            # Pagination
            paginator = Paginator(pendings, 2)  # Show 2 pending votes per page
            page = request.GET.get("page")
            pendings = paginator.get_page(page)
            context["pendings"] = pendings
            return render(request, "vote/manage.html", context)
        messages.info(request, "Vous êtes membre du centre de dépouillement!")
        return redirect("vote:home")


# --------------- Verify Signature Votes ---------------
class VerifySignature(LoginRequiredMixin, View):
    login_url = "/login/"
    redirect_field_name = "next"

    def get(self, request, *args, **kwargs):
        return redirect("vote:manage_votes")

    def post(self, request, *args, **kwargs):
        user = request.user
        if not user.is_superuser and user.is_staff:
            signature_id = request.POST.get('signature_id' or None)
            if signature_id is not None:
                signature = Signature.objects.filter(id=signature_id)
                if signature.exists():
                    signature = signature[0]

                    # Verify signature using utils
                    if utils.verify_signature(signature):
                        messages.success(request, "Signature est verifié avec succé")
                        return redirect("vote:manage_votes")

            messages.error(request, "Signature non valide!")
            return redirect("vote:manage_votes")
        messages.info(request, "Vous êtes membre du centre de dépouillement!")
        return redirect("vote:home")


# --------------- Mark And Transfer Vote ---------------
class TransferVote(LoginRequiredMixin, View):
    login_url = "/login/"
    redirect_field_name = "next"

    def get(self, request, *args, **kwargs):
        return redirect("vote:manage_votes")

    def post(self, request, *args, **kwargs):
        user = request.user
        if not user.is_superuser and user.is_staff:
            pending_id = request.POST.get('pending_id')
            pending = Pending.objects.filter(pk=pending_id)
            if pending.exists():
                pending = pending[0]
                voter, candidate = utils.decrypt_pending(pending)
                messages.success(request, "Le vote est marqué avec succé!")
                return redirect("vote:manage_votes")
            messages.error(request, "Vote inexistant!")
            return redirect("vote:manage_votes")
        messages.info(request, "Vous êtes membre du centre de dépouillement!")
        return redirect("vote:home")














