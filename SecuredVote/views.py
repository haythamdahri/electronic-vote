from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.mixins import LoginRequiredMixin
from django.shortcuts import render, redirect
from django.urls import reverse
from django.views import View
from SecuredVote.forms import SearchForm, LoginForm


#--------------- Home ---------------
class Home(View):

    def get(self, request, *args, **kwargs):
        context = dict()
        search = request.GET.get('search')
        print(f'search: {search}')
        return render(request, 'vote/index.html', context)

#--------------- Login ---------------
class Login(View):
    def get(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            return redirect('vote:home')
        context = dict()
        context['login_form'] = LoginForm()
        return render(request, 'vote/login.html', context)

    def post(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            return redirect('vote:home')
        context = dict()
        login_form = LoginForm(request.POST or None)
        if login_form.is_valid():
            user = authenticate(request, username=login_form.cleaned_data['email'],
                                password=login_form.cleaned_data['password'])
            if user is not None:
                login(request, user)
                redirect_url = request.POST.get("next", reverse("vote:home"))
                return redirect(redirect_url)
        else:
            messages.error(request, "Adresse email ou mot de passe non valide!")
        context['login_form'] = login_form

        return render(request, 'vote/login.html', context)


#--------------- Login ---------------
class Logout(View):
    def get(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            logout(request)
            return redirect('vote:login')


    def post(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            logout(request)
            return redirect('vote:login')


#--------------- Profile ---------------
class Profile(LoginRequiredMixin, View):
    login_url = "/login/"
    redirect_field_name = "next"

    def get(self, request, *args, **kwargs):
        return render(request, 'vote/profile.html')

