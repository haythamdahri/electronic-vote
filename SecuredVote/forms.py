from django import forms
from django.contrib.auth.models import User


class SearchForm(forms.Form):
    search = forms.CharField(max_length=255, empty_value=False, widget=forms.TextInput(
        attrs={'class': 'form-control mr-sm-2', 'placeholder': 'Chercher ...', 'aria-label': 'Search',
               'type': 'search'}))

class LoginForm(forms.ModelForm):
    email = forms.EmailField(max_length=250, widget=forms.EmailInput(attrs={'class': 'form-control', 'placeholder': 'Enter email', 'aria-label': 'Enter email'}))
    password = forms.CharField(max_length=250, widget=forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': 'Password', 'aria-label': 'Password'}))
    class Meta:
        model = User
        fields = ['email', 'password']

    def clean(self):
        cleaned_data = super().clean()
        email = cleaned_data.get('email')
        password = cleaned_data.get('password')
        user = User.objects.filter(email=email)
        if user.exists():
            user = user.first()
            if not user.check_password(password):
                self.add_error('password', 'Mot de passe non valide!')
        else:
            self.add_error('email', 'Adresse email non valide!')
