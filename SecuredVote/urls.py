from django.contrib import admin
from django.urls import path, include
from . import views

app_name = "vote"

urlpatterns = [
    path('', views.Home.as_view(), name="home"),
    path('login/', views.Login.as_view(), name="login"),
    path('logout/', views.Logout.as_view(), name="logout"),
    path('profile/', views.Profile.as_view(), name="profile"),
    path('vote/', views.MakeVote.as_view(), name="make_vote"),
]
