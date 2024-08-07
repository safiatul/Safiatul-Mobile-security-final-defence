from django.urls import path
from . import views
from django.contrib.auth import views as auth_views
urlpatterns = [
path("", views.Index.as_view(),name="index"),
path("login", views.Login.as_view(),name="login"),
path('signup/', views.Signup.as_view(), name='signup'),
path("dashboard", views.Dashboard.as_view(),name="dashboard"),
path('logout/', views.logout, name='logout'),
]