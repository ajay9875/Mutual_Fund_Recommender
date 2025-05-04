from django.contrib import admin
from django.urls import path
from Myapp import views
from django.conf import settings
from django.conf.urls.static import static
from django.urls import path

 # Ensure all views are imported for another routing

handler404 = 'your_app.views.custom_404_view'

urlpatterns = [
    path('', views.default, name='default'),  # First hit goes to dashboard
    path('mutul_fund_recommender/dashboard/', views.userdashboard, name='dashboard'),  # Dashboard for logged-in users
    path('mutual_fund_recommender/landing_page/', views.landing_page, name='landing_page'),  # New URL
    path("mutual_fund_recommender/login/", views.loginUser, name='login'),
    path("logout/", views.logoutUser, name='logout'),
    path("mutul_fund_recommender/about/", views.about, name='about'),
    path("mutul_fund_recommender/services/", views.services, name='services'),
    path("mutul_fund_recommender/contact/", views.contact, name='contact'),
    path("mutul_fund_recommender/forgetpass/", views.forgetpassword, name='forgetpass'),
    path("mutul_fund_recommender/verifyotp/", views.verifyOTP, name='verifyotp'),
    path("mutul_fund_recommender/resetpass/", views.resetpassword, name='resetpass'),
    path("mutul_fund_recommender/forgetusername/", views.forgetusername, name='forgetusername'),
    path("mutul_fund_recommender/newuser/", views.newuser, name='newuser'),
    path("mutul_fund_recommender/account_settings/", views.account_settings, name="account_settings"),
    path("mutul_fund_recommender/delete_account/", views.delete_account, name="delete_account"),

]
