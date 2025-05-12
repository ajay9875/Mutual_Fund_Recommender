from django.contrib import admin
from django.urls import path
from Myapp import views
from django.conf import settings
from django.conf.urls.static import static
from . import views

 # Ensure all views are imported for another routing

handler404 = 'your_app.views.custom_404_view'

urlpatterns = [
    path('', views.default, name='default'),  # First hit goes to dashboard
    path('dashboard/', views.userdashboard, name='dashboard'),  # Dashboard for logged-in users
    path('landing_page/', views.landing_page, name='landing_page'),  # New URL
    path("login/", views.loginUser, name='login'),
    path("logout/", views.logoutUser, name='logout'),
    path("about/", views.about, name='about'),
    path("services/", views.services, name='services'),
    path("contact/", views.contact, name='contact'),
    path("forgetpass/", views.forgetpassword, name='forgetpass'),
    path("verifyotp/", views.verifyOTP, name='verifyotp'),
    path("resetpass/", views.resetpassword, name='resetpass'),
    path("forgetusername/", views.forgetusername, name='forgetusername'),
    path("newuser/", views.newuser, name='newuser'),
    path("account_settings/", views.account_settings, name="account_settings"),
    path("delete_account/", views.delete_account, name="delete_account"),

    path('tasks/', views.task_list, name='task_list'),

    path('fund-details/', views.fund_details, name='fund_details'),
    path('sip-calculator/', views.sip_calculator, name='sip_calculator'),

    # If you want to use `nav_data_api`
    #path('api/nav-data/', views.nav_data_api, name='nav_data_api'),  

    # Or, if you want to use `nav_data_view`
    # path('api/nav-data/', views.nav_data_view, name='nav-data'),

    # Other paths
    #path('nav-chart/', views.nav_chart_page, name='nav_chart'), # Ensure this is correctly mapped
]
