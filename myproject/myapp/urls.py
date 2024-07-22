from django.urls import path
from . import views  



urlpatterns = [
        path('', views.home, name='home'),
        path('register/', views.register, name='register'),
        path('login/', views.login_view, name='login'),
        path('logout/', views.logout_view, name='logout'),
        path('verify/', views.verify, name='verify'),
        path('file_new_case/', views.file_new_case, name='file_new_case'),  
        path('case_parties/', views.case_parties, name='case_parties'), 
        path('details/', views.details, name='details'),  
        path('stk_push/', views.stk_push, name='stk_push'),
        path('mpesa_stk_push/', views.mpesa_stk_push, name='mpesa_stk_push'),
        path('dashboard/', views.dashboard, name='dashboard'),  
        path('add_affidavit/<int:profile_id>/', views.add_affidavit, name='add_affidavit'),
        path('review_dashboard/', views.review_dashboard, name='review_dashboard'),
        path('edit/<int:affidavit_id>/', views.edit_affidavit, name='edit_affidavit'),
        path('confirm_delete/<int:affidavit_id>/', views.delete_affidavit, name='confirm_delete_affidavit'),
        path('download_profiles/', views.download_profiles_csv, name='download_profiles_csv'),
        path('download_profile/<int:profile_id>/', views.download_profile_csv, name='download_profile_csv'),
        path('download_completed_affidavits/', views.download_completed_affidavits_csv, name='download_completed_affidavits_csv'),
        path('download_affidavits/<int:profile_id>/', views.download_affidavits_csv, name='download_affidavits_csv'),
        path('download_affidavit_csv/<int:affidavit_id>/', views.download_affidavit_csv, name='download_affidavit_csv'),
        path('verify_email/<uidb64>/<token>/', views.verify_email, name='verify_email'),
        path('verify_email/<uidb64>/<token>/', views.verify_email, name='verify_email'),
        path('password_reset/', views.password_reset_request, name='password_reset'),
        path('reset/<uidb64>/<token>/', views.password_reset_confirm, name='password_reset_confirm'),
] 
