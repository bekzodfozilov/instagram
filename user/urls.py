from django.urls import path


from .views import CreateUserView, VerifyApiView, GetNewVerification, \
    ChangeUserInformationView, ChangeUserPhotoView, ForgetPasswordView, LoginView, LoginRefreshView, LogoutView, ResetPasswordView

urlpatterns = [
    path('login/',LoginView.as_view(),name='login' ),
    path('login-refresh/',LoginRefreshView.as_view(),name='login_refresh'),
    path('logout/',LogoutView.as_view(),name='logout'),

    path('signup/', CreateUserView.as_view(), name='signup'),
    path('verify/', VerifyApiView.as_view(), name='verify'),
    path('new-verification/', GetNewVerification.as_view(), name='new_verification'),
    path('update-information/', ChangeUserInformationView.as_view(), name='update_information'),
    path('update-photo/', ChangeUserPhotoView.as_view(), name='update_photo'),
    path('forget-password/', ForgetPasswordView.as_view(), name='forget_password'),
    path('reset-password/', ResetPasswordView.as_view())

]