from django.urls import path
from .views import UserDetailAPI, RegisterUserAPIView, verifyOTPView,OTP

urlpatterns = [
  path("get-details",UserDetailAPI.as_view()),
  path('register',RegisterUserAPIView.as_view()),
  path('otp',OTP.as_view()),
  path('',verifyOTPView.as_view())
]


