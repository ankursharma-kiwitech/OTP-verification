from random import random

import generic as generic
from django.core.mail import send_mail
from django.db.models.functions import math
from rest_framework.exceptions import PermissionDenied
from rest_framework.generics import CreateAPIView
from rest_framework.permissions import AllowAny
from rest_framework.views import APIView
from rest_framework.response import Response
from .serializers import UserSerializer, RegisterSerializer, verifyOTPSerializer
from django.contrib.auth.models import User
from rest_framework.authentication import TokenAuthentication
from rest_framework import generics


# Class based view to Get User Details using Token Authentication
class UserDetailAPI(APIView):
    authentication_classes = (TokenAuthentication,)
    permission_classes = (AllowAny,)

    def get(self, request, *args, **kwargs):
        user = User.objects.get(id=request.user.id)
        serializer = UserSerializer(user)
        return Response(serializer.data)


# Class based view to register user
class RegisterUserAPIView(generics.CreateAPIView):
    permission_classes = (AllowAny,)
    serializer_class = RegisterSerializer


class OTP(APIView):
    def generate_otp(self, request, *args, **kwargs):
        digits = "0123456789"
        OTP = ""
        for i in range(4):
            OTP += digits[math.floor(random.random() * 10)]
        return OTP

    def send_otp(self, request, *args, **kwargs):
        email = request.data['email']
        o = self.generate_otp(request, *args, **kwargs)
        print(o)
        htmlgen = '<p>Your OTP is <strong>' + o + '</strong></p>'
        send_mail('OTP request', o, '<gmail id>', [email], fail_silently=False, html_message=htmlgen)
        return Response({"message": "OTP sent successfully"})


class verifyOTPView(generics.CreateAPIView):
    serializer_class = verifyOTPSerializer

    def post(self, request):
        username = request.data["username"]
        otp = int(request.data["otp"])
        user = User.objects.get(username=username)
        if int(user.otp) == otp:
            user.verified = True
            # user.otp.delete()  #?? How to handle the otp, Should I set it to null??
            user.save()
            return Response("Verification Successful")
        else:
            raise PermissionDenied("OTP Verification failed")