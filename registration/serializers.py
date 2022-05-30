from random import randint

from django.core.mail import send_mail
from rest_framework import serializers
from django.contrib.auth.models import User
from rest_framework.response import Response
from rest_framework import status
from rest_framework.validators import UniqueValidator
from django.contrib.auth.password_validation import validate_password


# Serializer to Get User Details using Django Token Authentication
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["id", "first_name", "last_name", "username", "email"]


# Serializer to Register User
class RegisterSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(
        required=True,
        validators=[UniqueValidator(queryset=User.objects.all())]
    )
    password = serializers.CharField(
        write_only=True, required=True, validators=[validate_password])
    password2 = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = User
        fields = ('username', 'password', 'password2',
                  'email', 'first_name', 'last_name')
        extra_kwargs = {
            'first_name': {'required': True},
            'last_name': {'required': True}
        }

    def validate(self, attrs):
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError(
                {"password": "Password fields didn't match."})
        return attrs

    def create(self, validated_data):
        user = User.objects.create(
            username=validated_data['username'],
            email=validated_data['email'],
            first_name=validated_data['first_name'],
            last_name=validated_data['last_name']
        )
        user.set_password(validated_data['password'])
        user.save()
        return user


class verifyOTPSerializer(serializers.Serializer):
    otp = serializers.IntegerField(write_only=True)

    class Meta:
        model = User
        fields = ('otp','email')

    def validate_otp(self, value):
        if value != self.context['otp']:
            raise serializers.ValidationError("OTP is invalid")
        return value

    def create(self, validated_data):
        user = super(UserSerializer, self).create(validated_data)
        user.set_password(validated_data['password'])

        class Meta:
            model = User
            fields = ['username', 'email', 'otp']

        def random_with_N_digits(n):
            range_start = 10 ** (n - 1)
            range_end = (10 ** n) - 1
            return randint(range_start, range_end)

        otp = random_with_N_digits(6)
        user.otp = otp
        user.save()

        subject = 'Please Confirm Your Account'
        message = 'Your 6 Digit Verification Pin: {}'.format(otp)
        email_from = '*****'
        recipient_list = [str(user.email), ]
        send_mail(subject, message, email_from, recipient_list)
        return user

