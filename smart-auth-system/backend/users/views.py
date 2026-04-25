import logging
from django.contrib.auth import authenticate
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated, AllowAny

from .serializers import RegisterSerializer, LoginSerializer
from .models import LoginHistory
from .risk_engine import RiskEngine

logger = logging.getLogger(__name__)


class RegisterView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)

        if serializer.is_valid():
            user = serializer.save()
            logger.info(f"User registered: {user.email}")

            return Response(
                {"message": "User registered successfully"},
                status=status.HTTP_201_CREATED
            )

        logger.error(f"Register failed: {serializer.errors}")
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = LoginSerializer(data=request.data)

        if not serializer.is_valid():
            logger.error(f"Login failed: {serializer.errors}")
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        user = serializer.validated_data.get("user")

        if not user.is_active:
            logger.warning(f"Inactive login attempt: {user.email}")
            return Response(
                {"error": "Account is disabled"},
                status=status.HTTP_403_FORBIDDEN
            )

        ip = self.get_client_ip(request) or "0.0.0.0"
        user_agent = request.META.get("HTTP_USER_AGENT", "unknown")

        last_login = LoginHistory.objects.filter(user=user).last()

        engine = RiskEngine(
            user=user,
            ip=ip,
            user_agent=user_agent,
            last_login=last_login
        )

        result = engine.evaluate()

        LoginHistory.objects.create(
            user=user,
            ip_address=ip,
            user_agent=user_agent,
            is_suspicious=result["is_suspicious"],
            location=None
        )

        user.risk_score += result["risk_score"]
        user.save()
        refresh = RefreshToken.for_user(user)

        logger.info(
            f"LOGIN SUCCESS | user={user.email} | ip={ip} | risk={user.risk_score} | flags={result['flags']}"
        )

        return Response({
            "message": "Login successful",
            "risk_score": user.risk_score,
            "is_suspicious": result["is_suspicious"],
            "flags": result["flags"],
            "access_token": str(refresh.access_token),
            "refresh_token": str(refresh)
        }, status=status.HTTP_200_OK)

class ProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user

        return Response({
            "email": user.email,
            "username": user.username,
            "risk_score": user.risk_score
        })


    def get_client_ip(self, request):
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            return x_forwarded_for.split(",")[0]
        return request.META.get("REMOTE_ADDR")