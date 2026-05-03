import logging
from datetime import timedelta
from django.http import JsonResponse

from django.contrib.auth import authenticate
from django.conf import settings
from django.utils import timezone

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated, AllowAny

from rest_framework_simplejwt.tokens import RefreshToken

from .serializers import RegisterSerializer, LoginSerializer
from .models import LoginHistory, LoginAttempt
from users.models import CustomUser
from users.risk_engine.engine import RiskEngine

logger = logging.getLogger(__name__)


# =========================
# HOME API
# =========================
def home(request):
    return JsonResponse({
        "status": "Success",
        "message": "Smart Auth API Running",
        "endpoints": {
            "login": "/api/login/",
            "register": "/api/register/",
            "profile": "/api/profile/"
        }
    })


# =========================
# REGISTER
# =========================
class RegisterView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)

        if serializer.is_valid():
            serializer.save()

            return Response(
                {"message": "User registered successfully"},
                status=status.HTTP_201_CREATED
            )

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# =========================
# LOGIN
# =========================
class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = LoginSerializer(data=request.data)

        if not serializer.is_valid():
            return Response(serializer.errors, status=400)

        email = serializer.validated_data["email"]
        password = serializer.validated_data["password"]

        ip = self.get_client_ip(request)
        user_agent = request.META.get("HTTP_USER_AGENT", "unknown")

        user = authenticate(username=email, password=password)

        # ❌ FAILED LOGIN
        if not user:
            LoginAttempt.objects.create(
                email=email,
                ip_address=ip,
                success=False
            )

            return Response(
                {"error": "Invalid credentials"},
                status=401
            )

        # 🚫 LOCK CHECK
        if user.is_locked:
            if user.lock_until and timezone.now() >= user.lock_until:
                user.is_locked = False
                user.lock_until = None
                user.risk_score = max(0, user.risk_score - 2)
                user.save()
            else:
                return Response(
                    {
                        "error": "Account locked",
                        "unlock_time": user.lock_until
                    },
                    status=403
                )

        # ✅ SUCCESS LOGIN
        LoginAttempt.objects.create(
            user=user,
            email=email,
            ip_address=ip,
            success=True
        )

        last_login = LoginHistory.objects.filter(user=user).last()

        engine = RiskEngine()

        result = engine.evaluate(
            user=user,
            ip=ip,
            user_agent=user_agent,
            last_login=last_login
        )

        # SAVE HISTORY
        LoginHistory.objects.create(
            user=user,
            ip_address=ip,
            user_agent=user_agent,
            is_suspicious=result["is_suspicious"],
            risk_reason=",".join(result["flags"])
        )

        # UPDATE RISK
        user.risk_score = min(10.0, user.risk_score + result["risk_score"])

        if user.risk_score > settings.RISK_LOCK_THRESHOLD:
            user.is_locked = True
            user.lock_until = timezone.now() + timedelta(
                minutes=settings.LOCK_TIME_MINUTES
            )

        user.save()

        refresh = RefreshToken.for_user(user)

        return Response({
            "message": "Login successful",
            "risk_score": user.risk_score,
            "flags": result["flags"],
            "access_token": str(refresh.access_token),
            "refresh_token": str(refresh)
        })


    def get_client_ip(self, request):
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            return x_forwarded_for.split(",")[0]
        return request.META.get("REMOTE_ADDR")


# =========================
# PROFILE
# =========================
class ProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response({
            "email": request.user.email,
            "username": request.user.username,
            "risk_score": request.user.risk_score
        })