import logging

from django.contrib.auth import authenticate
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated, AllowAny

from .serializers import RegisterSerializer, LoginSerializer
from .models import LoginHistory, LoginAttempt
from django.conf import settings
from django.utils import timezone
from datetime import timedelta
from users.risk_engine.engine import RiskEngine  # ✅ ONLY ONE IMPORT

logger = logging.getLogger(__name__)


# =========================
# REGISTER VIEW
# =========================
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


# =========================
# LOGIN VIEW (PHASE 3)
# =========================
class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = LoginSerializer(data=request.data)

        # ❌ INVALID REQUEST
        if not serializer.is_valid():
            logger.error(f"Login validation failed: {serializer.errors}")
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        email = serializer.validated_data.get("email")
        password = serializer.validated_data.get("password")

        ip = self.get_client_ip(request) or "0.0.0.0"
        user_agent = request.META.get("HTTP_USER_AGENT", "unknown")

        # 🔐 AUTHENTICATE USER
        
        user = authenticate(username=email, password=password)
        if user.is_locked:
            if user.lock_until and timezone.now() >= user.lock_until:
                user.is_locked = False
                user.lock_until = None
                user.risk_score = max(0, user.risk_score - 2)  # optional recovery

                user.save()

                logger.info(f"AUTO UNLOCKED | {user.email}")
        else:
            return Response(
                {
                    "error": "Account temporarily locked",
                    "unlock_time": user.lock_until
                },
                status=403
            )

        # ❌ LOGIN FAILED
        if not user:
            LoginAttempt.objects.create(
                email=email,
                ip_address=ip,
                success=False
            )

            logger.warning(f"FAILED LOGIN | email={email} | ip={ip}")

            return Response(
                {"error": "Invalid credentials"},
                status=status.HTTP_401_UNAUTHORIZED
            )

        # 🚫 ACCOUNT LOCK CHECK
        if getattr(user, "is_locked", False):
            logger.warning(f"LOCKED ACCOUNT ACCESS | {user.email}")

            return Response(
                {"error": "Account is locked"},
                status=status.HTTP_403_FORBIDDEN
            )

        # 🟢 SUCCESS LOGIN ATTEMPT LOG
        LoginAttempt.objects.create(
            email=email,
            ip_address=ip,
            success=True
        )

        # 🧠 RISK ENGINE EXECUTION
        last_login = LoginHistory.objects.filter(user=user).last()

        engine = RiskEngine()

        result = engine.evaluate(
            user=user,
            ip=ip,
            user_agent=user_agent,
            last_login=last_login
        )

        # 📊 SAVE LOGIN HISTORY
        LoginHistory.objects.create(
            user=user,
            ip_address=ip,
            user_agent=user_agent,
            is_suspicious=result["is_suspicious"],
            risk_reason=",".join(result["flags"])
        )

        # ⚠️ UPDATE RISK SCORE
        user.risk_score = min(10.0, user.risk_score + result["risk_score"])
        if user.risk_score >settings.RISK_LOCK_THRESHOLD:
            user.lock_until = timezone.now() + timedelta(minutes=settings.LOCK_TIME_MINUTES)
            logger.warning(f"ACCOUNT LOCKED | {user.email} | risk={user.risk_score}")
            user.is_locked=True
        user.save()

        # 🔑 JWT TOKEN
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

    # =========================
    # UTILITY FUNCTION
    # =========================
    def get_client_ip(self, request):
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            return x_forwarded_for.split(",")[0]
        return request.META.get("REMOTE_ADDR")


# =========================
# PROFILE VIEW
# =========================
class ProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user

        return Response({
            "email": user.email,
            "username": user.username,
            "risk_score": user.risk_score
        })