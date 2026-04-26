import logging
from datetime import timedelta

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
# LOGIN VIEW
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

        # ❌ LOGIN FAILED → BRUTE FORCE LOGIC
        if not user:
            LoginAttempt.objects.create(
                email=email,
                ip_address=ip,
                success=False
            )

            time_threshold = timezone.now() - timedelta(minutes=10)

            failed_attempts = LoginAttempt.objects.filter(
                email=email,
                success=False,
                timestamp__gte=time_threshold
            ).count()

            logger.warning(f"FAILED LOGIN | email={email} | attempts={failed_attempts}")

            # 🔐 LOCK USER IF EXISTS
            try:
                user_obj = CustomUser.objects.get(email=email)

                if failed_attempts >= settings.MAX_FAILED_ATTEMPTS:
                    user_obj.is_locked = True
                    user_obj.lock_until = timezone.now() + timedelta(
                        minutes=settings.LOCK_TIME_MINUTES
                    )
                    user_obj.save()

                    logger.warning(f"BRUTE FORCE LOCK | {email}")

            except CustomUser.DoesNotExist:
                pass

            return Response(
                {"error": "Invalid credentials"},
                status=status.HTTP_401_UNAUTHORIZED
            )

        # 🚫 CHECK LOCK STATUS
        if user.is_locked:

            # 🟢 AUTO UNLOCK
            if user.lock_until and timezone.now() >= user.lock_until:
                user.is_locked = False
                user.lock_until = None
                user.risk_score = max(0, user.risk_score - 2)
                user.save()

                logger.info(f"AUTO UNLOCKED | {user.email}")

            else:
                return Response(
                    {
                        "error": "Account temporarily locked",
                        "unlock_time": user.lock_until
                    },
                    status=status.HTTP_403_FORBIDDEN
                )

        # 🟢 SUCCESS LOGIN ATTEMPT
        LoginAttempt.objects.create(
            email=email,
            ip_address=ip,
            success=True
        )

        # 🧹 CLEAR FAILED ATTEMPTS
        LoginAttempt.objects.filter(email=email, success=False).delete()

        # 🧠 RISK ENGINE
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

        if user.risk_score > settings.RISK_LOCK_THRESHOLD:
            user.is_locked = True
            user.lock_until = timezone.now() + timedelta(
                minutes=settings.LOCK_TIME_MINUTES
            )

            logger.warning(f"ACCOUNT LOCKED | {user.email} | risk={user.risk_score}")

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