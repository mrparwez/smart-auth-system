import logging

logger = logging.getLogger(__name__)

class CleanLogMiddleware:

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):

        # BEFORE view
        user = request.user if request.user.is_authenticated else "Anonymous"
        ip = self.get_client_ip(request)

        response = self.get_response(request)

        # AFTER view (final log)
        logger.info(
            f"{request.method} {request.path} | "
            f"user={user} | ip={ip} | status={response.status_code}"
        )

        return response

    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0]
        return request.META.get('REMOTE_ADDR')