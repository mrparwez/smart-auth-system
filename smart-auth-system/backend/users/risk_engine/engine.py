from .rules import RiskRules
from .scorer import RiskScorer


class RiskEngine:

    def __init__(self):
        self.rules = RiskRules()
        self.scorer = RiskScorer()

    def evaluate(self, user, ip, user_agent, last_login=None):

        scores = []
        flags = []

        # RULES
        ip_score = self.rules.ip_change(
            last_login.ip_address if last_login else None,
            ip
        )

        device_score = self.rules.device_change(
            last_login.user_agent if last_login else None,
            user_agent
        )

        first_login_score = self.rules.first_login(last_login)

        # Collect scores
        if ip_score:
            scores.append(ip_score)
            flags.append("IP_CHANGED")

        if device_score:
            scores.append(device_score)
            flags.append("DEVICE_CHANGED")

        if first_login_score:
            scores.append(first_login_score)
            flags.append("FIRST_LOGIN")

        risk_score = self.scorer.calculate(scores)

        return {
            "risk_score": risk_score,
            "is_suspicious": risk_score > 0.5,
            "flags": flags
        }