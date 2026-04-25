class RiskEngine:

    def __init__(self, user, ip, user_agent, last_login=None):
        self.user = user
        self.ip = ip
        self.user_agent = user_agent
        self.last_login = last_login

        self.risk_score = 0.0
        self.is_suspicious = False
        self.flags = []

    def evaluate(self):

        # RULE 1: IP change
        if self.last_login and self.last_login.ip_address != self.ip:
            self.risk_score += 0.5
            self.is_suspicious = True
            self.flags.append("IP_CHANGED")

        # RULE 2: Device change (user-agent change)
        if self.last_login and self.last_login.user_agent != self.user_agent:
            self.risk_score += 0.3
            self.is_suspicious = True
            self.flags.append("DEVICE_CHANGED")

        # RULE 3: First login (optional simple rule)
        if not self.last_login:
            self.flags.append("FIRST_LOGIN")

        return {
            "risk_score": self.risk_score,
            "is_suspicious": self.is_suspicious,
            "flags": self.flags
        }