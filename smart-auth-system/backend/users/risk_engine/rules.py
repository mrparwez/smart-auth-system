class RiskRules:

    def ip_change(self, last_ip, current_ip):
        return 0.5 if last_ip and last_ip != current_ip else 0

    def device_change(self, last_device, current_device):
        return 0.3 if last_device and last_device != current_device else 0

    def first_login(self, last_login):
        return 0.1 if not last_login else 0