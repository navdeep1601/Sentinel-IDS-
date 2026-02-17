from colorama import Fore, Style

class AlertManager:
    def __init__(self, logger):
        self.logger = logger

    def alert(self, data):
        print(Fore.RED + "[ALERT]" + Style.RESET_ALL, data)
        self.logger.warning(str(data))
