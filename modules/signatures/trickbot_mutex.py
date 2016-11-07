from lib.cuckoo.common.abstracts import Signature

class TrickBotMutexes(Signature):
    name = "trickbot_mutex"
    description = "Attempts to create a known TrickBot mutex."
    weight = 3
    severity = 3
    categories = ["banker", "trojan"]
    families = ["TrickBot"]
    authors = ["Eoin Miller"]
    minimum = "0.5"

    def run(self):
        if self.check_mutex(pattern="^Global\\\\TrickBot$", regex=True):
            return True

        return False
