from lib.cuckoo.common.abstracts import Signature

class TrickBotTaskDelete(Signature):
    name = "TrickBotTaskDelete"
    description = "Attempts to delete Windows tasks associated with TrickBot"
    severity = 3
    weight = 3
    categories = ["banking", "trojan"]
    authors = ["Eoin Miller"]
    minimum = "1.0"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)

    filter_apinames = set(["DeleteFileW"])

    def on_call(self, call, process):
        if call["api"] == ("DeleteFileW") and self.get_argument(call, "FileName").endswith("TrickBot.job"):
            self.data.append({"file" : self.get_argument(call, "FileName") })
            return True

        return None
