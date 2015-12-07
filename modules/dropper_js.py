try:
    import re2 as re
except ImportError:
    import re

from lib.cuckoo.common.abstracts import Signature

class EXEDropper_JS(Signature):
    name = "exe_dropper_js"
    description = "Executes obfuscated JavaScript which drops and executes an executable file"
    weight = 3
    severity = 3
    categories = ["dropper","downloader"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)

    filter_categories = set(["browser"])
    # backward compat
    filter_apinames = set(["JsEval", "COleScript_Compile", "COleScript_ParseScriptText"])

    def on_call(self, call, process):
        if call["api"] == "JsEval":
            buf = self.get_argument(call, "Javascript")
        else:
            buf = self.get_argument(call, "Script")

        if re.search("(Save|Write)ToFile(\(|\/).*?\.exe\".*?Run(\(|\/).*?\.exe\"", buf, re.IGNORECASE|re.DOTALL):
            return True
