try:
    import re2 as re
except ImportError:
    import re

from lib.cuckoo.common.abstracts import Signature

class Silverlight_JS(Signature):
    name = "silverlight_js"
    description = "Executes obfuscated JavaScript containing a Silverlight object indicative of an exploit attempt"
    weight = 3
    severity = 3
    categories = ["exploit_kit", "silverlight"]
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

        if re.search("application\/x\-silverlight.*?\<param name[ \t\n]*=.*?value[ \t\n]*=.*?\<\/object\>.*", buf, re.IGNORECASE|re.DOTALL):
            return True
