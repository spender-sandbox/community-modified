from lib.cuckoo.common.abstracts import Signature

class HeapSpray_JS(Signature):
    name = "browser_scanbox"
    description = "Scanbox Activity in Browser"
    weight = 3
    severity = 5 
    categories = ["exploit"]
    authors = ["Will Metcalf"]
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
            if 'softwarelist.push(' in buf.lower() and 'indexof("-2147023083")' in buf.lower():
                return True
            elif 'var logger' in buf.lower() and 'document.onkeypress = keypress;' in buf.lower() and 'setinterval(sendchar,' in buf.lower():
                return True
