from lib.cuckoo.common.abstracts import Signature

class CVE2015_2419_JS(Signature):
    name = "cve_2015_2419_js"
    description = "Executes obfuscated JavaScript containing CVE-2015-2419 Internet Explorer Jscript9 JSON.stringify double free memory corruption attempt"
    severity = 3
    categories = ["exploit"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    references = ["https://www.fireeye.com/blog/threat-research/2015/08/cve-2015-2419_inte.html", "blog.checkpoint.com/2016/02/10/too-much-freedom-is-dangerous-understanding-ie-11-cve-2015-2419-exploitation/"]
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

        if "JSON[" in buf and "prototype" in buf and "stringify" in buf:
            return True
