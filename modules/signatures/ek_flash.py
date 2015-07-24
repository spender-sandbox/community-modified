# Copyright (C) 2015 Kevin Ross, Accuvant, Inc. (bspengler@accuvant.com)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

try:
    import re2 as re
except ImportError:
    import re

from lib.cuckoo.common.abstracts import Signature

class Flash_JS(Signature):
    name = "flash_js"
    description = "Executes obfuscated JavaScript containing allowScriptAccess=always indicative of a Flash exploit attempt"
    weight = 3
    severity = 3
    categories = ["exploit_kit", "flash"]
    authors = ["Kevin Ross", "Accuvant"]
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
            if re.match(".*allowscriptaccess[ ]*=[ ]*always.*", buf, re.IGNORECASE):
                return True
        else:
            buf = self.get_argument(call, "Script")
            if re.match(".*allowscriptaccess[ ]*=[ ]*always.*", buf, re.IGNORECASE):
                return True
