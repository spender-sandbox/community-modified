# Copyright (C) 2015 Accuvant, Inc. (bspengler@accuvant.com)
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

from lib.cuckoo.common.abstracts import Signature

class Angler_JS(Signature):
    name = "angler_js"
    description = "Executes obfuscated JavaScript indicative of Angler Exploit Kit"
    weight = 3
    severity = 3
    categories = ["exploit_kit"]
    families = ["angler"]
    authors = ["Accuvant"]
    minimum = "1.3"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)

    filter_categories = set(["browser"])
    # backward compat
    filter_apinames = set(["JsEval", "COleScript_Compile"])

    def on_call(self, call, process):
        if call["api"] == "JsEval":
            buf = self.get_argument(call, "Javascript")
            if "/malware.dontneedcoffee.com/.test()" in buf:
                return True
        else:
            buf = self.get_argument(call, "Script")
            if "/malware.dontneedcoffee.com/.test()" in buf:
                return True
