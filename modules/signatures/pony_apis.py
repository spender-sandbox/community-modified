# Copyright (C) 2015 KillerInstinct
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

class Pony_APIs(Signature):
    name = "pony_behavior"
    description = "Exhibits behavior characteristic of Pony malware"
    weight = 3
    severity = 3
    categories = ["trojan", "infostealer"]
    families = ["pony"]
    authors = ["KillerInstinct"]
    minimum = "1.2"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.urls = set()
        self.badpid = str()
        self.guidpat = "\{[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}\}"

    filter_apinames = set(["RegSetValueExA", "InternetCrackUrlA"])

    def on_call(self, call, process):
        if call["api"] == "RegSetValueExA":
            buf = self.get_argument(call, "FullName")
            if buf and "HWID" in buf:
                guid = self.get_argument(call, "Buffer")
                test = re.match(self.guidpat, guid)
                if test and not self.badpid:
                    self.badpid = str(process["process_id"])

        elif call["api"] == "InternetCrackUrlA":
            if str(process["process_id"]) == self.badpid:
                self.urls.add(self.get_argument(call, "Url"))

        return None

    def on_complete(self):
        if self.badpid:
            if self.urls:
                for url in self.urls:
                    self.data.append({"C2": url})
            return True

        return False
