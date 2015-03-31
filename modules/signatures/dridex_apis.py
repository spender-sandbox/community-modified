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

from lib.cuckoo.common.abstracts import Signature

class Dridex_APIs(Signature):
    name = "dridex_behavior"
    description = "Exhibits behavior characteristic of Dridex malware"
    severity = 3
    categories = ["banker", "trojan"]
    families = ["dridex"]
    authors = ["KillerInstinct"]
    minimum = "1.2"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.compname = ""
        self.username = ""
        self.crypted = []

    filter_apinames = set(["RegQueryValueExA", "CryptHashData"])

    def on_call(self, call, process):
        if call["api"] == "RegQueryValueExA":
            # There are many more ways to get the computer name, this is the
            # pattern observed with all Dridex varients 08/14 - 03/15 so far.
            testkey = self.get_argument(call, "FullName").lower()
            if testkey == "hkey_local_machine\\system\\controlset001\\control\\computername\\computername\\computername":
                if self.get_argument(call, "ValueName") == "ComputerName":
                    buf = self.get_argument(call, "Data")
                    if buf:
                        self.compname = buf.lower()
            if testkey == "hkey_current_user\\volatile environment\\username":
                if self.get_argument(call, "ValueName") == "USERNAME":
                    buf = self.get_argument(call, "Data")
                    if buf:
                        self.username = buf.lower()
        if call["api"] == "CryptHashData":
            self.crypted.append(self.get_argument(call, "Buffer").lower())

    def on_complete(self):
        ret = False
        if self.compname and self.username and self.crypted:
            buf = self.compname + self.username
            for item in self.crypted:
                if buf in item:
                    ret = True

        return ret
