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

class Andromeda_APIs(Signature):
    name = "andromeda_behavior"
    description = "Exhibits behavior characteristic of Andromeda/Gamarue malware"
    weight = 3
    severity = 3
    categories = ["trojan"]
    families = ["andromeda","gamarue"]
    authors = ["Accuvant"]
    minimum = "1.3"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.sysvolserial = None
        if "behavior" in self.results and "processes" in self.results["behavior"] and len(self.results["behavior"]["processes"]):
            if "environ" in self.results["behavior"]["processes"][0] and "SystemVolumeSerialNumber" in self.results["behavior"]["processes"][0]["environ"]:
                self.sysvolserial = int(self.results["behavior"]["processes"][0]["environ"]["SystemVolumeSerialNumber"].replace("-",""), 16)

    filter_apinames = set(["NtOpenEvent"])

    def on_call(self, call, process):
        eventname = self.get_argument(call, "EventName")
        try:
            eventname_int = int(eventname)
            if self.sysvolserial and eventname_int == self.sysvolserial ^ 0x696e6a63: # 'injc'
                return True
        except:
            pass
