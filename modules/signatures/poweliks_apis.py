# Copyright (C) KillerInstinct
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

class Poweliks_APIs(Signature):
    name = "poweliks_behavior"
    description = "Exhibits behavior characteristic of Poweliks malware"
    severity = 3
    weight = 3
    categories = ["trojan"]
    families = ["Poweliks"]
    authors = ["KillerInstinct"]
    minimum = "1.0"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)

    filter_apinames = set(["NtSetValueKey"])

    def on_call(self, call, process):
        # May need to add in some deobfuscation later...
        buf = self.get_argument(call, "Buffer")
        if buf and "eval(" in buf:
            return True

        return None
