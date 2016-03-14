# Copyright (C) 2016 Brad Spengler
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

class CuckooCrash(Signature):
    name = "antisandbox_cuckoocrash"
    description = "Crashed cuckoomon during analysis.  Report this error to the Github repo."
    severity = 3
    weight = 3
    categories = ["anti-sandbox"]
    authors = ["Brad Spengler"]
    minimum = "1.3"
    evented = True

    filter_categories = set(["__notification__"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)

    def on_call(self, call, process):
        subcategory = self.check_argument_call(call,
                                               api="__anomaly__",
                                               name="Subcategory",
                                               pattern="cuckoocrash")
        if subcategory:
            self.data.append({"pid" : process["process_id"]})
            self.data.append({"message" : self.get_argument(call, "Message")})
            return True
