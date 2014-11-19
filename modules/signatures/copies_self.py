# Copyright (C) 2014 Accuvant Inc. (bspengler@accuvant.com)
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

class CopiesSelf(Signature):
    name = "copies_self"
    description = "Creates a copy of itself"
    severity = 3
    categories = ["persistence"]
    authors = ["Accuvant"]
    minimum = "1.2"

    def run(self):
        if self.results["target"]["category"] != "file":
            return False
        target_sha1 = self.results["target"]["file"]["sha1"]

        for drop in self.results["dropped"]:
            if drop["sha1"] == target_sha1 and len(drop["guests_paths"]) > 1:
                for path in drop["guest_paths"][1:]:
                    self.data.append({"copy" : path})
                return True
        return False