# Copyright (C) 2012-2014 Cuckoo Foundation.
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

class PDF_EOF(Signature):
    name = "pdf_eof"
    description = "The PDF has data after the last %% EOF marker."
    severity = 3
    categories = ["pdf"]
    authors = ["KillerInstinct"]
    minimum = "1.3"

    filter_analysistypes = set(["file"])

    def run(self):
        if "static" in self.results and "pdf" in self.results["static"]:
            if "PDF" in self.results["target"]["file"]["type"]:
                if "Data After EOF" in self.results["static"]["pdf"]["Info"]:
                    if self.results["static"]["pdf"]["Info"]["Data After EOF"] != "0":
                        return True

        return False
