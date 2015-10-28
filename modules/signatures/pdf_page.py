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

class PDF_Page(Signature):
    name = "pdf_page"
    description = "The PDF has one page. Many malicious PDFs only have one page."
    severity = 2
    categories = ["pdf"]
    authors = ["KillerInstinct"]
    minimum = "1.3"

    filter_analysistypes = set(["file"])

    def run(self):
        if "static" in self.results and "pdf" in self.results["static"]:
            if "PDF" in self.results["target"]["file"]["type"]:
                if "Keywords" in self.results["static"]["pdf"]:
                    if "/Page" in self.results["static"]["pdf"]["Keywords"]:
                        if self.results["static"]["pdf"]["Keywords"]["/Page"] == 1:
                            return True

        return False
