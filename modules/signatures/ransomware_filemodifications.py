# Copyright (C) 2016 Kevin Ross
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

try:
    import re2 as re
except ImportError:
    import re

from lib.cuckoo.common.abstracts import Signature

class RansomwareFileModifications(Signature):
    name = "ransomware_file_modifications"
    description = "Exhibits possible ransomware file modification behavior"
    severity = 3
    confidence = 50
    categories = ["ransomware"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.movefilecount = 0
        self.appendcount = 0
        self.newextensions = []
     
    filter_apinames = set(["MoveFileWithProgressW"])

    def on_call(self, call, process):

        if call["api"] == "MoveFileWithProgressW":
            origfile = self.get_argument(call, "ExistingFileName")
            newfile = self.get_argument(call, "NewFileName")
            self.movefilecount += 1
            if origfile != newfile:
                origextextract = re.search("^.*(\.[a-zA-Z0-9_\-]{1,}$)", origfile)
                origextension = origextextract.group(1)
                newextextract = re.search("^.*(\.[a-zA-Z0-9_\-]{1,}$)", newfile)
                newextension = newextextract.group(1)
                if newextension != ".tmp":
                    if origextension != newextension:
                        self.appendcount += 1
                        if self.newextensions.count(newextension) == 0:
                            self.newextensions.append(newextension)               

    def on_complete(self):
        ret = False

        if self.movefilecount > 100:
            self.data.append({"file_modifications" : "Performs %s file moves indicative of a potential file encryption process" % (self.movefilecount)})
            ret = True

        # Note: Always make sure this check is at bottom so that appended file extensions are underneath behavior alerts
        if self.appendcount > 40:
            # This check is to prevent any cases where there is a large number of unique appended extensions resulting in an overly large list
            newcount = len(self.newextensions)
            if newcount > 15:
                self.data.append({"appends_new_extension" : "Appended %s unique file extensions to multiple modified files" % (newcount)})
            if newcount < 15:           
                self.data.append({"appends_new_extension" : "Appends a new file extension to multiple modified files" })
                for newextension in self.newextensions:
                    self.data.append({"new_appended_file_extension" : newextension})
                ret = True

        return ret
