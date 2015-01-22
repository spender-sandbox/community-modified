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
import re

class AntiSandboxShare(Signature):
    name = "antisandbox_share"
    description = "Attempted to prevent Cuckoo from obtaining a dropped file"
    severity = 3
    categories = ["anti-sandbox"]
    authors = ["Accuvant"]
    minimum = "1.2"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.potentially_unshared = []
        self.unshared = set()

    filter_apinames = set(["NtOpenFile", "NtCreateFile"])

    def on_call(self, call, process):
        share = int(self.get_argument(call, "ShareAccess"), 16)
        # missing FILE_SHARE_READ
        if (share & 1) == 0:
            self.potentially_unshared.add(self.get_argument(call, "FileName"))
    def on_complete(self):
        whitelists = [
            r'^[A-Z]?:\\Documents and Settings\\[^\\]+\\Cookies\\.*\.txt$',
            r'^[A-Z]?:\\Users\\[^\\]+\\AppData\\Roaming\\Microsoft\\Windows\\Cookies\\.*\.txt$'
        ]
        found_unshared_drop = False
        for unshare in self.unshared:
            unsharedlower = unshare.lower()
            for drop in self.results["dropped"]:
                for path in drop["guest_paths"]:
                    if path.lower() == unsharedlower:
                        addit = True
                        for entry in whitelists:
                            if re.match(entry, path, re.IGNORECASE):
                                addit = False
                        if addit:
                            self.data.append({"file" : path})
                            found_unshared_drop = True
        return found_unshared_drop